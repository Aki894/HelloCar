//! HiCar radio ownership. libdbus is loaded on demand; credentials and received
//! RFCOMM descriptors only cross the inherited private SOCK_SEQPACKET channel.
//! No Bluetooth ACL event is treated as a media-session termination here.
use super::Result;
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use std::collections::BTreeSet;
use std::net::{IpAddr,Ipv4Addr,Ipv6Addr};

const FE35:&str="0000fe35-0000-1000-8000-00805f9b34fb";
const FE36:&str="0000fe36-0000-1000-8000-00805f9b34fb";
const FDEE:&str="0000fdee-0000-1000-8000-00805f9b34fb";
const ROOT:&str="/org/hellocar/hicar";
fn yes()->bool{true}fn adapter()->String{"/org/bluez/hci0".into()}fn one()->u8{1}fn channel()->u16{23}fn power()->i16{11}
#[derive(Deserialize)]
struct Config{
    #[serde(default="adapter")]adapter:String,model:String,#[serde(default="one")]sequence:u8,
    #[serde(default)]peer:Option<String>,#[serde(default)]reconnect_peer:Option<String>,#[serde(default,alias="exclude_peer")]exclude_peers:Vec<String>,
    #[serde(default)]pair_seconds:u64,#[serde(default="channel")]channel:u16,
    #[serde(default="power")]tx_power:i16,#[serde(default)]interface:Option<String>,
    #[serde(default="yes")]network:bool,#[serde(default="yes")]manage_controller:bool,
}
fn mac(value:&str)->Result<String>{
    let fields:Vec<_>=value.split(':').collect();
    if fields.len()!=6||fields.iter().any(|p|p.len()!=2||!p.bytes().all(|v|v.is_ascii_hexdigit())){return Err("invalid Bluetooth address".into());}Ok(value.to_ascii_uppercase())
}
fn validate(c:&Config)->Result<()>{
    let index=c.adapter.strip_prefix("/org/bluez/hci").ok_or("invalid adapter path")?;
    if index.is_empty()||index.len()>5||!index.bytes().all(|b|b.is_ascii_digit())||index.parse::<u16>().is_err(){return Err("invalid adapter index".into());}
    if c.model.len()!=8||!c.model.bytes().all(|b|b.is_ascii_hexdigit())||!(1..=29).contains(&c.channel)||!(-127..=20).contains(&c.tx_power){return Err("invalid radio parameters".into());}
    if c.pair_seconds!=0&&!(5..=120).contains(&c.pair_seconds){return Err("invalid pairing window".into());}
    if c.exclude_peers.len()>8{return Err("too many excluded peers".into());}for p in &c.exclude_peers{mac(p)?;}if let Some(p)=&c.peer{mac(p)?;}if let Some(p)=&c.reconnect_peer{mac(p)?;if c.exclude_peers.contains(&mac(p)?){return Err("reconnect peer is excluded".into());}}
    if c.peer.is_none()&&c.pair_seconds==0{return Err("selected peer or pairing window required".into());}
    if c.network&&c.interface.is_none(){return Err("wireless interface required".into());}
    if let Some(i)=&c.interface{if i.is_empty()||i.len()>15||i=="end0"||!i.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b)){return Err("invalid wireless interface".into());}}
    Ok(())
}
fn beacon(model:&str,sequence:u8)->Result<Vec<u8>>{let raw=super::unhex(model)?;if raw.len()!=4{return Err("invalid model".into());}Ok(vec![1,1,1,3,raw[0],raw[1],raw[2],4,raw[3],16,sequence])}
fn service_record(channel:u16,uuid:&str)->String{format!("<record><attribute id=\"0x0001\"><sequence><uuid value=\"{uuid}\"/></sequence></attribute><attribute id=\"0x0004\"><sequence><sequence><uuid value=\"0x0100\"/></sequence><sequence><uuid value=\"0x0003\"/><uint8 value=\"{channel}\"/></sequence></sequence></attribute><attribute id=\"0x0005\"><sequence><uuid value=\"0x1002\"/></sequence></attribute><attribute id=\"0x0100\"><text value=\"NearbyServerSocket\"/></attribute></record>")}
/// sdptool can return ATT and RFCOMM records for the same FE35 UUID.
/// Select exactly one RFCOMM descriptor, never the first arbitrary SDP PSM.
fn rfcomm_channel(sdp:&[u8])->Result<u16>{
    if sdp.len()>65536{return Err("SDP output exceeds limit".into());}
    let text=std::str::from_utf8(sdp).map_err(|_|"invalid SDP text")?;let mut channels=vec![];
    for record in text.split("Service RecHandle:").skip(1){
        let Some((classes,protocols))=record.split_once("Protocol Descriptor List:")else{continue;};
        let classes=classes.to_ascii_lowercase();if !classes.contains("(0xfe35)")&&!classes.contains("0000fe35-0000-1000-8000-00805f9b34fb"){continue;}
        let mut rfcomm=false;for line in protocols.lines(){let line=line.trim();
            if line.starts_with('"'){rfcomm=line.starts_with("\"RFCOMM\"")&&line.contains("0x0003");}
            if rfcomm{if let Some(value)=line.strip_prefix("Channel:"){
                let channel=value.trim().parse::<u16>().map_err(|_|"invalid RFCOMM channel")?;if !(1..=30).contains(&channel){return Err("invalid RFCOMM channel".into());}channels.push(channel);
            }}
        }
    }
    if channels.len()!=1{return Err("SDP must contain one FE35 RFCOMM service".into());}Ok(channels[0])
}
fn hotspot_ipv4_ready(addresses:&Value,interface:&str)->bool{
    addresses.as_array().is_some_and(|links|links.iter().any(|link|link["ifname"]==interface
        &&link["addr_info"].as_array().is_some_and(|addresses|addresses.iter().any(|address|
            address["family"]=="inet"&&address["local"]=="192.168.49.1"&&address["prefixlen"]==24))))
}
struct Selection{prefix:String,selected:Option<String>,excluded:BTreeSet<String>,deadline:Option<u64>}
impl Selection{
    fn new(c:&Config)->Result<Self>{Ok(Self{prefix:format!("{}/dev_",c.adapter),selected:c.peer.as_ref().map(|p|mac(p).map(|p|format!("{}/dev_{}",c.adapter,p.replace(':',"_")))).transpose()?,excluded:c.exclude_peers.iter().map(|p|mac(p)).collect::<Result<_>>()?,deadline:None})}
    fn address(&self,path:&str)->Option<String>{let p=path.strip_prefix(&self.prefix)?;if !p.bytes().all(|b|b.is_ascii_digit()||(b'A'..=b'F').contains(&b)||b==b'_'){return None;}mac(&p.replace('_',":")).ok()}
    fn allows(&mut self,path:&str,select:bool,now:u64)->bool{
        let Some(address)=self.address(path)else{return false;};
        if let Some(selected)=&self.selected{return selected==path;}
        if self.excluded.contains(&address)||self.deadline.is_none_or(|d|now>=d){return false;}
        if select{self.selected=Some(path.into());}true
    }
}
fn normalized_ip(ip:IpAddr)->IpAddr{match ip{IpAddr::V6(v)=>v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v)),_=>ip}}
fn proc_ip(raw:&str)->Option<IpAddr>{
    if raw.len()!=8&&raw.len()!=32{return None;}let mut bytes=vec![];
    for word in raw.as_bytes().chunks(8){let word=std::str::from_utf8(word).ok()?;bytes.extend(u32::from_str_radix(word,16).ok()?.to_ne_bytes());}
    Some(normalized_ip(if bytes.len()==4{IpAddr::V4(Ipv4Addr::new(bytes[0],bytes[1],bytes[2],bytes[3]))}else{IpAddr::V6(Ipv6Addr::from(<[u8;16]>::try_from(bytes).ok()?))}))
}
/// Protect active SSH on the Wi-Fi interface being replaced. A vehicle with no
/// Ethernet cable and no SSH session is allowed to start its hotspot normally.
fn ssh_on_interface(addresses:&Value,interface:&str,tcp:&str,tcp6:&str)->Result<bool>{
    let links=addresses.as_array().ok_or("invalid interface addresses")?;let link=links.iter().find(|l|l["ifname"].as_str()==Some(interface)).ok_or("wireless interface missing")?;
    let mut own=BTreeSet::new();for address in link["addr_info"].as_array().ok_or("invalid interface addresses")?{let local=address["local"].as_str().ok_or("invalid interface address")?;own.insert(normalized_ip(local.parse().map_err(|_|"invalid interface address")?));}
    for line in tcp.lines().chain(tcp6.lines()){
        let fields:Vec<_>=line.split_whitespace().collect();if fields.len()<4||fields[3]!="01"{continue;}
        let Some((raw,port))=fields[1].rsplit_once(':')else{continue;};if u16::from_str_radix(port,16).ok()!=Some(22){continue;}
        let ip=proc_ip(raw).ok_or("invalid SSH socket address")?;if own.contains(&ip){return Ok(true);}
    }Ok(false)
}

/// Synthetic contract only. No system bus, radio or network is accessed.
pub fn differential(v:&Value)->Result<Value>{
    let c:Config=serde_json::from_value(v["config"].clone()).map_err(|_|"invalid radio configuration")?;validate(&c)?;
    let mut selected=Selection::new(&c)?;selected.deadline=(c.pair_seconds!=0).then_some(c.pair_seconds*1000);
    let cases=v["requests"].as_array().filter(|v|v.len()<=128).ok_or("invalid radio requests")?;let mut out=vec![];
    for x in cases{let path=x["device"].as_str().ok_or("missing device")?;let now=x["now_ms"].as_u64().ok_or("missing time")?;
        out.push(selected.allows(path,x["select"]==true,now));}
    let protected=if let Some(addresses)=v.get("addresses"){Some(ssh_on_interface(addresses,v["interface"].as_str().ok_or("missing interface")?,v["tcp"].as_str().unwrap_or(""),v["tcp6"].as_str().unwrap_or(""))?)}else{None};
    Ok(json!({"beacon":super::hex(&beacon(&c.model,c.sequence)?),"allowed":out,"selected":selected.selected,"profile_channels":[c.channel,c.channel+1],"ssh_blocked":protected}))
}

#[cfg(unix)]mod linux{
use super::*;
use libloading::Library;
use std::{ffi::{c_char,c_int,c_long,c_void,CStr,CString},io::{self,Read},mem,os::fd::{AsRawFd,FromRawFd,OwnedFd},path::Path,process::Command,ptr,time::{Duration,Instant}};
const PROPERTIES:&str="org.freedesktop.DBus.Properties";
// DBusMessageIter is an ABI-stable padded public struct, smaller than this
// aligned opaque storage on supported ARMv7 and x86_64 libdbus-1 platforms.
#[repr(C,align(16))]struct Iter([u8;128]);impl Iter{fn new()->Self{Self([0;128])}}
type Conn=*mut c_void;type Msg=*mut c_void;
struct Api{
    _library:Library,bus_get:unsafe extern "C" fn(c_int,*mut c_void)->Conn,
    connection_close:unsafe extern "C" fn(Conn),connection_unref:unsafe extern "C" fn(Conn),
    exit_on_disconnect:unsafe extern "C" fn(Conn,c_int),read_write:unsafe extern "C" fn(Conn,c_int)->c_int,
    pop:unsafe extern "C" fn(Conn)->Msg,send:unsafe extern "C" fn(Conn,Msg,*mut u32)->c_int,
    flush:unsafe extern "C" fn(Conn),get_fd:unsafe extern "C" fn(Conn,*mut c_int)->c_int,
    max_message:unsafe extern "C" fn(Conn,c_long),max_received:unsafe extern "C" fn(Conn,c_long),
    new_call:unsafe extern "C" fn(*const c_char,*const c_char,*const c_char,*const c_char)->Msg,
    new_return:unsafe extern "C" fn(Msg)->Msg,new_error:unsafe extern "C" fn(Msg,*const c_char,*const c_char)->Msg,
    unref:unsafe extern "C" fn(Msg),message_type:unsafe extern "C" fn(Msg)->c_int,
    reply_serial:unsafe extern "C" fn(Msg)->u32,
    sender:unsafe extern "C" fn(Msg)->*const c_char,path:unsafe extern "C" fn(Msg)->*const c_char,
    interface:unsafe extern "C" fn(Msg)->*const c_char,member:unsafe extern "C" fn(Msg)->*const c_char,
    iter_init:unsafe extern "C" fn(Msg,*mut Iter)->c_int,iter_append:unsafe extern "C" fn(Msg,*mut Iter),
    arg_type:unsafe extern "C" fn(*mut Iter)->c_int,next:unsafe extern "C" fn(*mut Iter)->c_int,
    basic:unsafe extern "C" fn(*mut Iter,*mut c_void),recurse:unsafe extern "C" fn(*mut Iter,*mut Iter),
    append_basic:unsafe extern "C" fn(*mut Iter,c_int,*const c_void)->c_int,
    open:unsafe extern "C" fn(*mut Iter,c_int,*const c_char,*mut Iter)->c_int,
    close:unsafe extern "C" fn(*mut Iter,*mut Iter)->c_int,
}
impl Api{
    fn load()->Result<Self>{unsafe{
        let library=Library::new("libdbus-1.so.3").map_err(|_|"cannot load libdbus")?;
        macro_rules! sym{($s:literal)=>{*library.get(concat!($s,"\0").as_bytes()).map_err(|_|"missing libdbus API")?};}
        let init:unsafe extern "C" fn()->c_int=sym!("dbus_threads_init_default");if init()==0{return Err("cannot initialize D-Bus threads".into());}
        Ok(Self{bus_get:sym!("dbus_bus_get_private"),connection_close:sym!("dbus_connection_close"),connection_unref:sym!("dbus_connection_unref"),exit_on_disconnect:sym!("dbus_connection_set_exit_on_disconnect"),read_write:sym!("dbus_connection_read_write"),pop:sym!("dbus_connection_pop_message"),send:sym!("dbus_connection_send"),flush:sym!("dbus_connection_flush"),get_fd:sym!("dbus_connection_get_unix_fd"),max_message:sym!("dbus_connection_set_max_message_size"),max_received:sym!("dbus_connection_set_max_received_size"),new_call:sym!("dbus_message_new_method_call"),new_return:sym!("dbus_message_new_method_return"),new_error:sym!("dbus_message_new_error"),unref:sym!("dbus_message_unref"),message_type:sym!("dbus_message_get_type"),reply_serial:sym!("dbus_message_get_reply_serial"),sender:sym!("dbus_message_get_sender"),path:sym!("dbus_message_get_path"),interface:sym!("dbus_message_get_interface"),member:sym!("dbus_message_get_member"),iter_init:sym!("dbus_message_iter_init"),iter_append:sym!("dbus_message_iter_init_append"),arg_type:sym!("dbus_message_iter_get_arg_type"),next:sym!("dbus_message_iter_next"),basic:sym!("dbus_message_iter_get_basic"),recurse:sym!("dbus_message_iter_recurse"),append_basic:sym!("dbus_message_iter_append_basic"),open:sym!("dbus_message_iter_open_container"),close:sym!("dbus_message_iter_close_container"),_library:library})
    }}
}
enum Arg{Text(String),Path(String),Bool(bool),Byte(u8),I16(i16),U16(u16),I32(i32),U32(u32),Fd(OwnedFd),Array(String,Vec<Arg>),Entry(Vec<Arg>),Variant(Box<Arg>)}
impl Arg{
    fn text(&self)->Option<&str>{match self{Self::Text(s)|Self::Path(s)=>Some(s),Self::Variant(v)=>v.text(),_=>None}}
    fn boolean(&self)->Option<bool>{match self{Self::Bool(v)=>Some(*v),Self::Variant(v)=>v.boolean(),_=>None}}
    fn signature(&self)->String{match self{Self::Text(_)=>"s".into(),Self::Path(_)=>"o".into(),Self::Bool(_)=>"b".into(),Self::Byte(_)=>"y".into(),Self::I16(_)=>"n".into(),Self::U16(_)=>"q".into(),Self::I32(_)=>"i".into(),Self::U32(_)=>"u".into(),Self::Fd(_)=>"h".into(),Self::Array(s,_)=>format!("a{s}"),Self::Entry(v)=>format!("{{{}}}",v.iter().map(Self::signature).collect::<String>()),Self::Variant(_)=>"v".into()}}
}
fn text(s:&str)->Arg{Arg::Text(s.into())}fn path(s:&str)->Arg{Arg::Path(s.into())}fn variant(a:Arg)->Arg{Arg::Variant(Box::new(a))}
fn dict(rows:Vec<(&str,Arg)>)->Arg{Arg::Array("{sv}".into(),rows.into_iter().map(|(k,v)|Arg::Entry(vec![text(k),variant(v)])).collect())}
fn cstring(s:&str)->Result<CString>{CString::new(s).map_err(|_|"invalid D-Bus string".into())}
unsafe fn ctext(p:*const c_char)->String{if p.is_null(){String::new()}else{CStr::from_ptr(p).to_string_lossy().into_owned()}}
fn append(api:&Api,iter:&mut Iter,arg:&Arg)->Result<()>{unsafe{
    macro_rules! basic{($kind:expr,$v:expr)=>{if (api.append_basic)(iter,$kind,$v as *const _ as *const c_void)==0{return Err("D-Bus allocation failed".into());}};}
    match arg{
        Arg::Text(s)|Arg::Path(s)=>{let c=cstring(s)?;let p=c.as_ptr();basic!((if matches!(arg,Arg::Path(_)){b'o'}else{b's'}) as c_int,&p);},
        Arg::Bool(v)=>{let n=*v as u32;basic!(b'b' as c_int,&n);},Arg::Byte(v)=>basic!(b'y' as c_int,v),Arg::I16(v)=>basic!(b'n' as c_int,v),Arg::U16(v)=>basic!(b'q' as c_int,v),Arg::I32(v)=>basic!(b'i' as c_int,v),Arg::U32(v)=>basic!(b'u' as c_int,v),Arg::Fd(v)=>{let n=v.as_raw_fd();basic!(b'h' as c_int,&n);},
        Arg::Array(sig,values)=>{let c=cstring(sig)?;let mut child=Iter::new();if (api.open)(iter,b'a' as c_int,c.as_ptr(),&mut child)==0{return Err("D-Bus allocation failed".into());}for value in values{append(api,&mut child,value)?;}if (api.close)(iter,&mut child)==0{return Err("D-Bus allocation failed".into());}},
        Arg::Entry(values)=>{let mut child=Iter::new();if (api.open)(iter,b'e' as c_int,ptr::null(),&mut child)==0{return Err("D-Bus allocation failed".into());}for value in values{append(api,&mut child,value)?;}if (api.close)(iter,&mut child)==0{return Err("D-Bus allocation failed".into());}},
        Arg::Variant(value)=>{let sig=cstring(&value.signature())?;let mut child=Iter::new();if (api.open)(iter,b'v' as c_int,sig.as_ptr(),&mut child)==0{return Err("D-Bus allocation failed".into());}append(api,&mut child,value)?;if (api.close)(iter,&mut child)==0{return Err("D-Bus allocation failed".into());}},
    }Ok(())
}}
fn read_arg(api:&Api,iter:&mut Iter,depth:usize)->Result<Arg>{unsafe{
    if depth>12{return Err("D-Bus nesting exceeds limit".into());}
    let kind=(api.arg_type)(iter);let mut n=0u64;
    match kind as u8{
        b's'|b'o'|b'g'=>{let mut p:*const c_char=ptr::null();(api.basic)(iter,&mut p as *mut _ as *mut c_void);let s=ctext(p);if s.len()>65536{return Err("D-Bus string exceeds limit".into());}Ok(if kind==b'o' as c_int{Arg::Path(s)}else{Arg::Text(s)})},
        b'b'|b'y'|b'n'|b'q'|b'i'|b'u'|b'h'=>{(api.basic)(iter,&mut n as *mut _ as *mut c_void);Ok(match kind as u8{b'b'=>Arg::Bool(n as u32!=0),b'y'=>Arg::Byte(n as u8),b'n'=>Arg::I16(n as i16),b'q'=>Arg::U16(n as u16),b'i'=>Arg::I32(n as i32),b'u'=>Arg::U32(n as u32),_=>{let fd=n as i32;if fd<0{return Err("invalid D-Bus descriptor".into());}Arg::Fd(OwnedFd::from_raw_fd(fd))}})},
        b'a'|b'e'|b'r'|b'v'=>{let mut child=Iter::new();(api.recurse)(iter,&mut child);let mut values=vec![];while (api.arg_type)(&mut child)!=0{if values.len()>=1024{return Err("D-Bus collection exceeds limit".into());}values.push(read_arg(api,&mut child,depth+1)?);if (api.next)(&mut child)==0{break;}}
            Ok(if kind==b'v' as c_int{if values.len()!=1{return Err("invalid variant".into());}Arg::Variant(Box::new(values.remove(0)))}else if kind==b'e' as c_int||kind==b'r' as c_int{Arg::Entry(values)}else{Arg::Array(String::new(),values)})},
        _=>Err("unsupported D-Bus value".into()),
    }
}}
fn args(api:&Api,m:Msg)->Result<Vec<Arg>>{let mut iter=Iter::new();if unsafe{(api.iter_init)(m,&mut iter)}==0{return Ok(vec![]);}let mut out=vec![];loop{if out.len()>=32{return Err("too many D-Bus arguments".into());}out.push(read_arg(api,&mut iter,0)?);if unsafe{(api.next)(&mut iter)}==0{break;}}Ok(out)}
struct Message<'a>{api:&'a Api,raw:Msg}impl Drop for Message<'_>{fn drop(&mut self){unsafe{(self.api.unref)(self.raw);}}}
struct Bus{api:Api,connection:Conn,bluez:String,nm:String}
impl Drop for Bus{fn drop(&mut self){unsafe{(self.api.connection_close)(self.connection);(self.api.connection_unref)(self.connection);}}}
impl Bus{
    fn open()->Result<Self>{let api=Api::load()?;let connection=unsafe{(api.bus_get)(1,ptr::null_mut())};if connection.is_null(){return Err("cannot connect system D-Bus".into());}unsafe{(api.exit_on_disconnect)(connection,0);(api.max_message)(connection,262144);(api.max_received)(connection,1048576);}Ok(Self{api,connection,bluez:String::new(),nm:String::new()})}
    fn send(&self,m:Msg)->Result<u32>{let mut serial=0;if unsafe{(self.api.send)(self.connection,m,&mut serial)}==0{return Err("D-Bus send failed".into());}unsafe{(self.api.flush)(self.connection);}Ok(serial)}
    fn reply(&self,request:Msg,values:Vec<Arg>)->Result<()>{let raw=unsafe{(self.api.new_return)(request)};if raw.is_null(){return Err("D-Bus allocation failed".into());}let m=Message{api:&self.api,raw};let mut iter=Iter::new();unsafe{(self.api.iter_append)(raw,&mut iter);}for a in &values{append(&self.api,&mut iter,a)?;}self.send(m.raw)?;Ok(())}
    fn reject(&self,request:Msg,name:&str)->Result<()>{let name=cstring(name)?;let detail=cstring("request rejected")?;let raw=unsafe{(self.api.new_error)(request,name.as_ptr(),detail.as_ptr())};if raw.is_null(){return Err("D-Bus allocation failed".into());}let m=Message{api:&self.api,raw};self.send(m.raw)?;Ok(())}
    fn call(&mut self,state:&mut State,ipc:&mut Ipc,destination:&str,object:&str,interface:&str,member:&str,values:Vec<Arg>,timeout:Duration)->Result<Vec<Arg>>{
        let d=cstring(destination)?;let o=cstring(object)?;let i=cstring(interface)?;let n=cstring(member)?;
        let raw=unsafe{(self.api.new_call)(d.as_ptr(),o.as_ptr(),i.as_ptr(),n.as_ptr())};if raw.is_null(){return Err("D-Bus allocation failed".into());}
        let serial={let m=Message{api:&self.api,raw};let mut iter=Iter::new();unsafe{(self.api.iter_append)(raw,&mut iter);}for a in &values{append(&self.api,&mut iter,a)?;}self.send(m.raw)?};
        let expected=if destination=="org.bluez"{self.bluez.clone()}else if destination=="org.freedesktop.NetworkManager"{self.nm.clone()}else{destination.into()};
        let until=Instant::now()+timeout;
        while Instant::now()<until{
            if unsafe{(self.api.read_write)(self.connection,20)}==0{return Err("system D-Bus disconnected".into());}
            loop{let raw=unsafe{(self.api.pop)(self.connection)};if raw.is_null(){break;}
                let kind=unsafe{(self.api.message_type)(raw)};
                if matches!(kind,2|3)&&unsafe{(self.api.reply_serial)(raw)}==serial{
                    let m=Message{api:&self.api,raw};let sender=unsafe{ctext((self.api.sender)(raw))};
                    if sender!=expected{continue;}if kind==3{return Err("D-Bus method rejected".into());}return args(&self.api,m.raw);
                }
                let handled=state.handle(self,ipc,raw);unsafe{(self.api.unref)(raw);}handled?;
            }
        }Err("D-Bus method timeout".into())
    }
    fn owner(&mut self,state:&mut State,ipc:&mut Ipc,name:&str)->Result<String>{let a=self.call(state,ipc,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","GetNameOwner",vec![text(name)],Duration::from_secs(3))?;a.first().and_then(Arg::text).map(str::to_owned).ok_or("missing D-Bus owner".into())}
    fn poll(&mut self,state:&mut State,ipc:&mut Ipc)->Result<()>{if unsafe{(self.api.read_write)(self.connection,0)}==0{return Err("system D-Bus disconnected".into());}loop{let raw=unsafe{(self.api.pop)(self.connection)};if raw.is_null(){break;}let r=state.handle(self,ipc,raw);unsafe{(self.api.unref)(raw);}r?;}Ok(())}
}

struct Ipc{fd:OwnedFd}
impl Ipc{
    fn new(fd:i32)->Result<Self>{if fd<3{return Err("radio worker requires private descriptor".into());}let fd=unsafe{OwnedFd::from_raw_fd(fd)};
        let flags=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_GETFD)};if flags<0||unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_SETFD,flags|libc::FD_CLOEXEC)}<0{return Err("cannot secure private radio descriptor".into());}
        let mut kind=0;let mut size=mem::size_of::<c_int>() as libc::socklen_t;
        if unsafe{libc::getsockopt(fd.as_raw_fd(),libc::SOL_SOCKET,libc::SO_TYPE,&mut kind as *mut _ as *mut c_void,&mut size)}!=0||kind!=libc::SOCK_SEQPACKET{return Err("radio IPC requires SOCK_SEQPACKET".into());}
        let mut peer:libc::sockaddr_un=unsafe{mem::zeroed()};let mut len=mem::size_of_val(&peer) as libc::socklen_t;
        if unsafe{libc::getpeername(fd.as_raw_fd(),&mut peer as *mut _ as *mut libc::sockaddr,&mut len)}!=0||peer.sun_family!=libc::AF_UNIX as u16{return Err("radio IPC requires connected Unix socket".into());}
        #[cfg(target_os="linux")]{let mut cred:libc::ucred=unsafe{mem::zeroed()};let mut len=mem::size_of_val(&cred) as libc::socklen_t;if unsafe{libc::getsockopt(fd.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,&mut cred as *mut _ as *mut c_void,&mut len)}!=0||cred.uid!=unsafe{libc::geteuid()}{return Err("radio IPC peer identity mismatch".into());}}
        Ok(Self{fd})
    }
    fn receive(&self)->Result<Option<Value>>{let mut data=[0u8;65537];let n=unsafe{libc::recv(self.fd.as_raw_fd(),data.as_mut_ptr() as *mut c_void,data.len(),libc::MSG_DONTWAIT|libc::MSG_TRUNC)};
        if n==0{return Ok(Some(json!({"op":"close"})));}if n<0{let e=io::Error::last_os_error();return if e.kind()==io::ErrorKind::WouldBlock{Ok(None)}else{Err("private radio IPC read failed".into())};}
        if n as usize>65536{return Err("radio IPC exceeds limit".into());}serde_json::from_slice(&data[..n as usize]).map(Some).map_err(|_|"invalid private radio JSON".into())
    }
    fn send(&self,value:&Value,fd:Option<i32>)->Result<()>{let bytes=serde_json::to_vec(value).map_err(|_|"private radio serialization failed")?;if bytes.len()>65536{return Err("private radio response exceeds limit".into());}
        let mut iov=libc::iovec{iov_base:bytes.as_ptr() as *mut c_void,iov_len:bytes.len()};let mut msg:libc::msghdr=unsafe{mem::zeroed()};msg.msg_iov=&mut iov;msg.msg_iovlen=1;
        let mut control=[0usize;8];if let Some(fd)=fd{msg.msg_control=control.as_mut_ptr() as *mut c_void;msg.msg_controllen=unsafe{libc::CMSG_SPACE(mem::size_of::<i32>() as u32)} as usize;unsafe{let c=libc::CMSG_FIRSTHDR(&msg);(*c).cmsg_level=libc::SOL_SOCKET;(*c).cmsg_type=libc::SCM_RIGHTS;(*c).cmsg_len=libc::CMSG_LEN(mem::size_of::<i32>() as u32) as usize;ptr::write_unaligned(libc::CMSG_DATA(c) as *mut i32,fd);}}
        if unsafe{libc::sendmsg(self.fd.as_raw_fd(),&msg,libc::MSG_NOSIGNAL|libc::MSG_DONTWAIT)}!=bytes.len() as isize{return Err("private radio IPC write failed".into());}Ok(())
    }
}

struct State{selection:Selection,payload:Vec<u8>,power:i16,instance:u8,stopped:bool,closing:bool,slots:BTreeSet<(String,String)>,origin:Instant,wake_peer:Option<String>}
impl State{
    fn properties(&self)->Arg{dict(vec![("Type",text("peripheral")),("Discoverable",Arg::Bool(true)),("LocalName",text("HelloCar")),("TxPower",Arg::I16(self.power)),("Instance",Arg::Byte(self.instance)),("ServiceData",dict(vec![(FDEE,Arg::Array("y".into(),self.payload.iter().copied().map(Arg::Byte).collect()))]))])}
    fn handle(&mut self,bus:&mut Bus,ipc:&mut Ipc,m:Msg)->Result<()>{
        let kind=unsafe{(bus.api.message_type)(m)};let sender=unsafe{ctext((bus.api.sender)(m))};let object=unsafe{ctext((bus.api.path)(m))};let interface=unsafe{ctext((bus.api.interface)(m))};let member=unsafe{ctext((bus.api.member)(m))};
        if kind==4&&sender=="org.freedesktop.DBus"&&interface=="org.freedesktop.DBus"&&member=="NameOwnerChanged"{
            let a=args(&bus.api,m)?;if let (Some(name),Some(new))=(a.first().and_then(Arg::text),a.get(2).and_then(Arg::text)){
                if name=="org.bluez"&&new!=bus.bluez||name=="org.freedesktop.NetworkManager"&&!bus.nm.is_empty()&&new!=bus.nm{self.stopped=true;}
            }return Ok(());
        }
        if kind==4&&sender==bus.bluez&&interface==PROPERTIES&&member=="PropertiesChanged"{
            if self.selection.selected.as_ref()==Some(&object){let a=args(&bus.api,m)?;if a.first().and_then(Arg::text)==Some("org.bluez.Device1"){if let Some(Arg::Array(_,rows))=a.get(1){for row in rows{if let Arg::Entry(v)=row{if v.first().and_then(Arg::text)==Some("Connected")&&v.get(1).and_then(Arg::boolean)==Some(false){let _=ipc.send(&json!({"event":"disconnected","device":object}),None);}}}}}}return Ok(());
        }
        if kind!=1{return Ok(());}if sender!=bus.bluez{return bus.reject(m,"org.bluez.Error.Rejected");}
        let a=match args(&bus.api,m){Ok(v)=>v,Err(_)=>return bus.reject(m,"org.freedesktop.DBus.Error.InvalidArgs")};
        if interface==PROPERTIES&&object==format!("{ROOT}/advertisement"){
            if a.first().and_then(Arg::text)!=Some("org.bluez.LEAdvertisement1"){return bus.reject(m,"org.freedesktop.DBus.Error.InvalidArgs");}
            if member=="GetAll"{return bus.reply(m,vec![self.properties()]);}
            if member=="Get"{let wanted=a.get(1).and_then(Arg::text).unwrap_or("");if let Arg::Array(_,rows)=self.properties(){for row in rows{if let Arg::Entry(mut values)=row{if values.first().and_then(Arg::text)==Some(wanted){return bus.reply(m,vec![values.remove(1)]);}}}}}
            if member=="Set"{if let (Some(name),Some(Arg::Variant(value)))=(a.get(1).and_then(Arg::text),a.get(2)){match (name,value.as_ref()){("TxPower",Arg::I16(n))=>self.power=*n,("Instance",Arg::Byte(n))=>self.instance=*n,_=>return bus.reject(m,"org.freedesktop.DBus.Error.InvalidArgs")};return bus.reply(m,vec![]);}}
            return bus.reject(m,"org.freedesktop.DBus.Error.InvalidArgs");
        }
        if interface=="org.bluez.Agent1"&&object==format!("{ROOT}/agent"){
            if member=="Release"||member=="Cancel"{return bus.reply(m,vec![]);}
            let allowed=a.first().and_then(Arg::text).is_some_and(|p|self.selection.allows(p,false,self.origin.elapsed().as_millis() as u64));
            if !allowed||self.closing{return bus.reject(m,"org.bluez.Error.Rejected");}
            if member=="RequestConfirmation"||member=="RequestAuthorization"{return bus.reply(m,vec![]);}
            if member=="AuthorizeService"&&a.get(1).and_then(Arg::text).is_some_and(|s|[FE35,FE36].contains(&s.to_ascii_lowercase().as_str())){return bus.reply(m,vec![]);}
            return bus.reject(m,"org.bluez.Error.Rejected");
        }
        if interface=="org.bluez.LEAdvertisement1"&&member=="Release"{self.stopped=true;return bus.reply(m,vec![]);}
        if interface=="org.bluez.Profile1"{
            if member=="Release"{self.stopped=true;return bus.reply(m,vec![]);}
            let stream=if object==format!("{ROOT}/profile"){"control"}else if object==format!("{ROOT}/business"){"business"}else{return bus.reject(m,"org.bluez.Error.Rejected");};
            if member=="RequestDisconnection"{if let Some(device)=a.first().and_then(Arg::text){self.slots.remove(&(stream.into(),device.into()));let _=ipc.send(&json!({"event":"request-disconnection","stream":stream,"device":device}),None);}return bus.reply(m,vec![]);}
            if member=="NewConnection"{
                let Some(device)=a.first().and_then(Arg::text)else{return bus.reject(m,"org.bluez.Error.Rejected");};
                let slot=(stream.into(),device.into());
                if self.closing||self.slots.len()>=4||self.slots.contains(&slot)||!self.selection.allows(device,false,self.origin.elapsed().as_millis() as u64){return bus.reject(m,"org.bluez.Error.Rejected");}
                let Some(Arg::Fd(fd))=a.get(1)else{return bus.reject(m,"org.bluez.Error.Rejected");};
                let mut kind=0;let mut len=mem::size_of::<c_int>() as libc::socklen_t;
                if unsafe{libc::getsockopt(fd.as_raw_fd(),libc::SOL_SOCKET,libc::SO_TYPE,&mut kind as *mut _ as *mut c_void,&mut len)}!=0||kind!=libc::SOCK_STREAM{return bus.reject(m,"org.bluez.Error.Rejected");}
                let mut remote:libc::sockaddr_storage=unsafe{mem::zeroed()};let mut size=mem::size_of_val(&remote) as libc::socklen_t;
                if unsafe{libc::getpeername(fd.as_raw_fd(),&mut remote as *mut _ as *mut libc::sockaddr,&mut size)}!=0{return bus.reject(m,"org.bluez.Error.Rejected");}
                if !self.selection.allows(device,true,self.origin.elapsed().as_millis() as u64){return bus.reject(m,"org.bluez.Error.Rejected");}
                let address=self.selection.address(device).ok_or("invalid selected peer")?;
                if ipc.send(&json!({"event":"rfcomm","stream":stream,"device":device,"address":address,"initiator":false}),Some(fd.as_raw_fd())).is_err(){return bus.reject(m,"org.bluez.Error.Rejected");}
                self.slots.insert(slot);return bus.reply(m,vec![]);
            }
        }
        bus.reject(m,"org.freedesktop.DBus.Error.UnknownMethod")
    }
}

#[derive(Serialize)]struct Offer{ssid:String,bssid:String,password:String,owner_ip:&'static str,client_ip:&'static str,frequency:u32,port:u16}
struct SdpQuery{child:std::process::Child,out:std::process::ChildStdout,bytes:Vec<u8>,deadline:Instant,peer:String}
impl Drop for SdpQuery{fn drop(&mut self){let _=self.child.kill();let _=self.child.wait();}}
impl SdpQuery{
    fn spawn(mut command:Command,peer:String,timeout:Duration)->Result<Self>{
        let mut child=command.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().map_err(|_|"cannot start SDP discovery")?;
        let out=child.stdout.take().ok_or("SDP output unavailable")?;let flags=unsafe{libc::fcntl(out.as_raw_fd(),libc::F_GETFL)};
        if flags<0||unsafe{libc::fcntl(out.as_raw_fd(),libc::F_SETFL,flags|libc::O_NONBLOCK)}<0{let _=child.kill();let _=child.wait();return Err("cannot configure nonblocking SDP output".into());}
        Ok(Self{child,out,bytes:vec![],deadline:Instant::now()+timeout,peer})
    }
    fn poll(&mut self)->Result<Option<u16>>{
        if Instant::now()>=self.deadline{return Err("SDP discovery timed out".into());}
        // Bound per-tick work as well as total output so D-Bus/IPC stays live.
        let mut buf=[0u8;4096];for _ in 0..2{match self.out.read(&mut buf){Ok(0)=>break,Ok(n)=>{if self.bytes.len()+n>65536{return Err("SDP output exceeds limit".into());}self.bytes.extend_from_slice(&buf[..n]);},Err(e)if e.kind()==io::ErrorKind::WouldBlock=>break,Err(_)=>return Err("SDP output failed".into())}}
        if let Some(status)=self.child.try_wait().map_err(|_|"SDP process failed")?{
            if !status.success(){return Err("SDP discovery failed".into());}
            // Finished children may still have more than one tick of buffered data.
            match self.out.read(&mut buf){Ok(0)=>return rfcomm_channel(&self.bytes).map(Some),Ok(n)=>{if self.bytes.len()+n>65536{return Err("SDP output exceeds limit".into());}self.bytes.extend_from_slice(&buf[..n]);},Err(e)if e.kind()==io::ErrorKind::WouldBlock=>{},Err(_)=>return Err("SDP output failed".into())}
        }Ok(None)
    }
}
fn rfcomm_socket(peer:&str,port:u16)->Result<OwnedFd>{
    if !(1..=30).contains(&port){return Err("invalid outgoing RFCOMM channel".into());}
    #[repr(C)]struct RcAddress{family:u16,address:[u8;6],channel:u8}
    let mut bytes=[0u8;6];for(dst,src)in bytes.iter_mut().rev().zip(mac(peer)?.split(':')){*dst=u8::from_str_radix(src,16).map_err(|_|"invalid selected peer")?;}
    let raw=unsafe{libc::socket(31,libc::SOCK_STREAM|libc::SOCK_NONBLOCK|libc::SOCK_CLOEXEC,3)};if raw<0{return Err("cannot create outgoing RFCOMM socket".into());}let fd=unsafe{OwnedFd::from_raw_fd(raw)};
    let address=RcAddress{family:31,address:bytes,channel:port as u8};let result=unsafe{libc::connect(raw,&address as *const _ as *const libc::sockaddr,mem::size_of_val(&address) as _)};
    if result<0&&io::Error::last_os_error().raw_os_error()!=Some(libc::EINPROGRESS){return Err("outgoing RFCOMM connection failed".into());}Ok(fd)
}
fn rfcomm_ready(fd:&OwnedFd,started:Instant)->Option<bool>{
    if started.elapsed()>=Duration::from_secs(12){return Some(false);}let mut p=libc::pollfd{fd:fd.as_raw_fd(),events:libc::POLLOUT,revents:0};let n=unsafe{libc::poll(&mut p,1,0)};
    if n==0{return None;}let mut error=0i32;let mut len=mem::size_of::<i32>() as libc::socklen_t;
    Some(n>0&&unsafe{libc::getsockopt(fd.as_raw_fd(),libc::SOL_SOCKET,libc::SO_ERROR,&mut error as *mut _ as *mut c_void,&mut len)}==0&&error==0)
}
struct Radio{bus:Bus,state:State,ipc:Ipc,c:Config,device:Option<String>,connection:Option<String>,previous:Option<String>,offer:Option<Offer>,agent:bool,profile:bool,business:bool,advertisement:bool,restore_connectable:bool,restore_bondable:bool,activated:bool,startup_cancelled:bool,startup_close_id:Option<Value>,reconnect_at:Instant,reconnect_attempts:u8,projection_active:bool,reconnect_allowed:bool,business_connect:Option<(OwnedFd,Instant)>,sdp_query:Option<SdpQuery>,control_connect:Option<(OwnedFd,Instant,String)>}
impl Radio{
    fn call(&mut self,d:&str,p:&str,i:&str,m:&str,a:Vec<Arg>,timeout:Duration)->Result<Vec<Arg>>{self.bus.call(&mut self.state,&mut self.ipc,d,p,i,m,a,timeout)}
    fn bluez(&mut self,p:&str,i:&str,m:&str,a:Vec<Arg>)->Result<Vec<Arg>>{self.call("org.bluez",p,i,m,a,Duration::from_secs(5))}
    fn nm(&mut self,p:&str,i:&str,m:&str,a:Vec<Arg>)->Result<Vec<Arg>>{self.call("org.freedesktop.NetworkManager",p,i,m,a,Duration::from_secs(5))}
    fn property(&mut self,d:&str,p:&str,i:&str,k:&str)->Result<Arg>{let mut result=self.call(d,p,PROPERTIES,"Get",vec![text(i),text(k)],Duration::from_secs(3))?;if result.len()!=1{return Err("missing D-Bus property".into());}Ok(result.remove(0))}
    fn check_startup_cancel(&mut self)->Result<()>{
        if let Some(command)=self.ipc.receive()?{
            if command["op"]!="close"{return Err("radio operation before preparation completed".into());}
            self.startup_cancelled=true;self.startup_close_id=command.get("id").cloned();self.state.closing=true;
            return Err("radio preparation cancelled".into());
        }Ok(())
    }
    fn prepare(&mut self)->Result<String>{
        self.check_startup_cancel()?;
        self.bus.bluez=self.bus.owner(&mut self.state,&mut self.ipc,"org.bluez")?;
        let p=self.c.adapter.clone();let powered=self.property("org.bluez",&p,"org.bluez.Adapter1","Powered")?;
        if powered.boolean()!=Some(true){return Err("Bluetooth adapter is powered off".into());}
        let address=self.property("org.bluez",&p,"org.bluez.Adapter1","Address")?.text().ok_or("missing adapter address")?.to_owned();mac(&address)?;
        // Receive only BlueZ's property changes, not application bus traffic.
        self.call("org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","AddMatch",vec![text("type='signal',sender='org.bluez',interface='org.freedesktop.DBus.Properties'")],Duration::from_secs(3))?;
        for name in ["org.bluez","org.freedesktop.NetworkManager"]{self.call("org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","AddMatch",vec![text(&format!("type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='{name}'"))],Duration::from_secs(3))?;}
        if self.c.network{self.hotspot()?;}self.check_startup_cancel()?;Ok(address)
    }
    fn hotspot(&mut self)->Result<()>{
        let interface=self.c.interface.as_ref().ok_or("wireless interface required")?.clone();
        let addresses:Value=serde_json::from_slice(&command("ip",&["-j","address"])?).map_err(|_|"invalid interface addresses")?;
        let tcp=std::fs::read_to_string("/proc/net/tcp").map_err(|_|"cannot inspect management connections")?;
        let tcp6=match std::fs::read_to_string("/proc/net/tcp6"){Ok(s)=>s,Err(e) if e.kind()==io::ErrorKind::NotFound=>String::new(),Err(_)=>return Err("cannot inspect management connections".into())};
        if ssh_on_interface(&addresses,&interface,&tcp,&tcp6)?{return Err("active SSH uses the wireless interface".into());}
        if addresses.as_array().is_none_or(|links|links.iter().any(|l|l["addr_info"].as_array().is_some_and(|a|a.iter().any(|a|a["local"].as_str().is_some_and(|s|s.starts_with("192.168.49.")))))){return Err("HiCar subnet already in use".into());}
        self.bus.nm=self.bus.owner(&mut self.state,&mut self.ipc,"org.freedesktop.NetworkManager")?;
        let device=self.nm("/org/freedesktop/NetworkManager","org.freedesktop.NetworkManager","GetDeviceByIpIface",vec![text(&interface)])?.first().and_then(Arg::text).ok_or("wireless device missing")?.to_owned();self.device=Some(device.clone());
        let active=self.property("org.freedesktop.NetworkManager",&device,"org.freedesktop.NetworkManager.Device","ActiveConnection")?.text().unwrap_or("/").to_owned();
        if active!="/"{let previous=self.property("org.freedesktop.NetworkManager",&active,"org.freedesktop.NetworkManager.Connection.Active","Connection")?.text().ok_or("previous connection missing")?.to_owned();self.previous=Some(previous);}
        let _=self.nm(&device,"org.freedesktop.NetworkManager.Device","Disconnect",vec![]);
        let mut random=[0u8;32];std::fs::File::open("/dev/urandom").and_then(|mut f|std::io::Read::read_exact(&mut f,&mut random)).map_err(|_|"cannot obtain hotspot credentials")?;
        let password=super::super::hex(&random[..16]);let id=format!("hellocar-{}",super::super::hex(&random[16..20]));
        let mut uuid=random[16..32].to_vec();uuid[6]=(uuid[6]&15)|64;uuid[8]=(uuid[8]&63)|128;let h=super::super::hex(&uuid);let uuid=format!("{}-{}-{}-{}-{}",&h[..8],&h[8..12],&h[12..16],&h[16..20],&h[20..]);
        let settings=Arg::Array("{sa{sv}}".into(),vec![
            Arg::Entry(vec![text("connection"),dict(vec![("id",text(&id)),("uuid",text(&uuid)),("type",text("802-11-wireless")),("interface-name",text(&interface)),("autoconnect",Arg::Bool(false))])]),
            Arg::Entry(vec![text("802-11-wireless"),dict(vec![("ssid",Arg::Array("y".into(),b"HelloCar".iter().copied().map(Arg::Byte).collect())),("mode",text("ap")),("band",text("a")),("channel",Arg::U32(149))])]),
            Arg::Entry(vec![text("802-11-wireless-security"),dict(vec![("key-mgmt",text("wpa-psk")),("proto",Arg::Array("s".into(),vec![text("rsn")])),("psk",text(&password))])]),
            Arg::Entry(vec![text("ipv4"),dict(vec![("method",text("shared")),("address-data",Arg::Array("a{sv}".into(),vec![dict(vec![("address",text("192.168.49.1")),("prefix",Arg::U32(24))])]))])]),
            Arg::Entry(vec![text("ipv6"),dict(vec![("method",text("disabled"))])]),
        ]);
        let connection=self.nm("/org/freedesktop/NetworkManager/Settings","org.freedesktop.NetworkManager.Settings","AddConnectionUnsaved",vec![settings])?.first().and_then(Arg::text).ok_or("missing temporary connection")?.to_owned();self.connection=Some(connection.clone());
        command("iw",&["reg","set","CN"])?;
        self.nm("/org/freedesktop/NetworkManager","org.freedesktop.NetworkManager","ActivateConnection",vec![path(&connection),path(&device),path("/")])?;
        // ActivateConnection returns before address configuration completes.
        // The adapter may still report the previous AP's type/channel, so the
        // exact address on this interface is required before listeners bind.
        let deadline=Instant::now()+Duration::from_secs(12);loop{
            // Parent cancellation must reach cleanup before the manager's
            // bounded group stop. Each external diagnostic has a 3s limit;
            // check between them rather than waiting for the whole IP window.
            self.check_startup_cancel()?;
            let info=command("iw",&["dev",&interface,"info"])?;let info=String::from_utf8_lossy(&info);
            self.check_startup_cancel()?;
            let addresses:Value=serde_json::from_slice(&command("ip",&["-j","address"])?).map_err(|_|"invalid hotspot interface addresses")?;
            self.check_startup_cancel()?;
            if info.contains("type AP")&&info.contains("(5745 MHz)")&&hotspot_ipv4_ready(&addresses,&interface){break;}
            if Instant::now()>=deadline{return Err("5 GHz hotspot IPv4 not ready".into());}std::thread::sleep(Duration::from_millis(100));
        }
        let bssid=std::fs::read_to_string(Path::new("/sys/class/net").join(&interface).join("address")).map_err(|_|"cannot read hotspot address")?;let bssid=mac(bssid.trim())?;
        self.offer=Some(Offer{ssid:"HelloCar".into(),bssid,password,owner_ip:"192.168.49.1",client_ip:"192.168.49.2",frequency:5745,port:4005});super::super::crypto::wipe(&mut random);Ok(())
    }
    fn activate(&mut self)->Result<()>{
        if self.activated{return Err("radio already active".into());}
        self.state.origin=Instant::now();self.state.selection.deadline=(self.c.pair_seconds!=0).then_some(self.c.pair_seconds*1000);
        self.bluez("/org/bluez","org.bluez.AgentManager1","RegisterAgent",vec![path(&format!("{ROOT}/agent")),text("NoInputNoOutput")])?;self.agent=true;
        self.bluez("/org/bluez","org.bluez.AgentManager1","RequestDefaultAgent",vec![path(&format!("{ROOT}/agent"))])?;
        if self.c.manage_controller{let settings=mgmt(self.index()?,4,&[],Duration::from_secs(3))?;if settings.len()<17{return Err("truncated controller information".into());}let current=u32::from_le_bytes(settings[13..17].try_into().unwrap());
            self.restore_bondable=current&16==0;self.restore_connectable=current&2==0;
            if self.restore_bondable{self.setting(9,16,true,Duration::from_secs(3))?;}if self.restore_connectable{self.setting(7,2,true,Duration::from_secs(3))?;}}
        for (suffix,uuid,channel,business) in [("business",FE36,self.c.channel+1,true),("profile",FE35,self.c.channel,false)]{
            self.bluez("/org/bluez","org.bluez.ProfileManager1","RegisterProfile",vec![path(&format!("{ROOT}/{suffix}")),text(uuid),dict(vec![("Name",text(if business{"NearbyBusinessSocket"}else{"NearbyServerSocket"})),("Channel",Arg::U16(channel)),("ServiceRecord",text(&service_record(channel,uuid))),("RequireAuthentication",Arg::Bool(false)),("RequireAuthorization",Arg::Bool(false))])])?;
            if business{self.business=true;}else{self.profile=true;}
        }
        let p=self.c.adapter.clone();self.bluez(&p,"org.bluez.LEAdvertisingManager1","RegisterAdvertisement",vec![path(&format!("{ROOT}/advertisement")),dict(vec![])])?;self.advertisement=true;self.activated=true;
        if let Some(peer)=self.state.wake_peer.clone(){self.reconnect_allowed=self.property("org.bluez",&peer,"org.bluez.Device1","Paired").ok().and_then(|v|v.boolean())==Some(true);}Ok(())
    }
    fn reconnect(&mut self)->Result<()>{
        if !self.activated||!self.reconnect_allowed||self.projection_active||self.state.closing||!self.state.slots.is_empty()||Instant::now()<self.reconnect_at{return Ok(());}
        let Some(peer)=self.state.wake_peer.clone()else{return Ok(());};
        if !self.state.selection.allows(&peer,false,self.state.origin.elapsed().as_millis() as u64){return Ok(());}
        if self.sdp_query.is_some()||self.control_connect.is_some(){return Ok(());}
        self.reconnect_attempts=self.reconnect_attempts.saturating_add(1);self.reconnect_at=Instant::now()+Duration::from_secs(match self.reconnect_attempts{1=>3,2=>5,_=>10});
        let address=self.state.selection.address(&peer).ok_or("invalid reconnect peer")?;let mut command=Command::new("/usr/bin/sdptool");command.env("LC_ALL","C");command.args(["search","--bdaddr",&address,"0xfe35"]);
        self.sdp_query=Some(SdpQuery::spawn(command,peer,Duration::from_secs(8))?);Ok(())
    }
    fn poll_control(&mut self)->Result<()>{
        if let Some(query)=self.sdp_query.as_mut(){
            let peer=query.peer.clone();let allowed=!self.projection_active&&self.state.slots.is_empty()&&self.state.selection.allows(&peer,false,self.state.origin.elapsed().as_millis() as u64);
            if !allowed{self.sdp_query=None;return Ok(());}
            match query.poll(){Ok(None)=>{},Ok(Some(port))=>{self.sdp_query=None;let address=self.state.selection.address(&peer).ok_or("invalid reconnect peer")?;
                match rfcomm_socket(&address,port){Ok(fd)=>self.control_connect=Some((fd,Instant::now(),peer)),Err(_)=>{let _=self.ipc.send(&json!({"event":"reconnect-result","success":false}),None);}}
            },Err(_)=>{self.sdp_query=None;let _=self.ipc.send(&json!({"event":"reconnect-result","success":false}),None);}}
        }
        if let Some((fd,started,peer))=self.control_connect.as_ref(){
            if self.projection_active||!self.state.slots.is_empty()||!self.state.selection.allows(peer,false,self.state.origin.elapsed().as_millis() as u64){self.control_connect=None;return Ok(());}
            if let Some(ready)=rfcomm_ready(fd,*started){let (fd,_,peer)=self.control_connect.take().unwrap();
                if ready&&self.state.selection.allows(&peer,true,self.state.origin.elapsed().as_millis() as u64){let address=self.state.selection.address(&peer).ok_or("invalid reconnect peer")?;
                    self.ipc.send(&json!({"event":"rfcomm","stream":"control","device":peer,"address":address,"initiator":true}),Some(fd.as_raw_fd()))?;self.state.slots.insert(("control".into(),peer));
                    let _=self.ipc.send(&json!({"event":"reconnect-result","success":true}),None);
                }else{let _=self.ipc.send(&json!({"event":"reconnect-result","success":false}),None);}
            }
        }Ok(())
    }
    fn open_business(&mut self,port:u16)->Result<()>{
        if !self.reconnect_allowed||self.projection_active||self.business_connect.is_some()||!(1..=30).contains(&port){return Err("outgoing business connection unavailable".into());}
        let selected=self.state.selection.selected.as_deref().ok_or("selected peer missing")?;if self.state.wake_peer.as_deref()!=Some(selected){return Err("outgoing business peer no longer selected".into());}let peer=self.state.selection.address(selected).ok_or("invalid selected peer")?;
        if self.state.slots.iter().any(|(stream,_)|stream=="business"){return Err("business connection already present".into());}
        self.business_connect=Some((rfcomm_socket(&peer,port)?,Instant::now()));Ok(())
    }
    fn poll_business(&mut self)->Result<()>{
        let Some((fd,started))=self.business_connect.as_ref()else{return Ok(());};let Some(ready)=rfcomm_ready(fd,*started)else{return Ok(());};
        let (fd,_)=self.business_connect.take().unwrap();if !ready{let _=self.ipc.send(&json!({"event":"reconnect-result","success":false}),None);return Ok(());}
        let device=self.state.selection.selected.clone().ok_or("selected peer missing")?;let address=self.state.selection.address(&device).ok_or("invalid selected peer")?;
        self.ipc.send(&json!({"event":"rfcomm","stream":"business","device":device,"address":address,"initiator":true}),Some(fd.as_raw_fd()))?;
        self.state.slots.insert(("business".into(),device));Ok(())
    }
    fn index(&self)->Result<u16>{self.c.adapter.rsplit("hci").next().ok_or("invalid adapter")?.parse().map_err(|_|"invalid adapter index".into())}
    fn setting(&self,opcode:u16,mask:u32,enabled:bool,timeout:Duration)->Result<()>{let result=mgmt(self.index()?,opcode,&[u8::from(enabled)],timeout)?;if result.len()<4||(u32::from_le_bytes(result[..4].try_into().unwrap())&mask!=0)!=enabled{return Err("controller setting not applied".into());}Ok(())}
    fn cleanup(&mut self){self.state.closing=true;self.business_connect=None;self.sdp_query=None;self.control_connect=None;
        let registrations=[(self.advertisement,self.c.adapter.clone(),"org.bluez.LEAdvertisingManager1","UnregisterAdvertisement",format!("{ROOT}/advertisement")),(self.profile,"/org/bluez".into(),"org.bluez.ProfileManager1","UnregisterProfile",format!("{ROOT}/profile")),(self.business,"/org/bluez".into(),"org.bluez.ProfileManager1","UnregisterProfile",format!("{ROOT}/business")),(self.agent,"/org/bluez".into(),"org.bluez.AgentManager1","UnregisterAgent",format!("{ROOT}/agent"))];
        self.advertisement=false;self.profile=false;self.business=false;self.agent=false;self.activated=false;
        for (active,p,i,m,arg) in registrations{if active{let _=self.call("org.bluez",&p,i,m,vec![path(&arg)],Duration::from_millis(500));}}
        if self.restore_bondable{self.restore_bondable=false;let _=self.setting(9,16,false,Duration::from_millis(500));}if self.restore_connectable{self.restore_connectable=false;let _=self.setting(7,2,false,Duration::from_millis(500));}
        if let Some(c)=self.connection.take(){let _=self.call("org.freedesktop.NetworkManager",&c,"org.freedesktop.NetworkManager.Settings.Connection","Delete",vec![],Duration::from_secs(1));}
        if let (Some(previous),Some(device))=(self.previous.take(),self.device.take()){let _=self.call("org.freedesktop.NetworkManager","/org/freedesktop/NetworkManager","org.freedesktop.NetworkManager","ActivateConnection",vec![path(&previous),path(&device),path("/")],Duration::from_secs(2));}
        self.offer=None;
    }
}
#[cfg(test)]mod sdp_process_tests{
    use super::*;
    #[test]fn sdp_query_does_not_block_and_cancels_on_deadline(){
        let mut command=Command::new("/bin/sh");command.args(["-c","exec sleep 5"]);
        let mut query=SdpQuery::spawn(command,"private-peer".into(),Duration::from_secs(5)).unwrap();let pid=query.child.id() as i32;
        let before=Instant::now();assert!(query.poll().unwrap().is_none());assert!(before.elapsed()<Duration::from_millis(200));
        query.deadline=Instant::now()-Duration::from_millis(1);assert_eq!(query.poll().unwrap_err(),"SDP discovery timed out");drop(query);assert_ne!(unsafe{libc::kill(pid,0)},0);
    }
    #[test]fn sdp_query_returns_only_verified_rfcomm_channel_after_child_exit(){
        let output="Service RecHandle: 0x10011\nService Class ID List:\n UUID 128: 0000fe35-0000-1000-8000-00805f9b34fb\nProtocol Descriptor List:\n \"RFCOMM\" (0x0003)\n Channel: 12\n";
        let mut command=Command::new("/bin/sh");command.args(["-c","printf '%s' \"$1\"","sdp-fixture",output]);
        let mut query=SdpQuery::spawn(command,"private-peer".into(),Duration::from_secs(5)).unwrap();let until=Instant::now()+Duration::from_secs(3);
        loop{if let Some(channel)=query.poll().unwrap(){assert_eq!(channel,12);break;}assert!(Instant::now()<until);std::thread::sleep(Duration::from_millis(2));}
    }
    #[test]fn sdp_query_bounds_child_output(){
        let mut command=Command::new("/bin/sh");command.args(["-c","head -c 70000 /dev/zero"]);
        let mut query=SdpQuery::spawn(command,"private-peer".into(),Duration::from_secs(5)).unwrap();let until=Instant::now()+Duration::from_secs(3);
        loop{match query.poll(){Err(error)=>{assert_eq!(error,"SDP output exceeds limit");break;},Ok(_)=>{assert!(Instant::now()<until);std::thread::sleep(Duration::from_millis(2));}}}
    }
}
fn command(program:&str,args:&[&str])->Result<Vec<u8>>{let mut child=Command::new(program).args(args).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn().map_err(|_|"cannot start network diagnostic")?;let deadline=Instant::now()+Duration::from_secs(3);
    loop{if child.try_wait().map_err(|_|"cannot inspect network diagnostic")?.is_some(){let result=child.wait_with_output().map_err(|_|"cannot read network diagnostic")?;if !result.status.success()||result.stdout.len()>262144{return Err("network diagnostic failed".into());}return Ok(result.stdout);}if Instant::now()>=deadline{let _=child.kill();let _=child.wait();return Err("network diagnostic timeout".into());}std::thread::sleep(Duration::from_millis(10));}}
fn mgmt(index:u16,opcode:u16,payload:&[u8],timeout:Duration)->Result<Vec<u8>>{
    #[repr(C)]struct Address{family:u16,dev:u16,channel:u16}
    let raw=unsafe{libc::socket(31,libc::SOCK_RAW|libc::SOCK_CLOEXEC,1)};if raw<0{return Err("cannot open Bluetooth management socket".into());}let fd=unsafe{OwnedFd::from_raw_fd(raw)};
    let address=Address{family:31,dev:0xffff,channel:3};if unsafe{libc::bind(raw,&address as *const _ as *const libc::sockaddr,mem::size_of_val(&address) as libc::socklen_t)}!=0{return Err("cannot bind Bluetooth management socket".into());}
    let mut data=opcode.to_le_bytes().to_vec();data.extend(index.to_le_bytes());data.extend((payload.len() as u16).to_le_bytes());data.extend(payload);
    if unsafe{libc::send(raw,data.as_ptr() as *const c_void,data.len(),0)}!=data.len() as isize{return Err("Bluetooth management write failed".into());}
    let deadline=Instant::now()+timeout;loop{let left=deadline.saturating_duration_since(Instant::now());if left.is_zero(){return Err("Bluetooth management timeout".into());}let mut p=libc::pollfd{fd:fd.as_raw_fd(),events:libc::POLLIN,revents:0};if unsafe{libc::poll(&mut p,1,left.as_millis().min(i32::MAX as u128) as i32)}<=0{continue;}let mut buf=[0;4096];let n=unsafe{libc::recv(raw,buf.as_mut_ptr() as *mut c_void,buf.len(),0)};if n<9{continue;}let n=n as usize;let event=u16::from_le_bytes([buf[0],buf[1]]);if u16::from_le_bytes([buf[2],buf[3]])!=index||u16::from_le_bytes([buf[4],buf[5]]) as usize+6!=n||!matches!(event,1|2)||u16::from_le_bytes([buf[6],buf[7]])!=opcode{continue;}if buf[8]!=0{return Err("Bluetooth management command rejected".into());}if event==1{return Ok(buf[9..n].to_vec());}}
}

pub fn run(fd:i32)->Result<()>{
    let mut ipc=Ipc::new(fd)?;unsafe{libc::signal(libc::SIGTERM,libc::SIG_IGN);}
    let until=Instant::now()+Duration::from_secs(15);let config=loop{if let Some(v)=ipc.receive()?{break v;}if Instant::now()>until{return Err("missing private radio configuration".into());}std::thread::sleep(Duration::from_millis(10));};
    let c:Config=serde_json::from_value(config.clone()).map_err(|_|"invalid radio configuration")?;validate(&c)?;
    let state=State{selection:Selection::new(&c)?,payload:beacon(&c.model,c.sequence)?,power:c.tx_power,instance:0,stopped:false,closing:false,slots:BTreeSet::new(),origin:Instant::now(),wake_peer:c.peer.as_ref().or(c.reconnect_peer.as_ref()).map(|p|format!("{}/dev_{}",c.adapter,p.to_ascii_uppercase().replace(':',"_")))};
    let bus=Bus::open()?;let mut radio=Radio{bus,state,ipc,c,device:None,connection:None,previous:None,offer:None,agent:false,profile:false,business:false,advertisement:false,restore_connectable:false,restore_bondable:false,activated:false,startup_cancelled:false,startup_close_id:None,reconnect_at:Instant::now(),reconnect_attempts:0,projection_active:false,reconnect_allowed:false,business_connect:None,sdp_query:None,control_connect:None};
    let result=(||{
        let address=radio.prepare()?;radio.ipc.send(&json!({"id":config.get("id"),"ok":true,"ready":true,"address":address,"offer":radio.offer}),None)?;
        loop{
            if let Some(v)=radio.ipc.receive()?{let op=v["op"].as_str().ok_or("missing radio operation")?;
                let reply:Result<Value>=match op{
                    "activate"=>radio.activate().map(|_|json!({"active":true})),
                    "release"=>{let stream=v["stream"].as_str().ok_or("missing stream")?;let device=v["device"].as_str().ok_or("missing device")?;radio.state.slots.remove(&(stream.into(),device.into()));Ok(json!({}))},
                    "open-business"=>{let port=v["port"].as_u64().and_then(|v|u16::try_from(v).ok()).ok_or("invalid business port")?;radio.open_business(port).map(|_|json!({"pending":true}))},
                    "projection"=>{radio.projection_active=v["active"].as_bool().ok_or("projection active flag required")?;if !radio.projection_active{radio.reconnect_at=Instant::now();radio.reconnect_attempts=0;}Ok(json!({}))},
                    "status"=>Ok(json!({"active":radio.activated,"streams":radio.state.slots.len()})),
                    "close"=>{radio.cleanup();let _=radio.ipc.send(&json!({"id":v.get("id"),"ok":true,"closed":true}),None);break;},
                    _=>Err("unknown radio operation".into()),
                };
                match reply{Ok(mut value)=>{value["ok"]=true.into();value["id"]=v.get("id").cloned().unwrap_or(Value::Null);radio.ipc.send(&value,None)?;},Err(error)=>{radio.ipc.send(&json!({"id":v.get("id"),"ok":false,"error":error}),None)?;if op=="activate"{return Err("radio activation failed".into());}}}
            }
            radio.bus.poll(&mut radio.state,&mut radio.ipc)?;radio.reconnect()?;radio.poll_control()?;radio.poll_business()?;if radio.state.stopped{let _=radio.ipc.send(&json!({"event":"stopped"}),None);break;}
            let mut busfd=0;unsafe{(radio.bus.api.get_fd)(radio.bus.connection,&mut busfd);}
            let mut fds=[libc::pollfd{fd:radio.ipc.fd.as_raw_fd(),events:libc::POLLIN,revents:0},libc::pollfd{fd:busfd,events:libc::POLLIN,revents:0}];unsafe{libc::poll(fds.as_mut_ptr(),2,50);}
        }Ok(())
    })();radio.cleanup();
    if radio.startup_cancelled{
        // Acknowledge only after temporary networking has been removed and
        // the previous connection restored. EOF has no request to acknowledge.
        if let Some(id)=radio.startup_close_id.take(){let _=radio.ipc.send(&json!({"id":id,"ok":true,"closed":true}),None);}
        Ok(())
    }else{result}
}
}
pub fn run(fd:i32)->Result<()>{#[cfg(unix)]{linux::run(fd)}#[cfg(not(unix))]{let _=fd;Err("radio worker requires Linux/Unix".into())}}

#[cfg(test)]mod tests{use super::*;
    fn sdp_record(uuid:&str,protocol:&str)->String{format!("Service RecHandle: 0x10011\nService Class ID List:\n UUID 128: {uuid}\nProtocol Descriptor List:\n{protocol}\n")}
    #[test]fn sdp_selects_rfcomm_record_after_same_uuid_att_record(){
        let att=sdp_record(FE35," \"L2CAP\" (0x0100)\n PSM: 31\n \"ATT\" (0x0007)");
        let rfcomm=sdp_record(FE35," \"L2CAP\" (0x0100)\n \"RFCOMM\" (0x0003)\n Channel: 6");
        assert_eq!(rfcomm_channel(format!("{att}{rfcomm}").as_bytes()).unwrap(),6);
        assert_eq!(rfcomm_channel(sdp_record(FE35," \"RFCOMM\" (0x0003)\n Channel: 12").as_bytes()).unwrap(),12);
    }
    #[test]fn sdp_rejects_invalid_absent_and_ambiguous_rfcomm_channels(){
        for value in ["0","31","-1","six"]{assert!(rfcomm_channel(sdp_record(FE35,&format!(" \"RFCOMM\" (0x0003)\n Channel: {value}")).as_bytes()).is_err());}
        let one=sdp_record(FE35," \"RFCOMM\" (0x0003)\n Channel: 6");assert!(rfcomm_channel(format!("{one}{one}").as_bytes()).is_err());
        assert!(rfcomm_channel(sdp_record(FE36," \"RFCOMM\" (0x0003)\n Channel: 6").as_bytes()).is_err());
        assert!(rfcomm_channel(sdp_record(FE35," \"ATT\" (0x0007)\n Channel: 6").as_bytes()).is_err());assert!(rfcomm_channel(&vec![b'A';65537]).is_err());
    }
    #[test]fn hotspot_requires_target_interface_ipv4_and_prefix(){
        let mut addresses=json!([{"ifname":"other0","addr_info":[{"family":"inet","local":"192.168.49.1","prefixlen":24}]},{"ifname":"wlan0","addr_info":[]}]);
        assert!(!hotspot_ipv4_ready(&addresses,"wlan0"));
        addresses[1]["addr_info"]=json!([{"family":"inet","local":"192.168.49.1","prefixlen":16}]);assert!(!hotspot_ipv4_ready(&addresses,"wlan0"));
        addresses[1]["addr_info"][0]["prefixlen"]=24.into();assert!(hotspot_ipv4_ready(&addresses,"wlan0"));
        addresses[1]["addr_info"][0]["family"]="inet6".into();assert!(!hotspot_ipv4_ready(&addresses,"wlan0"));
    }
    #[test]fn reconnect_hint_does_not_select_or_steal_a_pairing_window(){
        let c:Config=serde_json::from_value(json!({"model":"00040A00","network":false,"manage_controller":false,"pair_seconds":120,"reconnect_peer":"02:00:00:00:00:01"})).unwrap();validate(&c).unwrap();
        let mut s=Selection::new(&c).unwrap();s.deadline=Some(120000);assert!(s.selected.is_none());
        let old="/org/bluez/hci0/dev_02_00_00_00_00_01";let new="/org/bluez/hci0/dev_02_00_00_00_00_02";
        assert!(s.allows(old,false,0));assert!(s.selected.is_none());assert!(s.allows(new,true,100));assert!(!s.allows(old,true,101));assert!(s.allows(new,true,102));
    }
    #[test]fn selection_is_sticky_and_agent_cannot_claim(){let c:Config=serde_json::from_value(json!({"model":"00040A00","network":false,"manage_controller":false,"pair_seconds":10,"exclude_peers":["02:00:00:00:00:01"]})).unwrap();validate(&c).unwrap();let mut s=Selection::new(&c).unwrap();s.deadline=Some(10000);
        assert!(!s.allows("/org/bluez/hci0/dev_02_00_00_00_00_01",true,0));assert!(s.allows("/org/bluez/hci0/dev_02_00_00_00_00_02",false,0));assert!(s.selected.is_none());assert!(s.allows("/org/bluez/hci0/dev_02_00_00_00_00_03",true,0));assert!(!s.allows("/org/bluez/hci0/dev_02_00_00_00_00_02",true,0));assert!(s.allows("/org/bluez/hci0/dev_02_00_00_00_00_03",false,20000));}
    #[test]fn rejects_management_interface_and_bad_addresses(){for value in ["02:00:00:00:00: 1","02:00:00:00:00:0g","02:00:00:00:00:000"]{assert!(mac(value).is_err());}let c:Config=serde_json::from_value(json!({"model":"00040A00","interface":"end0","peer":"02:00:00:00:00:01"})).unwrap();assert!(validate(&c).is_err());assert_eq!(beacon("00040A00",7).unwrap(),vec![1,1,1,3,0,4,10,4,0,16,7]);}
}
