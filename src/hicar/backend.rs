//! Production HiCar owner: only bounded control/state crosses private worker IPC.
//! RFCOMM authentication transport EOF does not revoke a successful projection.
use super::Result;

#[cfg(unix)]
mod unix {
use super::super::{crypto::{Crypto,wipe},hex,unhex,json as strict,wire::{Decoder,Format,Frame}};
use super::Result;
use serde_json::{Value,json};
use std::{collections::{BTreeMap,VecDeque},io::{Read,Write,ErrorKind},net::{Ipv4Addr,TcpListener,TcpStream},
    os::{fd::{OwnedFd,AsRawFd,FromRawFd},unix::{net::UnixStream,process::CommandExt}},
    path::PathBuf,process::{Child,Command,Stdio},sync::atomic::{AtomicBool,Ordering},time::{Duration,Instant}};
const IPC:usize=256*1024;
const QUEUE:usize=256*1024;
static STOP:AtomicBool=AtomicBool::new(false);
extern "C" fn stop(_:i32){STOP.store(true,Ordering::Relaxed);}
fn event(name:&str,epoch:u64){println!("{}",json!({"event":name,"session_epoch":epoch}));}
fn now_us()->u64{let mut t=libc::timespec{tv_sec:0,tv_nsec:0};unsafe{libc::clock_gettime(libc::CLOCK_MONOTONIC,&mut t);}t.tv_sec as u64*1_000_000+t.tv_nsec as u64/1000}
fn num(v:&Value,k:&str)->Result<u64>{v[k].as_u64().ok_or_else(||format!("missing private field {k}"))}
fn text<'a>(v:&'a Value,k:&str)->Result<&'a str>{v[k].as_str().ok_or_else(||format!("missing private field {k}"))}
fn wipe_field(v:&mut Value,k:&str){if let Some(Value::String(s))=v.get_mut(k){unsafe{wipe(s.as_bytes_mut());}}}
/// Each DMSDP service owns its lifetime. A normal speaker/microphone teardown
/// must not release the still-active modem speaker or microphone.
#[derive(Default)]
struct AudioServices{speakers:BTreeMap<String,bool>,microphones:BTreeMap<String,Value>,role:u8}
impl AudioServices{
    fn microphone(&self)->Option<(&str,&Value)>{self.microphones.get_key_value("modemMic").or_else(||self.microphones.get_key_value("mic1")).map(|(n,v)|(n.as_str(),v))}
    fn apply(&mut self,e:&Value)->Vec<Value>{
        let service=e["service"].as_str().unwrap_or("speaker1");
        let old_mic=self.microphone().map(|(n,v)|(n.to_owned(),v.clone()));
        let was_ready=!self.speakers.is_empty();let old_role=self.role;
        let setup=e["audio_setup_sent"]==true;
        if e["microphone_ready"]==true{self.microphones.insert(service.into(),e.clone());}
        if e["microphone_stopped"]==true{self.microphones.remove(service);}
        if setup||e["audio_stopped"]==true{self.speakers.remove(service);}
        if e["audio_ready"]==true{self.speakers.insert(service.into(),e["modem"]==true);}
        let new_mic=self.microphone().map(|(n,v)|(n.to_owned(),v.clone()));
        let ready=!self.speakers.is_empty();
        self.role=if self.microphones.contains_key("modemMic")||self.speakers.values().any(|m|*m){3}else{0};
        let mut commands=vec![];
        if e["audio_ready"]==true&&e["port"].as_u64().is_some(){commands.push(json!({"op":"audio-service","service":service,"active":true,"port":e["port"]}));}
        if e["audio_stopped"]==true&&was_ready{commands.push(json!({"op":"audio-service","service":service,"active":false}));}
        if old_mic!=new_mic{
            if let Some((name,_))=old_mic{commands.push(json!({"op":"microphone-stop","service":name}));}
            if let Some((name,v))=new_mic{commands.push(json!({"op":"microphone-start","service":name,"port":v["port"],"session":v["session"]}));}
        }
        if setup&&!ready{commands.push(json!({"op":"audio-begin"}));}
        if old_role!=self.role{commands.push(json!({"op":"audio-role","role":self.role}));}
        // Changing the role clears decoder state; re-arm the remaining speaker.
        if ready&&(!was_ready||old_role!=self.role){commands.push(json!({"op":"audio-ready"}));}
        else if was_ready&&!ready&&!setup{commands.push(json!({"op":"audio-stop"}));}
        commands
    }
}
#[cfg(test)]mod audio_service_tests{
    use super::*;
    fn ready(name:&str,modem:bool)->Value{json!({"audio_ready":true,"service":name,"modem":modem})}
    fn mic(name:&str,port:u16)->Value{json!({"microphone_ready":true,"service":name,"modem":name=="modemMic","port":port,"session":7})}
    #[test]fn a_remaining_modem_owner_keeps_call_role_and_playback(){
        let mut s=AudioServices::default();s.apply(&ready("speaker1",false));s.apply(&ready("modemSpeaker",true));
        s.apply(&mic("modemMic",42000));
        let commands=s.apply(&json!({"microphone_stopped":true,"service":"modemMic","modem":true}));
        assert_eq!(s.role,3);assert_eq!(commands,vec![json!({"op":"microphone-stop","service":"modemMic"})]);
        assert_eq!(s.apply(&json!({"audio_stopped":true,"service":"speaker1"}))[0]["op"],"audio-service");
        assert_eq!(s.role,3);assert!(!s.speakers.is_empty());
        let commands=s.apply(&json!({"audio_stopped":true,"service":"modemSpeaker","modem":true}));
        assert!(commands.contains(&json!({"op":"audio-role","role":0})));
        assert!(commands.contains(&json!({"op":"audio-stop"})));
    }
    #[test]fn microphone_priority_restores_speech_after_call_and_ignores_stale_stop(){
        let mut s=AudioServices::default();s.apply(&mic("mic1",41000));
        let commands=s.apply(&mic("modemMic",42000));
        assert_eq!(commands[0],json!({"op":"microphone-stop","service":"mic1"}));
        assert_eq!(commands[1]["service"],"modemMic");
        assert!(s.apply(&mic("mic1",43000)).is_empty());
        let commands=s.apply(&json!({"microphone_stopped":true,"service":"modemMic","modem":true}));
        assert_eq!(commands[0],json!({"op":"microphone-stop","service":"modemMic"}));
        assert_eq!(commands[1]["service"],"mic1");assert_eq!(commands[1]["port"],43000);
        assert!(s.apply(&json!({"microphone_stopped":true,"service":"modemMic","modem":true})).is_empty());
    }
    #[test]fn another_speaker_setup_and_normal_stop_do_not_flush_call_decoder(){
        let mut s=AudioServices::default();s.apply(&ready("modemSpeaker",true));
        assert!(s.apply(&json!({"audio_setup_sent":true})).is_empty());
        assert!(s.apply(&ready("speaker1",false)).is_empty());assert_eq!(s.role,3);
        assert_eq!(s.apply(&json!({"audio_stopped":true}))[0]["op"],"audio-service");
        assert_eq!(s.apply(&json!({"audio_stopped":true,"service":"modemSpeaker","modem":true})).len(),3);
    }
}
fn mac(s:&str)->Result<String>{let p:Vec<_>=s.split(':').collect();if p.len()!=6||p.iter().any(|s|s.len()!=2||!s.bytes().all(|b|b.is_ascii_hexdigit())){return Err("invalid peer address".into());}Ok(s.to_ascii_uppercase())}
struct Config{model:String,identity:PathBuf,library:PathBuf,store:PathBuf,interface:String,live:PathBuf,audio_binary:PathBuf,
    adapter:String,peer:Option<String>,reconnect_peer:Option<String>,excluded:Vec<String>,pair:bool,pair_seconds:u64,sequence:u8,duration:u64,power:i16,channel:u16,
    test:bool,fds:[Option<i32>;3],test_ip:Option<Ipv4Addr>,test_port:Option<u16>}
impl Config{
    fn parse(args:&[String])->Result<Self>{
        let mut c=Self{model:"00040A00".into(),identity:"/var/lib/hellocar/identity.json".into(),
            library:std::env::var_os("HELLOCAR_AUTH_LIBRARY").map(PathBuf::from).unwrap_or_else(||"/usr/local/lib/hellocar/libhellocar_hichain.so".into()),store:"/var/lib/hellocar/keys".into(),
            interface:String::new(),live:"/run/hellocar/media.sock".into(),audio_binary:std::env::var_os("HELLOCAR_AUDIO_BINARY").map(PathBuf::from).unwrap_or_else(||"/usr/bin/ffmpeg".into()),adapter:"/org/bluez/hci0".into(),
            peer:None,reconnect_peer:None,excluded:vec![],pair:false,pair_seconds:120,sequence:0,duration:0,power:11,channel:23,test:false,fds:[None;3],test_ip:None,test_port:None};
        let mut i=0;while i<args.len(){let name=args[i].as_str();i+=1;
            if matches!(name,"--pair"|"--test-mode"|"--managed"|"--allow-incoming"|"--reply-control"|"--reply-identity"|"--dmsdp-options"|"--audio"){
                if name=="--pair"{c.pair=true;if args.get(i).is_some_and(|v|!v.starts_with("--")){c.pair_seconds=args[i].parse().map_err(|_|"invalid pairing duration")?;i+=1;}}
                if name=="--test-mode"{c.test=true;}continue;}
            let value=args.get(i).ok_or("missing HiCar option value")?;i+=1;
            match name{
                "--model"=>c.model=value.to_ascii_uppercase(),"--identity"=>c.identity=value.into(),"--auth-library"=>c.library=value.into(),
                "--auth-store"=>c.store=value.into(),"--network-interface"=>c.interface=value.clone(),"--live-socket"=>c.live=value.into(),
                "--audio-binary"=>c.audio_binary=value.into(),"--adapter"=>c.adapter=value.clone(),"--peer"=>c.peer=Some(mac(value)?),
                "--reconnect-peer"=>c.reconnect_peer=Some(mac(value)?),
                "--exclude-peer"=>c.excluded.push(mac(value)?),"--sequence"=>c.sequence=value.parse().map_err(|_|"invalid discovery sequence")?,
                "--duration"=>c.duration=value.parse().map_err(|_|"invalid duration")?,"--pair-seconds"=>c.pair_seconds=value.parse().map_err(|_|"invalid pairing duration")?,
                "--tx-power"=>c.power=value.parse().map_err(|_|"invalid transmit power")?,"--channel"=>c.channel=value.parse().map_err(|_|"invalid RFCOMM channel")?,
                "--rust-session-binary"|"--rust-media-binary"=>{},
                "--test-radio-fd"|"--test-session-fd"|"--test-media-fd"=>{let n=if name=="--test-radio-fd"{0}else if name=="--test-session-fd"{1}else{2};c.fds[n]=Some(value.parse().map_err(|_|"invalid test descriptor")?);},
                "--test-listen-ip"=>c.test_ip=Some(value.parse().map_err(|_|"invalid test address")?),
                "--test-base-port"=>c.test_port=Some(value.parse().map_err(|_|"invalid test port")?),
                _=>return Err("unknown HiCar backend option".into()),
            }
        }
        if c.model.len()!=8||!c.model.bytes().all(|v|v.is_ascii_hexdigit())||c.excluded.len()>8||!(1..=29).contains(&c.channel)
            ||!(-127..=20).contains(&c.power)||!(5..=120).contains(&c.pair_seconds)||c.duration>86400{return Err("invalid HiCar backend parameters".into());}
        if c.peer.is_none()&&!c.pair{return Err("selected peer or explicit pairing window required".into());}
        if c.peer.as_ref().is_some_and(|p|c.excluded.contains(p)){return Err("selected peer is excluded".into());}
        if c.test{
            if c.fds.iter().any(Option::is_none)||c.test_ip!=Some(Ipv4Addr::LOCALHOST)||!c.test_port.is_some_and(|p|(1024..=65532).contains(&p)){return Err("mock backend requires three private sockets and loopback listeners".into());}
            let mut f:Vec<_>=c.fds.iter().flatten().copied().collect();f.sort();f.dedup();if f.len()!=3{return Err("mock descriptors must be distinct".into());}
        }else if c.fds.iter().any(Option::is_some)||c.test_ip.is_some()||c.test_port.is_some(){return Err("private mock descriptors require explicit test mode".into());}
        if !c.test&&(c.interface.is_empty()||c.interface=="end0"||c.interface.len()>15||!c.interface.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b))){return Err("wireless interface required".into());}
        for path in [&c.identity,&c.library,&c.store,&c.live,&c.audio_binary]{if !path.is_absolute()||path.as_os_str().len()>4096{return Err("absolute bounded backend paths required".into());}}
        Ok(c)
    }
}
fn validate_fd(fd:i32,kind:i32)->Result<()>{
    if fd<3{return Err("private descriptor must not be stdio".into());}let mut actual=0;let mut size=std::mem::size_of_val(&actual) as libc::socklen_t;
    if unsafe{libc::getsockopt(fd,libc::SOL_SOCKET,libc::SO_TYPE,&mut actual as *mut _ as *mut libc::c_void,&mut size)}!=0||actual!=kind{return Err("private descriptor socket type mismatch".into());}
    let mut peer:libc::sockaddr_un=unsafe{std::mem::zeroed()};let mut n=std::mem::size_of_val(&peer) as libc::socklen_t;
    if unsafe{libc::getpeername(fd,&mut peer as *mut _ as *mut libc::sockaddr,&mut n)}!=0||peer.sun_family!=libc::AF_UNIX as u16{return Err("connected private Unix descriptor required".into());}
    #[cfg(target_os="linux")]{let mut cred:libc::ucred=unsafe{std::mem::zeroed()};let mut n=std::mem::size_of_val(&cred) as libc::socklen_t;
        if unsafe{libc::getsockopt(fd,libc::SOL_SOCKET,libc::SO_PEERCRED,&mut cred as *mut _ as *mut libc::c_void,&mut n)}!=0||cred.uid!=unsafe{libc::geteuid()}{return Err("private worker uid mismatch".into());}}
    // Inherited mock descriptors must not leak to any later helper exec.
    if unsafe{libc::fcntl(fd,libc::F_SETFD,libc::FD_CLOEXEC)}<0{return Err("private descriptor ownership failed".into());}Ok(())
}
fn spawn(name:&str,kind:i32)->Result<(OwnedFd,Child)>{
    let mut pair=[-1;2];if unsafe{libc::socketpair(libc::AF_UNIX,kind|libc::SOCK_CLOEXEC,0,pair.as_mut_ptr())}!=0{return Err("cannot allocate worker channel".into());}
    let parent=unsafe{OwnedFd::from_raw_fd(pair[0])};let child=unsafe{OwnedFd::from_raw_fd(pair[1])};let fd=child.as_raw_fd();
    let mut command=Command::new(std::env::current_exe().map_err(|_|"cannot locate backend executable")?);command.args([name,&fd.to_string()]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    unsafe{command.pre_exec(move||{if libc::fcntl(fd,libc::F_SETFD,0)<0{return Err(std::io::Error::last_os_error());}Ok(())});}
    let process=command.spawn().map_err(|_|"cannot start private HiCar worker")?;drop(child);Ok((parent,process))
}
fn finish(child:&mut Option<Child>,timeout:Duration){if let Some(mut child)=child.take(){let end=Instant::now()+timeout;loop{if child.try_wait().ok().flatten().is_some(){return;}if Instant::now()>=end{let _=child.kill();let _=child.wait();return;}std::thread::sleep(Duration::from_millis(5));}}}
struct Rpc{socket:UnixStream,child:Option<Child>,limit:usize}
impl Rpc{
    fn new(name:&str,inherited:Option<i32>,limit:usize)->Result<Self>{let (fd,child)=if let Some(fd)=inherited{validate_fd(fd,libc::SOCK_STREAM)?;(unsafe{OwnedFd::from_raw_fd(fd)},None)}else{let (fd,child)=spawn(name,libc::SOCK_STREAM)?;(fd,Some(child))};
        let socket=UnixStream::from(fd);socket.set_read_timeout(Some(Duration::from_secs(2))).map_err(|_|"worker read timeout unavailable")?;socket.set_write_timeout(Some(Duration::from_secs(2))).map_err(|_|"worker write timeout unavailable")?;Ok(Self{socket,child,limit})}
    fn call(&mut self,v:&Value)->Result<Value>{
        self.socket.set_read_timeout(Some(Duration::from_secs(if v["op"]=="set-video"{6}else{2}))).map_err(|_|"worker deadline unavailable")?;
        let mut data=serde_json::to_vec(v).map_err(|_|"private request serialization failed")?;if data.is_empty()||data.len()>self.limit{return Err("private request exceeds limit".into());}
        let sent=self.socket.write_all(&(data.len() as u32).to_be_bytes()).and_then(|_|self.socket.write_all(&data));wipe(&mut data);sent.map_err(|_|"private worker send failed")?;
        let mut length=[0;4];self.socket.read_exact(&mut length).map_err(|_|"private worker reply unavailable")?;let n=u32::from_be_bytes(length) as usize;if n==0||n>self.limit{return Err("private response exceeds limit".into());}
        let mut data=vec![0;n];self.socket.read_exact(&mut data).map_err(|_|"private worker reply truncated")?;let result:Result<Value>=serde_json::from_slice(&data).map_err(|_|"invalid private response".into());wipe(&mut data);let v=result?;if v["ok"]!=true{return Err("private worker rejected operation".into());}Ok(v)}
    fn close(&mut self){let _=self.call(&json!({"op":"close"}));let _=self.socket.shutdown(std::net::Shutdown::Both);finish(&mut self.child,Duration::from_millis(250));}
}
impl Drop for Rpc{fn drop(&mut self){let _=self.socket.shutdown(std::net::Shutdown::Both);finish(&mut self.child,Duration::from_millis(250));}}
struct Packet{value:Value,fd:Option<OwnedFd>}
struct Radio{fd:OwnedFd,child:Option<Child>,next:u64,pending:VecDeque<Packet>,closed:bool}
impl Radio{
    fn new(inherited:Option<i32>)->Result<Self>{let (fd,child)=if let Some(fd)=inherited{validate_fd(fd,libc::SOCK_SEQPACKET)?;(unsafe{OwnedFd::from_raw_fd(fd)},None)}else{let (fd,child)=spawn("radio-worker",libc::SOCK_SEQPACKET)?;(fd,Some(child))};Ok(Self{fd,child,next:0,pending:VecDeque::new(),closed:false})}
    fn send(&self,v:&Value)->Result<()>{let mut data=serde_json::to_vec(v).map_err(|_|"radio request serialization failed")?;
        if data.len()>65536{return Err("radio request exceeds limit".into());}let n=unsafe{libc::send(self.fd.as_raw_fd(),data.as_ptr() as *const _,data.len(),libc::MSG_NOSIGNAL)};wipe(&mut data);if n!=data.len() as isize{return Err("radio request failed".into());}Ok(())}
    fn receive(&self)->Result<Option<Packet>>{
        let mut bytes=[0u8;65537];let mut control=[0usize;16];let mut iov=libc::iovec{iov_base:bytes.as_mut_ptr() as *mut _,iov_len:bytes.len()};let mut msg:libc::msghdr=unsafe{std::mem::zeroed()};msg.msg_iov=&mut iov;msg.msg_iovlen=1;msg.msg_control=control.as_mut_ptr() as *mut _;msg.msg_controllen=std::mem::size_of_val(&control);
        let n=unsafe{libc::recvmsg(self.fd.as_raw_fd(),&mut msg,libc::MSG_DONTWAIT|libc::MSG_CMSG_CLOEXEC)};if n<0{return if std::io::Error::last_os_error().kind()==ErrorKind::WouldBlock{Ok(None)}else{Err("private radio read failed".into())};}if n==0{return Err("private radio closed".into());}
        let mut fds=vec![];unsafe{let mut c=libc::CMSG_FIRSTHDR(&msg);while !c.is_null(){if (*c).cmsg_level==libc::SOL_SOCKET&&(*c).cmsg_type==libc::SCM_RIGHTS{let head=libc::CMSG_LEN(0) as usize;let count=(*c).cmsg_len.saturating_sub(head)/std::mem::size_of::<i32>();for i in 0..count{let fd=std::ptr::read_unaligned(libc::CMSG_DATA(c).add(i*4) as *const i32);if fd>=0{fds.push(OwnedFd::from_raw_fd(fd));}}}c=libc::CMSG_NXTHDR(&msg,c);}}
        if n as usize>65536||msg.msg_flags&(libc::MSG_TRUNC|libc::MSG_CTRUNC)!=0||fds.len()>1{return Err("invalid radio private packet".into());}
        let parsed=serde_json::from_slice(&bytes[..n as usize]).map_err(|_|"invalid radio private JSON".to_owned());wipe(&mut bytes[..n as usize]);Ok(Some(Packet{value:parsed?,fd:fds.pop()}))
    }
    fn call(&mut self,mut v:Value,timeout:Duration)->Result<Value>{self.next=self.next.checked_add(1).ok_or("radio request generation exhausted")?;v["id"]=self.next.into();self.send(&v)?;let until=Instant::now()+timeout;
        loop{if STOP.load(Ordering::Relaxed)&&!self.closed{return Err("radio preparation interrupted".into());}
            if let Some(packet)=self.receive()?{if packet.value["id"].as_u64()==Some(self.next){if packet.fd.is_some()||packet.value["ok"]!=true{return Err("radio operation rejected".into());}return Ok(packet.value);}if self.pending.len()>=8{return Err("radio event backlog exceeds limit".into());}self.pending.push_back(packet);}if Instant::now()>=until{return Err("radio operation timeout".into());}std::thread::sleep(Duration::from_millis(5));}}
    fn poll(&mut self)->Result<Option<Packet>>{if let Some(v)=self.pending.pop_front(){Ok(Some(v))}else{self.receive()}}
    fn close(&mut self){if !self.closed{self.closed=true;let _=self.call(json!({"op":"close"}),Duration::from_secs(7));finish(&mut self.child,Duration::from_millis(250));}}
}
impl Drop for Radio{fn drop(&mut self){self.close();}}
#[derive(Clone,Copy,PartialEq)]enum Kind{Nearby,Business,Data,Control,Sight}
struct Channel{fd:OwnedFd,kind:Kind,decoder:Decoder,json:strict::Stream,token:Option<u64>,device:Option<String>,radio_stream:Option<String>,
    output:VecDeque<(Vec<u8>,usize)>,queued:usize,created:Instant,last_valid:Instant,last_heartbeat:Instant,epoch:u64,closing:bool,negotiated:bool}
impl Channel{
    fn new(fd:OwnedFd,kind:Kind,epoch:u64)->Result<Self>{let flags=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_GETFL)};if flags<0||unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_SETFL,flags|libc::O_NONBLOCK)}<0{return Err("cannot configure backend transport".into());}
        Ok(Self{fd,kind,decoder:Decoder::new(if kind==Kind::Data{Format::Module}else{Format::Nearby}),json:strict::Stream::new(),token:None,device:None,radio_stream:None,output:VecDeque::new(),queued:0,created:Instant::now(),last_valid:Instant::now(),last_heartbeat:Instant::now()-Duration::from_secs(1),epoch,closing:false,negotiated:false})}
    fn enqueue(&mut self,data:Vec<u8>)->Result<()>{if data.is_empty(){return Ok(());}if self.output.len()>=64||self.queued+data.len()>QUEUE{return Err("backend transport backpressure".into());}self.queued+=data.len();self.output.push_back((data,0));Ok(())}
    fn flush(&mut self)->Result<()>{for _ in 0..16{let Some((data,offset))=self.output.front_mut()else{break;};let n=unsafe{libc::send(self.fd.as_raw_fd(),data[*offset..].as_ptr() as *const _,data.len()-*offset,libc::MSG_DONTWAIT|libc::MSG_NOSIGNAL)};
        if n<0{if std::io::Error::last_os_error().kind()==ErrorKind::WouldBlock{break;}return Err("backend transport write failed".into());}if n==0{return Err("backend transport write EOF".into());}*offset+=n as usize;self.queued-=n as usize;if *offset==data.len(){let (mut data,_)=self.output.pop_front().unwrap();wipe(&mut data);}else{break;}}Ok(())}
    fn read(&self)->Result<Option<Vec<u8>>>{let mut bytes=vec![0u8;4096];let n=unsafe{libc::recv(self.fd.as_raw_fd(),bytes.as_mut_ptr() as *mut _,bytes.len(),libc::MSG_DONTWAIT)};
        if n<0{return if std::io::Error::last_os_error().kind()==ErrorKind::WouldBlock{Ok(None)}else{Err("backend transport read failed".into())};}if n==0{return Err("backend transport EOF".into());}bytes.truncate(n as usize);Ok(Some(bytes))}
}
impl Drop for Channel{fn drop(&mut self){for (data,_)in &mut self.output{wipe(data);}unsafe{libc::shutdown(self.fd.as_raw_fd(),libc::SHUT_RDWR);}}}
fn pending(channel:&mut Channel,v:&Value)->Result<()>{if let Some(p)=v["pending"].as_array(){if p.len()>64{return Err("excess private pending records".into());}for data in p{channel.enqueue(unhex(data.as_str().ok_or("invalid private pending record")?)?)?;}}Ok(())}
fn connected(local:Ipv4Addr,peer:Ipv4Addr,port:u16)->Result<OwnedFd>{
    let raw=unsafe{libc::socket(libc::AF_INET,libc::SOCK_STREAM|libc::SOCK_CLOEXEC|libc::SOCK_NONBLOCK,0)};if raw<0{return Err("cannot allocate HiSight control transport".into());}let fd=unsafe{OwnedFd::from_raw_fd(raw)};
    let addr=|ip:Ipv4Addr,p:u16|libc::sockaddr_in{sin_family:libc::AF_INET as u16,sin_port:p.to_be(),sin_addr:libc::in_addr{s_addr:u32::from_ne_bytes(ip.octets())},sin_zero:[0;8]};let own=addr(local,0);let target=addr(peer,port);
    if unsafe{libc::bind(raw,&own as *const _ as *const libc::sockaddr,std::mem::size_of_val(&own) as _)}!=0{return Err("cannot bind HiSight control source".into());}
    if unsafe{libc::connect(raw,&target as *const _ as *const libc::sockaddr,std::mem::size_of_val(&target) as _)}!=0{
        if std::io::Error::last_os_error().raw_os_error()!=Some(libc::EINPROGRESS){return Err("HiSight control refused".into());}let mut p=libc::pollfd{fd:raw,events:libc::POLLOUT,revents:0};if unsafe{libc::poll(&mut p,1,2000)}<=0{return Err("HiSight control timeout".into());}
        let mut error=0;let mut size=4;if unsafe{libc::getsockopt(raw,libc::SOL_SOCKET,libc::SO_ERROR,&mut error as *mut _ as *mut _,&mut size)}!=0||error!=0{return Err("HiSight control failed".into());}}
    Ok(fd)
}
fn listener(local:Ipv4Addr,port:u16)->Result<TcpListener>{
    let raw=unsafe{libc::socket(libc::AF_INET,libc::SOCK_STREAM|libc::SOCK_CLOEXEC|libc::SOCK_NONBLOCK,0)};
    if raw<0{return Err("cannot allocate HiCar listener".into());}let fd=unsafe{OwnedFd::from_raw_fd(raw)};let yes=1i32;
    let address=libc::sockaddr_in{sin_family:libc::AF_INET as u16,sin_port:port.to_be(),sin_addr:libc::in_addr{s_addr:u32::from_ne_bytes(local.octets())},sin_zero:[0;8]};
    if unsafe{libc::setsockopt(raw,libc::SOL_SOCKET,libc::SO_REUSEADDR,&yes as *const _ as *const _,std::mem::size_of_val(&yes) as _)}!=0
        ||unsafe{libc::bind(raw,&address as *const _ as *const _,std::mem::size_of_val(&address) as _)}!=0||unsafe{libc::listen(raw,4)}!=0{return Err("cannot bind HiCar listener".into());}
    Ok(TcpListener::from(fd))
}
struct Owner{config:Config,radio:Radio,worker:Rpc,media:Option<Rpc>,mock_media:Option<i32>,channels:Vec<Channel>,listeners:Vec<TcpListener>,
    offer:Value,address:String,own:String,local:Ipv4Addr,peer_ip:Ipv4Addr,base:u16,auth:Option<u64>,authenticated:bool,key:Vec<u8>,epoch:u64,
    audio_services:AudioServices,video_set:bool,clock_set:bool,last_stats:Instant,last_poll:Instant,closing:bool}
impl Owner{
    fn start(config:Config)->Result<Self>{
        // Validate every inherited mock endpoint before opening any real worker.
        if config.test{for (i,fd)in config.fds.iter().enumerate(){validate_fd(fd.unwrap(),if i==0{libc::SOCK_SEQPACKET}else{libc::SOCK_STREAM})?;}}
        let mut radio=Radio::new(config.fds[0])?;
        let prepared=radio.call(json!({"model":config.model,"sequence":config.sequence,"peer":config.peer,"reconnect_peer":config.reconnect_peer,"exclude_peers":config.excluded,
            "pair_seconds":if config.pair{config.pair_seconds}else{0},"channel":config.channel,"tx_power":config.power,"interface":config.interface,
            "adapter":config.adapter,"network":true,"manage_controller":true}),Duration::from_secs(25))?;
        let address=mac(text(&prepared,"address")?)?;let offer=prepared["offer"].clone();
        let local=text(&offer,"owner_ip")?.parse::<Ipv4Addr>().map_err(|_|"invalid offered local address")?;let peer_ip=text(&offer,"client_ip")?.parse::<Ipv4Addr>().map_err(|_|"invalid offered peer address")?;
        let base=num(&offer,"port")?.try_into().map_err(|_|"invalid offered TCP port")?;
        if config.test{if local!=Ipv4Addr::LOCALHOST||peer_ip!=Ipv4Addr::LOCALHOST||Some(base)!=config.test_port{return Err("mock radio must use selected loopback listeners".into());}}
        else{let _=super::super::session::Offer::parse(&offer)?;}
        let seed=format!("{}{}",config.model,address.replace(':',"")).to_ascii_uppercase();let crypto=Crypto::load()?;let own=hex(&crypto.sha256(seed.as_bytes())?).to_ascii_uppercase();
        let mut worker=Rpc::new("session-worker",config.fds[1],IPC)?;
        let ready=worker.call(&json!({"identity":config.identity,"model":config.model,"address":address,"library":config.library,"store":config.store,"offer":offer,"business_channel":config.channel+1}))?;
        if ready["ready"]!=true||ready["wire_identity_sha256"].as_str()!=Some(hex(&crypto.sha256(own.as_bytes())?).as_str()){return Err("private signing identity mismatch".into());}
        let mut listeners=vec![];for offset in 0..3{listeners.push(listener(local,base+offset)?);}
        radio.call(json!({"op":"activate"}),Duration::from_secs(15))?;
        event("ready",0);
        Ok(Self{mock_media:config.fds[2],config,radio,worker,media:None,channels:vec![],listeners,offer,address,own,local,peer_ip,base,
            auth:None,authenticated:false,key:vec![],epoch:0,audio_services:AudioServices::default(),video_set:false,clock_set:false,last_stats:Instant::now(),last_poll:Instant::now(),closing:false})
    }
    fn next_epoch(&mut self)->Result<()>{self.epoch=self.epoch.checked_add(1).ok_or("projection epoch exhausted")?;Ok(())}
    fn begin_media(&mut self)->Result<Value>{
        if self.media.is_some(){return Err("projection already active".into());}
        if self.config.test&&self.mock_media.is_none(){return Err("mock media descriptor already consumed".into());}
        let mut media=Rpc::new("media-worker",self.mock_media.take(),65536)?;let mut config=json!({"key":hex(&self.key),"local_ip":self.local,"peer_ip":self.peer_ip,"live_socket":self.config.live,"audio_binary":self.config.audio_binary});
        let ready=media.call(&config);wipe_field(&mut config,"key");let ready=ready?;if !self.config.test{self.radio.call(json!({"op":"projection","active":true}),Duration::from_secs(1))?;}self.media=Some(media);self.video_set=false;self.clock_set=false;self.audio_services=AudioServices::default();Ok(ready)
    }
    fn media_call(&mut self,v:Value)->Result<Value>{self.media.as_mut().ok_or("media worker unavailable")?.call(&v)}
    fn auth_close(&mut self){if let Some(generation)=self.auth.take(){let _=self.worker.call(&json!({"op":"auth-close","generation":generation}));}self.authenticated=false;wipe(&mut self.key);self.key.clear();}
    fn attach_radio(&mut self,packet:Packet)->Result<()>{
        let v=packet.value;match v["event"].as_str(){
            Some("rfcomm")=>{
                let stream=text(&v,"stream")?;let device=text(&v,"device")?.to_owned();let address=mac(text(&v,"address")?)?;
                if !matches!(stream,"control"|"business")||self.config.peer.as_ref().is_some_and(|p|p!=&address)||self.config.excluded.contains(&address){return Err("unselected RFCOMM descriptor".into());}
                let fd=packet.fd.ok_or("missing RFCOMM descriptor")?;
                if self.channels.len()>=8||self.channels.iter().any(|c|c.radio_stream.as_deref()==Some(stream)){let _=self.radio.call(json!({"op":"release","stream":stream,"device":device}),Duration::from_secs(1));return Ok(());}
                if self.config.peer.is_none(){self.config.peer=Some(address.clone());println!("{}",json!({"event":"target_selected","address":address,"session_epoch":self.epoch}));}
                let kind=if stream=="business"{Kind::Business}else{Kind::Nearby};
                if kind==Kind::Business{self.stop_projection();self.auth_close();self.next_epoch()?;self.auth=Some(num(&self.worker.call(&json!({"op":"auth-open"}))?,"generation")?);}
                let mut channel=Channel::new(fd,kind,self.epoch)?;channel.device=Some(device);channel.radio_stream=Some(stream.into());
                if kind==Kind::Business{channel.token=self.auth;}else{let opened=self.worker.call(&json!({"op":"open","business":true,"initiator":v["initiator"]==true}))?;channel.token=Some(num(&opened,"channel")?);if let Some(initial)=opened["initial"].as_str(){channel.enqueue(Frame{kind:0,flags:0,options:vec![],payload:unhex(initial)?}.encode(Format::Nearby)?)?;}}
                self.channels.push(channel);event("rfcomm_connected",self.epoch);
            },
            Some("request-disconnection")=>{let stream=v["stream"].as_str();let device=v["device"].as_str();for c in &mut self.channels{if c.radio_stream.as_deref()==stream&&c.device.as_deref()==device{c.closing=true;}}},
            Some("reconnect-result")=>event(if v["success"]==true{"bluetooth_reconnect_ready"}else{"bluetooth_reconnect_failed"},self.epoch),
            Some("stopped")=>return Err("radio registration ended".into()),
            // ACL disconnect also occurs during normal Wi-Fi handoff.
            Some("disconnected")=>{},_=>if packet.fd.is_some(){return Err("unexpected radio descriptor".into());},
        }Ok(())
    }
    fn accept(&mut self)->Result<()>{for i in 0..3{for _ in 0..4{
        let (stream,address)=match self.listeners[i].accept(){Ok(v)=>v,Err(e)if e.kind()==ErrorKind::WouldBlock=>break,Err(_)=>return Err("network accept failed".into())};
        let kind=[Kind::Nearby,Kind::Data,Kind::Control][i];
        if address.ip()!=std::net::IpAddr::V4(self.peer_ip)||!self.authenticated||self.channels.len()>=8||self.channels.iter().any(|c|c.kind==kind&&(kind!=Kind::Nearby||c.radio_stream.is_none())){continue;}
        if kind==Kind::Control{self.next_epoch()?;}
        let fd:OwnedFd=stream.into();let mut channel=Channel::new(fd,kind,self.epoch)?;
        let opened:Result<()>=(||{if kind==Kind::Nearby{channel.token=Some(num(&self.worker.call(&json!({"op":"open","business":false}))?,"channel")?);}
            if kind==Kind::Control{
                let ready=self.begin_media()?;let info=json!({"deviceId":self.own,"deviceName":"HelloCar","deviceType":4,"bluetoothMac":self.address,"btName":"HelloCar","localIp":self.local.to_string(),"remoteIp":self.peer_ip.to_string(),"port":0,"properties":{"2003":self.config.model,"5002":true,"5003":true,"5004":true,"5014":false}});
                let result=self.worker.call(&json!({"op":"dmsdp-open","generation":self.auth,"device_info":info,"audio":true}))?;channel.token=Some(num(&result,"session")?);channel.enqueue(unhex(text(&result,"initial")?)?)?;
                let ports=self.worker.call(&json!({"op":"dmsdp-ports","session":channel.token,"ports":ready["audio_ports"]}))?;pending(&mut channel,&ports)?;
            }Ok(())})();
        if opened.is_err(){if kind==Kind::Control{
            if let Some(token)=channel.token{let _=self.worker.call(&json!({"op":"dmsdp-close","session":token}));}
            self.stop_projection();
        }event("tcp_stream_error",self.epoch);continue;}
        self.channels.push(channel);event("tcp_connected",self.epoch);
    }}Ok(())}
    fn receive_nearby(&mut self,c:&mut Channel,bytes:&[u8])->Result<()>{for frame in c.decoder.feed(bytes)?{
        let result=self.worker.call(&json!({"op":"nearby","channel":c.token,"kind":frame.kind,"flags":frame.flags,"payload":hex(&frame.payload)}))?;
        if let Some(port)=result["business_endpoint"].as_u64(){self.radio.call(json!({"op":"open-business","port":port}),Duration::from_secs(1))?;}
        if let Some(reply)=result["reply"].as_str(){c.enqueue(Frame{kind:frame.kind,flags:0,options:vec![],payload:unhex(reply)?}.encode(Format::Nearby)?)?;}
        if let Some(commands)=result["pending"].as_array(){for command in commands{c.enqueue(Frame{kind:command[0].as_u64().ok_or("invalid resource command")?.try_into().map_err(|_|"invalid resource command")?,flags:0,options:vec![],payload:unhex(command[1].as_str().ok_or("invalid resource payload")?)?}.encode(Format::Nearby)?)?;}}
    }Ok(())}
    fn receive_business(&mut self,c:&mut Channel,bytes:&[u8])->Result<()>{for envelope in c.json.feed(bytes)?{
        let mut result=self.worker.call(&json!({"op":"auth","generation":c.token,"envelope":envelope.to_string()}))?;
        if let Some(reply)=result["reply"].as_str(){c.enqueue(unhex(reply)?)?;}
        if result["metadata"]["key_ready"]==true{let decoded=unhex(text(&result,"key")?)?;if !matches!(decoded.len(),16|32){return Err("invalid authenticated key size".into());}wipe(&mut self.key);self.key=decoded;self.authenticated=true;}
        wipe_field(&mut result,"key");
    }Ok(())}
    fn receive_control(&mut self,c:&mut Channel,bytes:&[u8])->Result<()>{let result=self.worker.call(&json!({"op":"dmsdp-receive","session":c.token,"data":hex(bytes),"now_us":now_us(),"capture":false}))?;
        if result["events"].as_array().is_some_and(|v|!v.is_empty()){c.last_valid=Instant::now();}
        pending(c,&result)?;let state=&result["state"];c.negotiated=state["negotiated"]==true;
        if let Some(events)=result["events"].as_array(){for e in events{
            if e["microphone_ready"]==true||e["microphone_stopped"]==true||e["audio_ready"]==true||e["audio_stopped"]==true{
                println!("{}",json!({"event":"hicar_audio_service","service":e["service"].as_str().filter(|n|matches!(*n,"speaker1"|"mic1"|"modemMic"|"modemSpeaker")).unwrap_or("speaker1"),"ready":e["microphone_ready"]==true||e["audio_ready"]==true,"stopped":e["microphone_stopped"]==true||e["audio_stopped"]==true}));
            }
            for command in self.audio_services.apply(e){self.media_call(command)?;}
        }}
        if !self.clock_set{if let Some(clock)=state["clock"].as_array(){self.media_call(json!({"op":"clock-start","port":clock[2]}))?;self.clock_set=true;}}
        if state["negotiated"]==true&&c.last_heartbeat.elapsed()>=Duration::from_secs(1){let heart=self.worker.call(&json!({"op":"dmsdp-heartbeat","session":c.token}))?;c.enqueue(unhex(text(&heart,"heartbeat")?)?)?;pending(c,&heart)?;c.last_heartbeat=Instant::now();}
        if let Some(port)=state["media_port"].as_u64(){if !self.channels.iter().any(|c|c.kind==Kind::Sight){
            let fd=connected(self.local,self.peer_ip,port.try_into().map_err(|_|"invalid HiSight port")?)?;let result=self.worker.call(&json!({"op":"hisight-open","generation":self.auth}))?;
            let mut sight=Channel::new(fd,Kind::Sight,self.epoch)?;sight.token=Some(num(&result,"session")?);sight.enqueue(unhex(text(&result,"initial")?)?)?;self.channels.push(sight);event("hisight_connected",self.epoch);
        }}Ok(())}
    fn receive_sight(&mut self,c:&mut Channel,bytes:&[u8])->Result<()>{let result=self.worker.call(&json!({"op":"hisight-receive","session":c.token,"data":hex(bytes),"capture":false}))?;pending(c,&result)?;
        let state=&result["state"];if state["peer_teardown"]==true{c.closing=true;}
        if !self.video_set{if let Some(port)=state["media_endpoint"].as_u64(){self.media_call(json!({"op":"set-video","media_port":port,"input_port":state["input_endpoint"]}))?;self.video_set=true;
            let play=self.worker.call(&json!({"op":"hisight-play","session":c.token}))?;pending(c,&play)?;
        }}Ok(())}
    fn handle(&mut self,c:&mut Channel,bytes:&[u8])->Result<()>{match c.kind{
        Kind::Nearby=>self.receive_nearby(c,bytes),Kind::Business=>self.receive_business(c,bytes),Kind::Control=>self.receive_control(c,bytes),Kind::Sight=>self.receive_sight(c,bytes),
        Kind::Data=>{for frame in c.decoder.feed(bytes)?{if frame.kind!=1||frame.payload!=vec![0;16]||c.token.unwrap_or(0)>=3{return Err("unsupported data-port negotiation".into());}c.token=Some(c.token.unwrap_or(0)+1);let mut payload=vec![0];payload.extend((self.base+2).to_be_bytes());payload.extend([0;13]);c.enqueue(Frame{kind:1,flags:0,options:vec![],payload}.encode(Format::Module)?)?;}Ok(())},
    }}
    fn release_channel(&mut self,c:&mut Channel,failed:bool){
        match c.kind{
            Kind::Nearby=>{let _=self.worker.call(&json!({"op":"close-channel","channel":c.token}));},
            Kind::Business=>{if failed||!self.authenticated{self.stop_projection();self.auth_close();}},
            Kind::Control|Kind::Sight=>{self.stop_projection();},Kind::Data=>{},
        }
        if let (Some(stream),Some(device))=(&c.radio_stream,&c.device){let _=self.radio.call(json!({"op":"release","stream":stream,"device":device}),Duration::from_secs(1));}
    }
    fn step_channels(&mut self)->Result<()>{
        let count=self.channels.len();
        for _ in 0..count{
            if self.channels.is_empty(){break;}let mut c=self.channels.remove(0);
            if c.epoch!=self.epoch&&(c.kind==Kind::Control||c.kind==Kind::Sight){continue;}
            let mut failed=false;let mut eof=false;
            if !c.closing{for _ in 0..8{match c.read(){Ok(Some(mut bytes))=>{let handled=self.handle(&mut c,&bytes);wipe(&mut bytes);if handled.is_err(){failed=true;break;}},Ok(None)=>break,Err(_)=>{eof=true;break;}}}}
            if c.kind==Kind::Control&&!failed&&!eof{
                if c.last_valid.elapsed()>=Duration::from_secs(8){failed=true;event("control_peer_timeout",c.epoch);}
                else if c.negotiated&&c.last_heartbeat.elapsed()>=Duration::from_secs(1){match self.worker.call(&json!({"op":"dmsdp-heartbeat","session":c.token})){Ok(v)=>{if let Some(h)=v["heartbeat"].as_str(){if c.enqueue(unhex(h)?).is_err(){failed=true;}}c.last_heartbeat=Instant::now();},Err(_)=>{failed=true;}}}
            }
            if matches!(c.kind,Kind::Nearby|Kind::Business|Kind::Data)&&!self.authenticated&&c.created.elapsed()>Duration::from_secs(30){failed=true;}
            if !failed&&c.flush().is_err(){eof=true;}
            if failed||eof||c.closing{if failed{event(if c.kind==Kind::Control{"control_parse_stopped"}else if c.kind==Kind::Sight{"hisight_parse_stopped"}else if c.kind==Kind::Business{"auth_parse_stopped"}else{"parse_stopped"},c.epoch);}
                if matches!(c.kind,Kind::Control|Kind::Sight){self.channels.push(c);self.stop_projection();self.channels.retain(|c|!c.closing);}else{self.release_channel(&mut c,failed);}}
            else{self.channels.push(c);}
        }
        Ok(())
    }
    fn stats(&mut self,force:bool)->Result<()>{if self.media.is_none()||!force&&self.last_poll.elapsed()<Duration::from_millis(250){return Ok(());}self.last_poll=Instant::now();
        let response=self.media_call(json!({"op":"status"}))?;let state=&response["state"];
        if force||self.last_stats.elapsed()>=Duration::from_secs(1){let mut out=state.clone();out["event"]="bridge_stats".into();out["session_epoch"]=self.epoch.into();println!("{out}");self.last_stats=Instant::now();}
        if self.video_set&&state["video_ended"]==true{self.stop_projection();}Ok(())}
    fn stop_projection(&mut self){
        if self.closing{return;}self.closing=true;
        // Flush RTSP TEARDOWN while its authenticated worker still exists.
        for c in &mut self.channels{if c.kind==Kind::Sight&&!c.closing{if let Ok(v)=self.worker.call(&json!({"op":"hisight-teardown","session":c.token})){if let Some(w)=v["teardown"].as_str(){if let Ok(w)=unhex(w){let _=c.enqueue(w);}}let _=pending(c,&v);}let until=Instant::now()+Duration::from_millis(150);while !c.output.is_empty()&&Instant::now()<until{let _=c.flush();std::thread::sleep(Duration::from_millis(2));}let _=self.worker.call(&json!({"op":"hisight-close","session":c.token}));c.closing=true;}}
        for c in &mut self.channels{if c.kind==Kind::Control&&!c.closing{if let Ok(v)=self.worker.call(&json!({"op":"dmsdp-stop-audio","session":c.token})){let _=pending(c,&v);let _=c.flush();}let _=self.worker.call(&json!({"op":"dmsdp-close","session":c.token}));c.closing=true;}}
        if let Some(mut media)=self.media.take(){media.close();if !self.config.test{let _=self.radio.call(json!({"op":"projection","active":false}),Duration::from_secs(1));}println!("{}",json!({"event":"bridge_stats","session_epoch":self.epoch,"active":false,"connected":false,"video_frames":0,"epoch_video_frames":0}));event("hisight_closed",self.epoch);}
        self.video_set=false;self.clock_set=false;self.audio_services=AudioServices::default();self.closing=false;
    }
    fn run(&mut self)->Result<()>{let started=Instant::now();loop{
        if STOP.load(Ordering::Relaxed)||self.config.duration!=0&&started.elapsed()>=Duration::from_secs(self.config.duration){return Ok(());}
        for _ in 0..8{let Some(packet)=self.radio.poll()?else{break;};self.attach_radio(packet)?;}
        self.accept()?;self.step_channels()?;self.stats(false)?;
        let mut fds=vec![libc::pollfd{fd:self.radio.fd.as_raw_fd(),events:libc::POLLIN,revents:0}];
        for l in &self.listeners{fds.push(libc::pollfd{fd:l.as_raw_fd(),events:libc::POLLIN,revents:0});}for c in &self.channels{fds.push(libc::pollfd{fd:c.fd.as_raw_fd(),events:libc::POLLIN|if c.output.is_empty(){0}else{libc::POLLOUT},revents:0});}unsafe{libc::poll(fds.as_mut_ptr(),fds.len() as libc::nfds_t,10);}
    }}
    fn shutdown(&mut self){self.stop_projection();self.channels.clear();self.auth_close();self.worker.close();self.radio.close();event("stopped",self.epoch);}
}
impl Drop for Owner{fn drop(&mut self){self.shutdown();}}
pub fn run(args:&[String])->Result<()>{let config=Config::parse(args)?;STOP.store(false,Ordering::Relaxed);unsafe{libc::signal(libc::SIGTERM,stop as *const () as libc::sighandler_t);libc::signal(libc::SIGINT,stop as *const () as libc::sighandler_t);}match Owner::start(config){Ok(mut owner)=>owner.run(),Err(_) if STOP.load(Ordering::Relaxed)=>Ok(()),Err(e)=>Err(e)}}
}
pub fn run(args:&[String])->Result<()>{#[cfg(unix)]{unix::run(args)}#[cfg(not(unix))]{let _=args;Err("HiCar backend requires Linux/Unix".into())}}
