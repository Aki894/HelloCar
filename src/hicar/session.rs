//! R2 connection state: Nearby/ResourceManager and authenticated business envelopes.
//! The temporary BlueZ adapter exchanges secrets only over an inherited Unix socket.
use super::{Result,wire::{self,Frame},json,hex,unhex};
use serde_json::{Value,json as value};
use std::collections::BTreeMap;

fn text<'a>(v:&'a Value,k:&str)->Result<&'a str>{v.get(k).and_then(Value::as_str).ok_or_else(||format!("missing {k}"))}
fn number(v:&Value,k:&str)->Result<u32>{v.get(k).and_then(Value::as_u64).and_then(|v|v.try_into().ok()).ok_or_else(||format!("invalid {k}"))}
fn uint(data:&[u8],p:&mut usize)->Result<u32>{wire::read_uint(data,p)?.ok_or("truncated resource integer".into())}
fn append(out:&mut Vec<u8>,tag:u32,data:&[u8])->Result<()>{out.extend(wire::tlv(tag,data)?);Ok(())}

pub struct Offer {ssid:String,bssid:String,password:String,owner:String,client:String,pub port:u32}
impl Offer {
    pub fn parse(v:&Value)->Result<Self>{
        let out=Self{ssid:text(v,"ssid")?.into(),bssid:text(v,"bssid")?.into(),password:text(v,"password")?.into(),
            owner:text(v,"owner_ip")?.into(),client:text(v,"client_ip")?.into(),port:number(v,"port")?};
        if !(1..=32).contains(&out.ssid.len())||!(8..=63).contains(&out.password.len())||!(1024..=65532).contains(&out.port)
            ||!valid_mac(&out.bssid)||number(v,"frequency")?!=5745{return Err("invalid network offer".into());}
        for s in [&out.ssid,&out.password]{if !s.is_ascii()||s.bytes().any(|b|matches!(b,0|b'\n'|b'\r'|b'#')){return Err("invalid network text".into());}}
        let owner=out.owner.parse::<std::net::Ipv4Addr>().map_err(|_|"invalid owner address")?;
        let client=out.client.parse::<std::net::Ipv4Addr>().map_err(|_|"invalid client address")?;
        if owner==client||owner.octets()[..3]!=[192,168,49]||client.octets()[..3]!=[192,168,49]{return Err("invalid private network".into());}Ok(out)
    }
    fn credentials(&self)->Vec<u8>{format!("{}##{}\n{}\n{}\n5745\n1##version:3##{}##2##hicarApIp:{}",self.client,self.ssid,self.bssid,self.password,self.port,self.owner).into_bytes()}
}
impl Drop for Offer{fn drop(&mut self){unsafe{super::crypto::wipe(self.password.as_mut_vec());}}}
fn valid_mac(s:&str)->bool{let p=s.split(':').collect::<Vec<_>>();p.len()==6&&p.iter().all(|v|v.len()==2&&u8::from_str_radix(v,16).is_ok())}

pub struct Resource {offer:Offer,pub authenticated:bool,negotiated:bool,pub credentials_sent:bool,pub data_port:Option<u32>,pending:Vec<(u32,Vec<u8>)>}
impl Resource {
    pub fn new(offer:Offer)->Self{Self{offer,authenticated:false,negotiated:false,credentials_sent:false,data_port:None,pending:vec![]}}
    pub fn reset(&mut self){self.authenticated=false;self.negotiated=false;self.credentials_sent=false;self.pending.clear();}
    fn respond(&mut self,frame:&Frame)->Result<Option<Vec<u8>>>{
        if !self.authenticated||frame.flags&1!=0{return Ok(None);}let mut replies=vec![];
        for (tag,v) in wire::tlvs(&frame.payload)? {
            let mut p=0;
            match (frame.kind,tag){
                (4,1)=>{
                    if uint(&v,&mut p)?!=3{return Err("unsupported resource channel".into());}
                    let detailed=wire::tlvs(&v[p..])?;if detailed.len()!=1||detailed[0].0!=3{return Err("unsupported capability".into());}
                    let data=&detailed[0].1;if data.len()>256{return Err("capability exceeds limit".into());}
                    let mut caps=BTreeMap::new();p=0;while p<data.len(){let k=uint(data,&mut p)?;let n=uint(data,&mut p)?;
                        if caps.len()>=32||caps.insert(k,n).is_some(){return Err("duplicate/excess capability".into());}}
                    let accepted=caps.get(&2)==Some(&1)&&caps.get(&4)==Some(&1)&&caps.get(&5).is_some_and(|n|n&16!=0);
                    let mut result=wire::uint(3)?;result.extend(wire::uint(if accepted{1}else{255})?);
                    if accepted{let mut role=vec![1];role.extend(wire::uint(5745)?);append(&mut result,3,&role)?;}
                    append(&mut replies,2,&result)?;self.negotiated=accepted;
                },
                (4,3)=>{
                    if !self.negotiated{return Err("network not negotiated".into());}
                    let port=self.data_port.ok_or("DMSDP not listening")?;request(&v,3,20,1)?;
                    let mut result=wire::uint(0)?;result.extend(wire::uint(port)?);result.extend(&v);append(&mut replies,4,&result)?;
                },
                (4,7)=>{
                    let channel=uint(&v,&mut p)?;let status=uint(&v,&mut p)?;let selected=wire::tlvs(&v[p..])?;
                    if !self.negotiated||channel!=3||status!=1||selected.len()!=1||selected[0].0!=3{return Err("invalid network selection".into());}
                    let role=&selected[0].1;p=1;if role.first()!=Some(&2)||uint(role,&mut p)?!=5745||p!=role.len(){return Err("unsupported client role".into());}
                    if self.pending.len()>=4{return Err("too many network commands".into());}self.pending.push((33,wire::tlv(1,&[])?));
                },
                (33,1|2|4)=>{
                    if !self.negotiated{return Err("network command before negotiation".into());}
                    if tag==1{append(&mut replies,2,b"busy")?;}else{
                        if !std::str::from_utf8(&v).is_ok_and(valid_mac){return Err("invalid client MAC".into());}
                        append(&mut replies,3,&self.offer.credentials())?;self.credentials_sent=true;
                    }
                },
                (33,5)=>append(&mut replies,6,&[])?,_=>{},
            }
        }Ok((!replies.is_empty()).then_some(replies))
    }
    pub fn pending(&mut self)->Vec<(u32,Vec<u8>)>{std::mem::take(&mut self.pending)}
}
fn request(v:&[u8],channel:u32,business:u32,protocol:u32)->Result<()>{
    let mut p=0;if uint(v,&mut p)?!=channel||uint(v,&mut p)?!=business{return Err("unsupported business request".into());}
    let len=uint(v,&mut p)? as usize;
    if len>128||len>v.len()-p{return Err("invalid business tag length".into());}
    std::str::from_utf8(&v[p..p+len]).map_err(|_|"invalid business tag")?;p+=len;
    if uint(v,&mut p)?!=protocol||p!=v.len(){return Err("unsupported business transport".into());}Ok(())
}
pub struct Negotiator {summary:Vec<u8>,business:Option<u32>,seen:u8,initiator:bool,requested:bool,pending:Vec<(u32,Vec<u8>)>,endpoint:Option<u16>}
impl Negotiator {
    pub fn new(summary:Vec<u8>,business:Option<u32>)->Result<Self>{
        if !(1..=256).contains(&summary.len())||business.is_some_and(|n|!(1..=30).contains(&n)){return Err("invalid channel identity".into());}
        Ok(Self{summary,business,seen:0,initiator:false,requested:false,pending:vec![],endpoint:None})
    }
    pub fn start(&mut self)->Result<Vec<u8>>{
        self.initiator=true;let mut out=wire::tlv(1,&[2])?;append(&mut out,3,&self.summary)?;append(&mut out,5,&[0])?;Ok(out)
    }
    fn pending(&mut self)->Vec<(u32,Vec<u8>)>{std::mem::take(&mut self.pending)}
    fn endpoint(&mut self)->Option<u16>{self.endpoint.take()}
    pub fn complete(&self)->bool{self.seen==7}
    pub fn respond(&mut self,f:&Frame,resource:&mut Resource)->Result<Option<Vec<u8>>>{
        if f.flags&1!=0{return Ok(None);}
        if matches!(f.kind,4|33)&&self.complete(){return resource.respond(f);}
        let mut out=vec![];
        if f.kind==2&&self.complete(){for (tag,v) in wire::tlvs(&f.payload)?{match tag{
            3=>{if let Some(channel)=self.business{
                request(&v,2,19,0)?;let mut response=wire::uint(0)?;response.extend(wire::uint(channel)?);response.extend(v);response.extend(wire::uint(16)?);
                response.extend([0,0,0xfe,0x36,0,0,0x10,0,0x80,0,0,0x80,0x5f,0x9b,0x34,0xfb]);append(&mut out,4,&response)?;
                // A simultaneous phone-originated connection wins over our wake-up.
                self.initiator=false;self.pending.clear();self.endpoint=None;
            }},
            4 if self.initiator=>{
                let mut p=0;if uint(&v,&mut p)?!=0{return Err("remote business request rejected".into());}let port=uint(&v,&mut p)?;
                if !(1..=30).contains(&port)||uint(&v,&mut p)?!=2||uint(&v,&mut p)?!=19{return Err("invalid remote business channel".into());}
                let n=uint(&v,&mut p)? as usize;if n>128||n>v.len()-p{return Err("invalid remote business tag".into());}p+=n;
                if uint(&v,&mut p)?!=0||uint(&v,&mut p)?!=16||v.len()-p!=16{return Err("invalid remote business transport".into());}
                self.endpoint=Some(port as u16);
            },_=>{},
        }}}
        else if f.kind==0 {let mut seen=self.seen;for (tag,v) in wire::tlvs(&f.payload)?{match tag{
            1=>{if v.len()!=1||v[0]<2{return Err("unsupported CCMP version".into());}append(&mut out,2,&[2])?;seen|=1;},
            2=>{if v.len()!=1||v[0]<2{return Err("unsupported CCMP version response".into());}seen|=1;},
            4=>{if !(1..=256).contains(&v.len()){return Err("invalid remote summary".into());}seen|=2;},
            6=>{if v!=[0]{return Err("encrypted Nearby channel is unsupported".into());}seen|=4;},
            3=>{if !(1..=256).contains(&v.len()){return Err("invalid summary length".into());}append(&mut out,4,&self.summary)?;seen|=2;},
            5=>{if v.len()!=1||v[0]>2{return Err("invalid encryption preference".into());}append(&mut out,6,&[0])?;seen|=4;},_=>{},
        }}self.seen=seen;}
        if self.initiator&&self.complete()&&!self.requested{
            let mut request=wire::uint(2)?;request.extend(wire::uint(19)?);request.extend(wire::uint(0)?);request.extend(wire::uint(0)?);
            self.pending.push((2,wire::tlv(3,&request)?));self.requested=true;
        }
        Ok((!out.is_empty()).then_some(out))
    }
}
fn frame(v:&Value)->Result<Frame>{Ok(Frame{kind:number(v,"kind")?,flags:number(v,"flags")?,options:vec![],payload:unhex(text(v,"payload")?)?})}
pub fn differential(v:&Value)->Result<Value>{
    let mut r=Resource::new(Offer::parse(&v["offer"])?);r.authenticated=v["authenticated"]==true;r.data_port=Some(r.offer.port+1);
    let mut n=Negotiator::new(unhex(text(v,"summary")?)?,v.get("business").and_then(Value::as_u64).map(|n|n as u32))?;
    let frames=v["frames"].as_array().ok_or("missing transcript")?;if frames.len()>128{return Err("transcript exceeds limit".into());}
    let mut out=vec![];for f in frames {let reply=n.respond(&frame(f)?,&mut r)?;out.push(value!({"reply":reply.map(|v|hex(&v)),"complete":n.complete(),
        "pending":r.pending().iter().map(|(k,v)|value!([k,hex(v)])).collect::<Vec<_>>(),"credentials_sent":r.credentials_sent}));}Ok(value!({"steps":out}))
}

#[cfg(unix)]pub mod worker {
    use super::*;
    use super::super::{native::{Runtime,Session},identity::Identity,crypto::{Crypto,wipe}};
    use std::{io::{Read,Write},os::unix::{io::FromRawFd,net::UnixStream},path::Path};
    const LIMIT:usize=256*1024;
    fn read(s:&mut UnixStream)->Result<Option<Value>>{
        let mut size=[0;4];match s.read(&mut size[..1]){Ok(0)=>return Ok(None),Ok(_)=>{},Err(_)=>return Err("private IPC read failed".into())};
        s.read_exact(&mut size[1..]).map_err(|_|"truncated IPC header")?;let n=u32::from_be_bytes(size) as usize;
        if n==0||n>LIMIT{return Err("invalid IPC length".into());}let mut bytes=vec![0;n];s.read_exact(&mut bytes).map_err(|_|"truncated IPC message")?;
        // IPC is bounded separately from individual 64 KiB wireless envelopes.
        let v=serde_json::from_slice(&bytes).map_err(|_|"invalid IPC JSON".into());wipe(&mut bytes);v
    }
    fn send(s:&mut UnixStream,v:&Value)->Result<()>{let mut data=serde_json::to_vec(v).map_err(|_|"IPC serialization failed")?;
        if data.len()>LIMIT{return Err("IPC response exceeds limit".into());}
        let result=s.write_all(&(data.len() as u32).to_be_bytes()).and_then(|_|s.write_all(&data)).map_err(|_|"private IPC write failed".into());wipe(&mut data);result
    }
    struct Business<'a>{native:Option<Session<'a>>,generation:u32}
    impl Business<'_>{fn close(&mut self,r:&mut Resource){self.native=None;r.reset();}}
    pub fn run(fd:i32)->Result<()>{
        if fd<3{return Err("session worker requires a private socket fd".into());}
        let mut socket=unsafe{UnixStream::from_raw_fd(fd)};socket.peer_addr().map_err(|_|"IPC fd is not a connected Unix socket")?;
        // The adapter owns graceful RTSP teardown. Group SIGTERM must reach the
        // adapter first while this private worker still services its IPC. EOF
        // from a dead parent exits the loop; the owner can still SIGKILL a
        // stalled native call after its bounded shutdown deadline.
        unsafe{libc::signal(libc::SIGTERM,libc::SIG_IGN);}
        let config=read(&mut socket)?.ok_or("missing private worker configuration")?;
        let identity=Identity::load(Path::new(text(&config,"identity")?))?;let crypto=Crypto::load()?;
        let model=text(&config,"model")?;let own=identity.wire_id(model,text(&config,"address")?,&crypto)?;
        // The old Python runtime initializes HUKS with the persisted random ID,
        // before deriving the Bluetooth signing identity. Keep that exact seed.
        let runtime=Runtime::open(Path::new(text(&config,"library")?),Path::new(text(&config,"store")?),&identity.device_id)?;
        let mut resource=Resource::new(Offer::parse(&config["offer"])?);resource.data_port=Some(resource.offer.port+1);
        let mut channels:BTreeMap<u32,Negotiator>=BTreeMap::new();let mut next=0u32;
        let mut business=Business{native:None,generation:0};let mut auth_open=false;let mut peer_seen=false;
        let mut sight:Option<(u32,super::super::hisight::Session)>=None;let mut next_sight=0u32;
        let mut control:Option<(u32,super::super::dmsdp::Session)>=None;let mut next_control=0u32;
        send(&mut socket,&value!({"ok":true,"ready":true,"wire_identity_sha256":hex(&crypto.sha256(own.as_bytes())?)}))?;
        while let Some(command)=read(&mut socket)?{
            let op=text(&command,"op")?;let result:Result<Value>=(||{match op {
                "open"=>{if channels.len()>=8{return Err("channel limit".into());}next=next.checked_add(1).ok_or("channel generation exhausted")?;
                    let channel=if command["business"]==true{Some(number(&config,"business_channel")?)}else{None};
                    let mut n=Negotiator::new(own.as_bytes().to_vec(),channel)?;let initial=if command["initiator"]==true{Some(hex(&n.start()?))}else{None};
                    channels.insert(next,n);Ok(value!({"channel":next,"initial":initial}))},
                "nearby"=>{let n=channels.get_mut(&number(&command,"channel")?).ok_or("stale channel")?;
                    let reply=n.respond(&frame(&command)?,&mut resource)?;let mut commands=resource.pending();commands.extend(n.pending());
                    Ok(value!({"reply":reply.map(|v|hex(&v)),"complete":n.complete(),"business_endpoint":n.endpoint(),
                        "pending":commands.iter().map(|(k,v)|value!([k,hex(v)])).collect::<Vec<_>>(),"credentials_sent":resource.credentials_sent}))},
                "close-channel"=>{channels.remove(&number(&command,"channel")?);Ok(value!({}))},
                "auth-open"=>{if auth_open{return Err("business authentication already active".into());}
                    business.generation=business.generation.checked_add(1).ok_or("auth generation exhausted")?;sight=None;control=None;business.close(&mut resource);peer_seen=false;auth_open=true;
                    Ok(value!({"generation":business.generation}))},
                "auth"=>{
                    if !auth_open||number(&command,"generation")?!=business.generation{return Err("stale authentication session".into());}
                    let envelope=text(&command,"envelope")?;let (operation,inner)=json::envelope(envelope.as_bytes(),peer_seen)?;
                    if operation==1{let peer=text(&inner,"deviceId")?;business.native=Some(Session::new(&runtime,&own,peer,&identity.pin,2)?);peer_seen=true;
                        let details=value!({"deviceId":own,"devicename":identity.name,"has_pin":true,"usb_connection":false,"CONNECT_ABILITY_KEY":"1","CAR_MODE_ID":model});
                        let reply=value!({"version":"A_0","discover_type":1,"oper_type":1,"data":details.to_string(),"usb_connection":false});
                        return Ok(value!({"reply":hex(reply.to_string().as_bytes()),"metadata":{"operation":1,"peer_id_bytes":peer.len(),"pin_required":true}}));}
                    let session=business.native.as_mut().ok_or("authentication before identity")?;
                    let (code,packets)=session.receive(inner.to_string().as_bytes())?;
                    if session.results().contains(&1){return Err("HiChain authentication failed".into());}
                    let mut replies=vec![];for packet in packets {let parsed=json::parse(&packet)?;if !parsed.is_object(){return Err("invalid native response".into());}
                        let p=std::str::from_utf8(&packet).map_err(|_|"invalid native text")?;
                        replies.extend(value!({"version":"A_0","discover_type":1,"oper_type":3,"data":p,"usb_connection":false}).to_string().as_bytes());}
                    let mut key=session.key_for_bridge();resource.authenticated=session.results().contains(&0)&&key.is_some();
                    let key_hex=if resource.authenticated{key.as_ref().map(|k|hex(k))}else{None};
                    if let Some(k)=key.as_mut(){wipe(k);}
                    Ok(value!({"reply":if replies.is_empty(){None}else{Some(hex(&replies))},"key":key_hex,
                        "metadata":{"operation":3,"message":inner.get("message").and_then(Value::as_u64),"backend":"hichain","native_code":code,
                        "replies":if replies.is_empty(){0}else{1},"results":session.results(),"key_ready":resource.authenticated}}))
                },
                "auth-close"=>{if command["generation"].as_u64()==Some(business.generation as u64){
                    // RFCOMM authentication can finish while the established
                    // TCP media session is still alive. Its owned cipher key
                    // lasts until HiSight closes or a new auth generation.
                    business.close(&mut resource);auth_open=false;peer_seen=false;
                }Ok(value!({}))},
                "hisight-open"=>{
                    if !auth_open||!resource.authenticated||number(&command,"generation")?!=business.generation{return Err("unauthenticated or stale HiSight session".into());}
                    if sight.is_some(){return Err("HiSight session already active".into());}
                    let mut key=business.native.as_ref().and_then(|s|s.key_for_bridge()).ok_or("missing authenticated media key")?;
                    let session=super::super::hisight::Session::new(&key);wipe(&mut key);let session=session?;
                    next_sight=next_sight.checked_add(1).ok_or("HiSight generation exhausted")?;
                    let initial=session.initial()?;sight=Some((next_sight,session));Ok(value!({"session":next_sight,"initial":hex(&initial)}))
                },
                "dmsdp-open"=>{
                    if !auth_open||!resource.authenticated||number(&command,"generation")?!=business.generation{return Err("unauthenticated or stale DMSDP session".into());}
                    if control.is_some(){return Err("DMSDP session already active".into());}
                    let mut key=business.native.as_ref().and_then(|s|s.key_for_bridge()).ok_or("missing authenticated control key")?;
                    let session=super::super::dmsdp::Session::new(&key,command["device_info"].clone(),command["audio"]==true);wipe(&mut key);let session=session?;
                    next_control=next_control.checked_add(1).ok_or("DMSDP generation exhausted")?;
                    let initial=session.initial()?;let state=session.state();control=Some((next_control,session));
                    Ok(value!({"session":next_control,"initial":hex(&initial),"state":state}))
                },
                "dmsdp-receive"|"dmsdp-heartbeat"|"dmsdp-ports"|"dmsdp-stop-audio"|"dmsdp-close"=>{
                    let token=number(&command,"session")?;
                    let (_,session)=control.as_mut().filter(|(n,_)|*n==token).ok_or("stale DMSDP session")?;
                    if op=="dmsdp-close"{control=None;return Ok(value!({}));}
                    let (events,plaintexts)=if op=="dmsdp-receive"{session.receive(&unhex(text(&command,"data")?)?,command["now_us"].as_u64().ok_or("missing monotonic timestamp")?,command["capture"]==true)?}else{(vec![],vec![])};
                    let heartbeat=if op=="dmsdp-heartbeat"{Some(session.heartbeat()?)}else{None};
                    if op=="dmsdp-stop-audio"{session.stop_audio()?;}
                    if op=="dmsdp-ports"{let ports=command["ports"].as_array().filter(|v|v.len()==2).ok_or("invalid speaker ports")?;
                        let port=ports[0].as_u64().and_then(|v|u16::try_from(v).ok()).ok_or("invalid speaker RTP port")?;
                        let rtcp=ports[1].as_i64().and_then(|v|i32::try_from(v).ok()).ok_or("invalid speaker RTCP mode")?;session.set_audio_ports((port,rtcp))?;
                    }
                    Ok(value!({"events":events,"plaintexts":plaintexts.iter().map(|v|hex(v)).collect::<Vec<_>>(),"pending":session.pending().iter().map(|v|hex(v)).collect::<Vec<_>>(),"heartbeat":heartbeat.map(|v|hex(&v)),"state":session.state()}))
                },
                "hisight-receive"|"hisight-play"|"hisight-teardown"|"hisight-close"=>{
                    let token=number(&command,"session")?;
                    let (_,session)=sight.as_mut().filter(|(n,_)|*n==token).ok_or("stale HiSight session")?;
                    if op=="hisight-close"{sight=None;return Ok(value!({}));}
                    let (events,plaintexts)=if op=="hisight-receive"{session.receive(&unhex(text(&command,"data")?)?,command["capture"]==true)?}else{(vec![],vec![])};
                    if op=="hisight-play"{session.request("PLAY")?;}
                    let teardown=if op=="hisight-teardown"{session.teardown()?}else{None};
                    Ok(value!({"events":events,"plaintexts":plaintexts.iter().map(|v|hex(v)).collect::<Vec<_>>(),"pending":session.pending().iter().map(|v|hex(v)).collect::<Vec<_>>(),"teardown":teardown.map(|v|hex(&v)),"state":session.state()}))
                },
                "close"=>Ok(value!({"closed":true})),_=>Err("unknown session command".into()),
            }})();
            match result{Ok(mut v)=>{v["ok"]=true.into();send(&mut socket,&v)?;if op=="close"{break;}},Err(error)=>{
                // Protocol errors revoke authorization before any later network command.
                if op=="auth"&&auth_open&&command["generation"].as_u64()==Some(business.generation as u64){sight=None;control=None;business.close(&mut resource);auth_open=false;peer_seen=false;}
                if op.starts_with("hisight-")&&sight.as_ref().is_some_and(|(n,_)|command["session"].as_u64()==Some(*n as u64)){sight=None;}
                if op.starts_with("dmsdp-")&&control.as_ref().is_some_and(|(n,_)|command["session"].as_u64()==Some(*n as u64)){control=None;sight=None;}
                send(&mut socket,&value!({"ok":false,"error":error}))?;
            }}
        }
        business.close(&mut resource);Ok(())
    }
}

#[cfg(test)]mod tests{
    use super::*;
    fn offer()->Offer{Offer::parse(&value!({"ssid":"HelloCar","bssid":"02:00:00:00:00:01","password":"12345678","owner_ip":"192.168.49.1","client_ip":"192.168.49.2","frequency":5745,"port":4005})).unwrap()}
    #[test]fn authentication_gates_credentials_and_generation_reset(){
        let mut r=Resource::new(offer());let f=Frame{kind:33,flags:0,options:vec![],payload:wire::tlv(2,b"02:11:22:33:44:55").unwrap()};
        assert!(r.respond(&f).unwrap().is_none());r.authenticated=true;assert!(r.respond(&f).is_err());r.negotiated=true;
        assert!(r.respond(&f).unwrap().is_some());assert!(r.credentials_sent);r.reset();assert!(!r.credentials_sent&&!r.authenticated);
    }
    #[test]fn outgoing_nearby_handshake_and_business_endpoint_roundtrip(){
        let mut client=Negotiator::new(vec![b'A';64],None).unwrap();let mut server=Negotiator::new(vec![b'B';64],Some(24)).unwrap();
        let mut cr=Resource::new(offer());let mut sr=Resource::new(offer());
        let frame=|kind,payload|Frame{kind,flags:0,options:vec![],payload};
        let hello=client.start().unwrap();let response=server.respond(&frame(0,hello),&mut sr).unwrap().unwrap();assert!(server.complete());
        assert!(client.respond(&frame(0,response),&mut cr).unwrap().is_none());assert!(client.complete());
        let pending=client.pending();assert_eq!(pending.len(),1);assert_eq!(pending[0].0,2);
        let reply=server.respond(&frame(2,pending[0].1.clone()),&mut sr).unwrap().unwrap();
        client.respond(&frame(2,reply),&mut cr).unwrap();assert_eq!(client.endpoint(),Some(24));assert!(client.pending().is_empty());assert_eq!(client.endpoint(),None);
    }
    #[test]fn simultaneous_phone_business_request_preserves_passive_connection(){
        let mut n=Negotiator::new(vec![b'A';64],Some(24)).unwrap();let mut r=Resource::new(offer());n.start().unwrap();n.seen=7;
        let mut request=wire::uint(2).unwrap();request.extend(wire::uint(19).unwrap());request.extend(wire::uint(0).unwrap());request.extend(wire::uint(0).unwrap());
        let reply=n.respond(&Frame{kind:2,flags:0,options:vec![],payload:wire::tlv(3,&request).unwrap()},&mut r).unwrap();assert!(reply.is_some());assert!(!n.initiator);assert!(n.pending().is_empty());assert_eq!(n.endpoint(),None);
    }
    #[test]fn outgoing_nearby_rejects_unencrypted_mismatch_and_invalid_business_channel(){
        let mut client=Negotiator::new(vec![b'A';64],None).unwrap();let mut r=Resource::new(offer());client.start().unwrap();
        let mut response=wire::tlv(2,&[2]).unwrap();response.extend(wire::tlv(4,b"real peer summary").unwrap());response.extend(wire::tlv(6,&[1]).unwrap());
        assert!(client.respond(&Frame{kind:0,flags:0,options:vec![],payload:response},&mut r).is_err());assert!(!client.complete());
        client.seen=7;let mut reply=wire::uint(0).unwrap();reply.extend(wire::uint(31).unwrap());reply.extend([0;20]);
        assert!(client.respond(&Frame{kind:2,flags:0,options:vec![],payload:wire::tlv(4,&reply).unwrap()},&mut r).is_err());assert_eq!(client.endpoint(),None);
    }
    #[test]fn negotiation_is_atomic_on_malformed_tlv(){let mut n=Negotiator::new(vec![65;64],Some(24)).unwrap();let mut r=Resource::new(offer());
        let mut payload=wire::tlv(1,&[2]).unwrap();payload.extend(wire::tlv(3,&[]).unwrap());assert!(n.respond(&Frame{kind:0,flags:0,options:vec![],payload},&mut r).is_err());assert_eq!(n.seen,0);}
}
