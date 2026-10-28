//! Stateful DMSDP control and Simple speaker negotiation. No media/identity logging.
use super::{Result,crypto::{Crypto,wipe},wire::{self,Decoder,Format,Frame,Message,Messages}};
use serde_json::{Value,json};
use std::{collections::VecDeque,io::Read};

fn digits(s:&str,n:usize)->bool{!s.is_empty()&&s.len()<=n&&s.bytes().all(|b|b.is_ascii_digit())}
fn seq(s:&str)->Result<()>{if digits(s,9){Ok(())}else{Err("invalid control sequence".into())}}
fn encode(start:&str,headers:&[(&str,String)])->Result<Vec<u8>>{
    if !matches!(start,"OPTIONS * DMSDP/1.0"|"GET_PARAMETER * DMSDP/1.0"|"SETUP * DMSDP/1.0"|"PLAY * DMSDP/1.0"|"TEARDOWN * DMSDP/1.0"|"DMSDP/1.0 200 OK"){return Err("unsupported DMSDP request".into());}
    let mut text=format!("{start}\r\n");
    for (name,value) in headers{if !value.is_ascii()||value.bytes().any(|b|matches!(b,0|10|13)){return Err("invalid DMSDP header value".into());}text.push_str(&format!("{name}: {value}\r\n"));}
    text.push_str("\r\n");Ok(text.into_bytes())
}
fn frame(data:Vec<u8>,encrypted:bool)->Result<Vec<u8>>{Frame{kind:if encrypted{0xab}else{0},flags:0,options:vec![],payload:data}.encode(Format::Control)}
fn metadata(m:&Message)->Value{
    let mut v=json!({"method":m.start.split(' ').next().unwrap_or(""),"header_names":m.headers.keys().collect::<Vec<_>>(),"body_bytes":m.body.len()});
    for name in ["cseq","cryptover","cryptoability","cryptoswitch","udpka","lowdelay"]{if let Some(n)=m.headers.get(name).filter(|n|digits(n,9)){v[name]=n.parse::<u32>().unwrap().into();}}v
}
fn ascii_json(v:&Value)->Result<Vec<u8>>{
    let text=serde_json::to_string(v).map_err(|_|"cannot encode device information")?;let mut out=String::new();
    for c in text.chars(){if c.is_ascii(){out.push(c);}else{let mut bytes=[0u16;2];for u in c.encode_utf16(&mut bytes){out.push_str(&format!("\\u{u:04x}"));}}}Ok(out.into_bytes())
}
fn unsigned(data:&[u8],pos:&mut usize)->Result<u32>{wire::read_uint(data,pos)?.ok_or_else(||"incomplete device integer".into())}
fn decimal(s:&str)->Result<(bool,String)>{
    let (negative,text)=if let Some(t)=s.strip_prefix('-'){(true,t)}else{(false,s.strip_prefix('+').unwrap_or(s))};
    if text.is_empty()||text.starts_with('_')||text.ends_with('_')||text.contains("__")||!text.bytes().all(|b|b.is_ascii_digit()||b==b'_'){return Err("invalid peer clock integer".into());}
    Ok((negative,text.replace('_',"")))
}
fn wrapped(s:&str)->Result<u32>{let(negative,text)=decimal(s)?;let n=text.bytes().fold(0u32,|n,b|n.wrapping_mul(10).wrapping_add((b-b'0')as u32));Ok(if negative{n.wrapping_neg()}else{n})}
fn clock_port(s:&str)->Result<u16>{let(negative,text)=decimal(s)?;if negative{return Err("invalid peer clock port".into());}text.parse::<u16>().ok().filter(|p|*p!=0).ok_or_else(||"invalid peer clock port".into())}
fn trigger(body:&[u8])->Option<&str>{let text=std::str::from_utf8(body).ok()?.strip_prefix("msdp_trigger_method:")?.trim_matches(|c:char|c.is_ascii_whitespace());
    (!text.is_empty()&&text.bytes().all(|b|b.is_ascii_uppercase())).then_some(text)}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum MicPhase{Idle,Crypto,Setup,Play,Ready}
struct Speaker{name:&'static str,kind:u8,remote:Option<u16>,ports:Option<(u16,i32)>,session:Option<u32>,sequence:u32,setup:Option<u32>,format:Option<Value>,ready:bool,mic_phase:MicPhase,retired:VecDeque<u32>}
impl Speaker{
    fn new()->Self{Self::named("speaker1",3)}
    fn named(name:&'static str,kind:u8)->Self{Self{name,kind,remote:None,ports:None,session:None,sequence:0,setup:None,format:None,ready:false,mic_phase:MicPhase::Idle,retired:VecDeque::new()}}
    fn microphone(&self)->bool{matches!(self.kind,2|9)}
    fn notify(&self,name:&str)->Value{let mut v=json!({});v[format!("{}_{}",if self.microphone(){"microphone"}else{"audio"},name)]=true.into();v["service"]=self.name.into();v["modem"]=(self.kind>=9).into();if let Some(p)=self.remote{v["port"]=p.into();}if let Some(id)=self.session{v["session"]=id.into();}v}
    fn request(&mut self,method:&str,extra:&[(&str,String)])->Result<Vec<u8>>{
        self.sequence=self.sequence.checked_add(1).filter(|n|*n<=999999999).ok_or("speaker sequence exhausted")?;
        let mut fields=vec![("ServiceID",self.name.into()),("ServiceType",self.kind.to_string()),("DataSessionID",self.session.ok_or("no speaker session")?.to_string()),("CSeq",self.sequence.to_string())];fields.extend_from_slice(extra);
        encode(&format!("{method} * DMSDP/1.0"),&fields)
    }
    fn retire(&mut self){if let Some(id)=self.session.take(){if self.retired.len()>=16{self.retired.pop_front();}self.retired.push_back(id);}self.ready=false;self.remote=None;self.mic_phase=MicPhase::Idle;}
    fn teardown(&mut self)->Result<Option<Vec<u8>>>{if self.session.is_none(){return Ok(None);}let record=self.request("TEARDOWN",&[])?;self.retire();Ok(Some(record))}
    fn state(&self)->Value{json!({"ports":self.ports,"session_id":self.session,"sequence":self.sequence,"setup_sequence":self.setup,"format":self.format,"ready":self.ready})}
    fn receive(&mut self,m:&Message)->Result<Option<(Vec<Value>,Vec<Vec<u8>>)>>{
        let h=&m.headers;if h.get("serviceid").map(String::as_str)!=Some(self.name){return Ok(None);}
        if h.get("servicetype")!=Some(&self.kind.to_string()){return Err("unsupported audio transport type".into());}
        let sequence=h.get("cseq").map(String::as_str).unwrap_or("");seq(sequence)?;
        let id=h.get("datasessionid").map(String::as_str).unwrap_or("");
        let id=(if digits(id,10){id.parse::<u32>().ok().filter(|n|*n<=0x7fffffff)}else{None}).ok_or("invalid speaker session")?;
        let mut events=vec![];let mut replies=vec![];
        let name=self.name;let kind=self.kind;
        let acknowledge=||encode("DMSDP/1.0 200 OK",&[("ServiceID",name.into()),("ServiceType",kind.to_string()),("DataSessionID",id.to_string()),("CSeq",sequence.into())]);
        if let Some(t)=trigger(&m.body){
            if !m.start.starts_with("SET_PARAMETER "){return Err("speaker trigger outside SET_PARAMETER".into());}
            match t{
                "OPTIONS"=>{
                    let(port,rtcp)=self.ports.ok_or("speaker ports are not configured")?;
                    if port==0||rtcp!= -1||!matches!(h.get("simple").map(String::as_str),Some("1"|"0"))||id==0{return Err("unsupported speaker setup mode".into());}
                    if self.session==Some(id){return Ok(Some((events,replies)));}
                    if self.retired.contains(&id){return Ok(Some((events,replies)));}
                    if self.session.is_some(){if self.microphone()&&self.ready{events.push(self.notify("stopped"));}self.retire();}
                    self.session=Some(id);self.ready=false;self.format=None;
                    if self.microphone(){
                        // A mic is a sender: the phone owns the RTP receiver.
                        // Simple=0 initiates its per-stream crypto and SETUP.
                        replies.push(self.request("OPTIONS",&[("Simple","0".into()),("CryptoVer","1".into()),("CryptoAbility","222".into()),("CryptoAlg","aes128-ctr".into()),("Fillp","0".into()),("TCP","0".into()),("Codec","0".into())])?);
                        self.mic_phase=MicPhase::Crypto;
                    }else{
                        if h.get("simple").map(String::as_str)!=Some("1"){return Err("unsupported speaker setup mode".into());}
                        replies.push(self.request("SETUP",&[("Transport",format!("RTP/AVP/UDP;unicast;client_port={port}--1")),("Simple","1".into()),("CryptoVer","1".into()),("CryptoAbility","222".into()),("CryptoAlg","aes128-ctr".into()),("Fillp","0".into()),("TCP","0".into()),("Codec","0".into())])?);
                    }
                    self.setup=Some(self.sequence);events.push(self.notify("setup_sent"));
                },
                "TEARDOWN"=>{if self.session==Some(id){if let Some(record)=self.teardown()?{replies.push(record);}events.push(self.notify("stopped"));}},
                "CLOSE"=>{if self.session==Some(id){events.push(self.notify("stopped"));self.retire();}},
                _=>return Err("unsupported speaker trigger".into()),
            }
        }else if m.start.starts_with("DMSDP/1.0 "){
            if self.session!=Some(id)||sequence.parse::<u32>().ok()!=self.setup{return Ok(Some((events,replies)));}
            if !m.start.starts_with("DMSDP/1.0 200 "){return Err("speaker setup refused".into());}
            if self.microphone(){return Ok(Some((events,replies)));}
            let transport=h.get("transport").map(String::as_str).unwrap_or("");
            let ports=transport.strip_prefix("RTP/AVP/UDP;unicast;client_port=").and_then(|s|s.strip_suffix("--1")).and_then(|s|s.split_once("--1;server_port="));
            let (client,server)=ports.ok_or("invalid speaker server endpoint")?;
            if !client.bytes().all(|b|b.is_ascii_digit())||client.is_empty()||!server.bytes().all(|b|b.is_ascii_digit())||server.is_empty(){return Err("invalid speaker server endpoint".into());}
            if client.parse::<u16>().ok()!=self.ports.map(|p|p.0)||server.parse::<u16>().ok().filter(|p|*p!=0).is_none(){return Err("invalid speaker server endpoint".into());}
            self.remote=server.parse().ok();self.ready=true;events.push(self.notify("ready"));
        }else if self.session!=Some(id){if self.microphone()||self.retired.contains(&id){return Ok(Some((events,replies)));}return Err("speaker session mismatch".into());}
        else if m.start.starts_with("SET_PARAMETER "){
            if self.microphone()&&h.contains_key("cryptoswitch"){
                if self.mic_phase==MicPhase::Idle||h.get("cryptover").map(String::as_str)!=Some("1")||h.get("cryptoswitch").map(String::as_str)!=Some("222")||h.get("cryptoalg").map(String::as_str)!=Some("aes128-ctr")||!m.body.is_empty(){return Err("unsupported microphone crypto negotiation".into());}
                replies.push(encode("DMSDP/1.0 200 OK",&[("ServiceID",name.into()),("ServiceType",kind.to_string()),("DataSessionID",id.to_string()),("CSeq",sequence.into()),("CryptoVer","1".into())])?);
                if self.mic_phase==MicPhase::Crypto{self.mic_phase=MicPhase::Setup;}
                return Ok(Some((events,replies)));
            }
            let text=h.get("audioparameter").map(String::as_str).unwrap_or("");
            let parts=text.strip_prefix("SampleRate=").and_then(|s|s.strip_suffix(";Codec=0")).and_then(|s|s.split_once(";Format=16;ChannelNum="));
            let(rate,channels)=parts.ok_or("unsupported speaker audio parameters")?;
            if !matches!(rate,"48000"|"44100"|"32000"|"24000"|"16000"|"8000")||!matches!(channels,"1"|"2")||!m.body.is_empty(){return Err("unsupported speaker audio parameters".into());}
            if self.microphone()&&(rate!="48000"||channels!="2"){return Err("microphone requires negotiated 48000 Hz stereo AAC".into());}
            let format=json!({"codec":"aac-adts","rate":rate.parse::<u32>().unwrap(),"channels":channels.parse::<u8>().unwrap(),"pcm_bits":16});
            self.format=Some(format.clone());replies.push(acknowledge()?);let mut e=format;e["audio_negotiated"]=true.into();events.push(e);
        }else if self.microphone()&&m.start.starts_with("SETUP "){
            if !matches!(self.mic_phase,MicPhase::Setup|MicPhase::Play|MicPhase::Ready)||!m.body.is_empty(){return Err("unexpected microphone setup".into());}
            let local=self.ports.ok_or("microphone port unavailable")?.0;
            let client=h.get("transport").and_then(|s|s.strip_prefix("RTP/AVP/UDP;unicast;client_port=")).ok_or("invalid microphone transport")?;
            let (rtp,rtcp)=client.split_once('-').ok_or("invalid microphone client ports")?;
            let remote=rtp.parse::<u16>().ok().filter(|p|*p!=0).ok_or("invalid microphone client RTP port")?;
            if rtcp!="-1"&&rtcp.parse::<u16>().ok().filter(|p|*p!=0).is_none(){return Err("invalid microphone client RTCP port".into());}
            if self.mic_phase!=MicPhase::Setup&&self.remote!=Some(remote){return Err("microphone endpoint changed during setup".into());}
            self.remote=Some(remote);
            replies.push(encode("DMSDP/1.0 200 OK",&[("ServiceID",name.into()),("ServiceType",kind.to_string()),("DataSessionID",id.to_string()),("CSeq",sequence.into()),("Transport",format!("RTP/AVP/UDP;unicast;client_port={client};server_port={local}--1"))])?);
            if self.mic_phase==MicPhase::Setup{self.mic_phase=MicPhase::Play;}
        }else if self.microphone()&&m.start.starts_with("PLAY "){
            if !matches!(self.mic_phase,MicPhase::Play|MicPhase::Ready)||!m.body.is_empty(){return Err("unexpected microphone play".into());}
            replies.push(acknowledge()?);
            if self.mic_phase!=MicPhase::Ready{self.ready=true;self.mic_phase=MicPhase::Ready;events.push(self.notify("ready"));}
        }else if m.start.starts_with("TEARDOWN "){replies.push(acknowledge()?);events.push(self.notify("stopped"));self.retire();}
        else if m.start.starts_with("GET_PARAMETER ")&&m.body.is_empty(){replies.push(acknowledge()?);}
        else{return Err("unsupported speaker request".into());}
        Ok(Some((events,replies)))
    }
}

pub struct Session{
    key:Vec<u8>,crypto:Option<Crypto>,decoder:Decoder,messages:Messages,pending:Vec<Vec<u8>>,failed:bool,
    negotiated:bool,device_info:Value,device_exchanged:bool,clock:Option<(u64,u64,u16)>,media_port:Option<u16>,speaker:Option<Speaker>,services:Vec<Speaker>,heartbeat_sequence:u32,
}
impl Drop for Session{fn drop(&mut self){wipe(&mut self.key);}}
impl Session{
    pub fn new(key:&[u8],device_info:Value,audio:bool)->Result<Self>{
        if !matches!(key.len(),0|16|32){return Err("invalid authenticated DMSDP key".into());}
        if !device_info.is_null()&&!device_info.is_object(){return Err("invalid DMSDP device information".into());}
        if ascii_json(&device_info)?.len()>65536{return Err("device information exceeds limit".into());}
        let services=if audio&&device_info["properties"]["5002"]==true{vec![Speaker::named("mic1",2),Speaker::named("modemMic",9),Speaker::named("modemSpeaker",10)]}else{vec![]};
        Ok(Self{key:key.iter().take(16).copied().collect(),crypto:if key.is_empty(){None}else{Some(Crypto::load()?)},decoder:Decoder::new(Format::Control),messages:Messages::new("DMSDP"),pending:vec![],failed:false,negotiated:false,device_info,device_exchanged:false,clock:None,media_port:None,speaker:audio.then(Speaker::new),services,heartbeat_sequence:1})
    }
    fn healthy(&self)->Result<()>{if self.failed{Err("DMSDP session requires reset".into())}else{Ok(())}}
    fn pack(&self,data:&[u8],plain:bool)->Result<Vec<u8>>{
        self.healthy()?;let payload=if let Some(crypto)=self.crypto.as_ref().filter(|_|!plain){
            let mut iv=[0;16];std::fs::File::open("/dev/urandom").and_then(|mut f|f.read_exact(&mut iv)).map_err(|_|"cannot obtain DMSDP IV")?;
            let mut out=iv.to_vec();out.extend(crypto.transform(&self.key,&iv,data)?);out
        }else{data.to_vec()};frame(payload,!plain&&self.crypto.is_some())
    }
    fn queue(&mut self,packet:Vec<u8>)->Result<()>{if self.pending.len()>=64{return Err("DMSDP response queue exceeds limit".into());}self.pending.push(packet);Ok(())}
    fn send(&mut self,data:&[u8])->Result<()>{if !self.negotiated{return Err("control session is not negotiated".into());}let packet=self.pack(data,false)?;self.queue(packet)}
    fn business(&mut self,module:u32,kind:u32,body:&[u8])->Result<()>{
        if body.len()>65535{return Err("business body exceeds limit".into());}
        let mut out=vec![b'$'];out.extend(module.to_be_bytes());out.extend(kind.to_be_bytes());out.extend((body.len()as u16).to_be_bytes());out.extend(body);self.send(&out)
    }
    pub fn initial(&self)->Result<Vec<u8>>{self.pack(&encode("OPTIONS * DMSDP/1.0",&[("CryptoVer","1".into()),("CryptoAbility","222".into()),("CryptoAlg",if self.crypto.is_some(){"aes128-ctr"}else{"null"}.into()),("UdpKA","0".into()),("LowDelay","0".into()),("CSeq","1".into())])?,true)}
    pub fn heartbeat(&mut self)->Result<Vec<u8>>{
        self.healthy()?;if !self.negotiated{return Err("heartbeat before control negotiation".into());}
        self.heartbeat_sequence=self.heartbeat_sequence.checked_add(1).filter(|n|*n<=999999999).ok_or("heartbeat sequence exhausted")?;
        self.pack(&encode("GET_PARAMETER * DMSDP/1.0",&[("CSeq",self.heartbeat_sequence.to_string())])?,false)
    }
    pub fn set_audio_ports(&mut self,ports:(u16,i32))->Result<()>{self.healthy()?;if ports.0==0||ports.1!= -1{return Err("invalid speaker ports".into());}self.speaker.as_mut().ok_or("speaker is disabled")?.ports=Some(ports);for service in &mut self.services{service.ports=Some(ports);}Ok(())}
    pub fn stop_audio(&mut self)->Result<()>{self.healthy()?;let mut pending=vec![];if let Some(speaker)=self.speaker.as_mut(){if let Some(record)=speaker.teardown()?{pending.push(record);}}for s in &mut self.services{if let Some(record)=s.teardown()?{pending.push(record);}}for p in pending{self.send(&p)?;}Ok(())}
    pub fn pending(&mut self)->Vec<Vec<u8>>{std::mem::take(&mut self.pending)}
    pub fn state(&self)->Value{json!({"failed":self.failed,"negotiated":self.negotiated,"device_exchanged":self.device_exchanged,"clock":self.clock,"media_port":self.media_port,"speaker":self.speaker.as_ref().map(Speaker::state),"heartbeat_sequence":self.heartbeat_sequence})}
    pub fn receive(&mut self,data:&[u8],now_us:u64,capture:bool)->Result<(Vec<Value>,Vec<Vec<u8>>)>{
        self.healthy()?;let result=if data.len()>65536{Err("DMSDP input chunk exceeds limit".into())}else{self.receive_inner(data,now_us,capture)};
        if result.is_err(){self.failed=true;self.pending.clear();self.negotiated=false;self.clock=None;self.media_port=None;wipe(&mut self.key);if let Some(s)=self.speaker.as_mut(){s.session=None;s.ready=false;}}result
    }
    fn receive_inner(&mut self,data:&[u8],now_us:u64,capture:bool)->Result<(Vec<Value>,Vec<Vec<u8>>)>{
        let mut events=vec![];let mut plaintexts=vec![];let frames=self.decoder.feed(data)?;if frames.len()>64{return Err("too many DMSDP control frames".into());}
        for frame in frames{
            let payload=if frame.kind==0xab{
                let Some(crypto)=&self.crypto else{events.push(json!({"encrypted":true,"size":frame.payload.len()}));continue};
                if !self.negotiated{return Err("encrypted data before negotiation".into());}
                if frame.payload.len()<=16||frame.payload.len()>=1500{return Err("invalid encrypted control record".into());}
                let plain=crypto.transform(&self.key,&frame.payload[..16],&frame.payload[16..])?;
                if capture{plaintexts.push(plain.clone());}plain
            }else{frame.payload};
            if payload.starts_with(b"$"){self.binary(&payload,&mut events)?;}else{
                for message in self.messages.feed(&payload)?{events.push(metadata(&message));self.text(&message,now_us,&mut events)?;}
            }
            if events.len()>256{return Err("too many DMSDP message events".into());}
        }Ok((events,plaintexts))
    }
    fn binary(&mut self,data:&[u8],events:&mut Vec<Value>)->Result<()>{
        if data.len()<11||u16::from_be_bytes([data[9],data[10]])as usize!=data.len()-11{return Err("invalid binary control message".into());}
        let module=u32::from_be_bytes(data[1..5].try_into().unwrap());let kind=u32::from_be_bytes(data[5..9].try_into().unwrap());let body=&data[11..];
        events.push(json!({"binary":true,"module":module,"data_type":kind,"body_bytes":body.len()}));
        if module==5&&kind==u32::MAX{let mut pos=0;let cmd=unsigned(body,&mut pos)?;let port=unsigned(body,&mut pos)?;
            if cmd!=101||pos!=body.len()||!(1..=65535).contains(&port){return Err("invalid HiSight endpoint".into());}self.media_port=Some(port as u16);events.push(json!({"hisight_endpoint":true,"port":port}));}
        if module==3&&kind==u32::MAX&&self.device_info.as_object().is_some_and(|v|!v.is_empty()){
            let mut pos=0;let command=unsigned(body,&mut pos)?;events.push(json!({"device_command":command,"body_bytes":body.len()-pos}));
            match command{
                101=>{let peer=super::json::parse(&body[pos..])?;if !peer.is_object()||peer.get("deviceId").and_then(Value::as_str).is_none(){return Err("missing peer device information".into());}
                    if !self.device_exchanged{let mut own=self.device_info.clone();own["businessId"]=peer.get("businessId").cloned().unwrap_or(json!(1));let mut payload=wire::uint(101)?;payload.extend(ascii_json(&own)?);self.business(3,u32::MAX,&payload)?;self.device_exchanged=true;events.push(json!({"device_info_sent":true}));}
                },
                104=>{if !self.device_exchanged||body.len()-pos!=4{return Err("invalid service discovery request".into());}let mask=u32::from_be_bytes(body[pos..].try_into().unwrap());events.push(json!({"service_request_mask":mask}));
                    for service_type in [8,4,2,256,512]{if mask&service_type==0||service_type==4&&self.speaker.is_none()||matches!(service_type,2|256|512)&&self.services.is_empty(){continue;}
                        let id=self.device_info.get("deviceId").and_then(Value::as_str).ok_or("missing local device identifier")?;let name=self.device_info.get("deviceName").and_then(Value::as_str).ok_or("missing local device name")?;
                        let service=if service_type==8{json!({"deviceId":id,"deviceName":name,"serviceId":"display1","serviceType":8,"properties":{"4001":1.0,"1009":800,"1010":480},"status":{}})}else{let microphone=matches!(service_type,2|256);let service_id=match service_type{2=>"mic1",256=>"modemMic",512=>"modemSpeaker",_=>"speaker1"};let rates=if microphone{"48000"}else if service_type==4{"48000,44100"}else{"48000,44100,16000,8000"};json!({"deviceId":id,"deviceName":name,"serviceId":service_id,"serviceType":service_type,"properties":{"2003":rates,"2004":"1","2005":"12"},"status":{}})};
                        let mut payload=wire::uint(102)?;payload.extend(ascii_json(&service)?);self.business(3,u32::MAX,&payload)?;events.push(json!({"service_announced":service_type}));
                    }
                },_=>{},
            }
        }Ok(())
    }
    fn text(&mut self,m:&Message,now_us:u64,events:&mut Vec<Value>)->Result<()>{
        if let Some(index)=self.services.iter().position(|s|m.headers.get("serviceid").map(String::as_str)==Some(s.name)){
            if !self.negotiated{return Err("audio service before control negotiation".into());}
            if let Some((changes,replies))=self.services[index].receive(m)?{events.extend(changes);for reply in replies{self.send(&reply)?;}}return Ok(());
        }
        if self.speaker.is_some(){
            if m.headers.get("serviceid").map(String::as_str)==Some("speaker1")&&!self.negotiated{return Err("speaker before control negotiation".into());}
            if let Some((audio,replies))=self.speaker.as_mut().unwrap().receive(m)?{events.extend(audio);for reply in replies{self.send(&reply)?;}return Ok(());}
        }
        let h=&m.headers;
        if m.start=="SET_PARAMETER * DMSDP/1.0"&&h.contains_key("cryptoswitch"){
            if self.negotiated||h.get("cryptover").map(String::as_str)!=Some("1")||h.get("cryptoswitch").map(String::as_str)!=Some("222")||h.get("cryptoalg").map(String::as_str)!=Some(if self.crypto.is_some(){"aes128-ctr"}else{"null"})||!m.body.is_empty(){return Err("unsupported control negotiation".into());}
            let sequence=h.get("cseq").ok_or("missing negotiation sequence")?;seq(sequence)?;
            let packet=self.pack(&encode("DMSDP/1.0 200 OK",&[("CSeq",sequence.clone()),("CryptoVer","1".into()),("CryptoSwitch","222".into()),("CryptoAlg",h["cryptoalg"].clone()),("Platform","0".into())])?,true)?;self.queue(packet)?;self.negotiated=true;events.push(json!({"negotiated":true,"cipher":h["cryptoalg"]}));
        }else if m.start=="GET_PARAMETER * DMSDP/1.0"&&self.negotiated&&m.body.is_empty()&&h.len()==1&&h.contains_key("cseq"){seq(&h["cseq"])?;events.push(json!({"keepalive_received":true}));}
        else if m.start=="SET_PARAMETER * DMSDP/1.0"&&self.negotiated&&["timeserverport","timeushigh","timeuslow"].iter().all(|k|h.contains_key(*k)){
            let high=wrapped(&h["timeushigh"])?;let low=wrapped(&h["timeuslow"])?;let port=clock_port(&h["timeserverport"])?;let sequence=h.get("cseq").ok_or("missing peer clock sequence")?;seq(sequence)?;
            self.clock=Some(((high as u64)<<32|low as u64,now_us,port));self.send(&encode("DMSDP/1.0 200 OK",&[("CSeq",sequence.clone())])?)?;events.push(json!({"clock_initialized":true}));
        }Ok(())
    }
}


/// Synthetic codec interface. Runtime users keep this state behind private IPC.
pub fn differential(v:&Value)->Result<Value>{
    let key=super::unhex(v["key"].as_str().ok_or("missing synthetic DMSDP key")?)?;
    let mut session=Session::new(&key,v.get("device_info").cloned().unwrap_or(Value::Null),v["audio"]==true)?;
    let initial=super::hex(&session.initial()?);
    let steps=v["steps"].as_array().filter(|s|s.len()<=256).ok_or("invalid DMSDP transcript")?;let mut out=vec![];
    for step in steps{
        if let Some(ports)=step.get("ports"){
            let values=ports.as_array().filter(|p|p.len()==2).ok_or("invalid speaker port pair")?;
            let port:u16=values[0].as_u64().ok_or("invalid speaker RTP port")?.try_into().map_err(|_|"speaker RTP port overflow")?;
            let rtcp:i32=values[1].as_i64().ok_or("invalid speaker RTCP mode")?.try_into().map_err(|_|"speaker RTCP mode overflow")?;
            session.set_audio_ports((port,rtcp))?;
        }
        let mut events=vec![];let mut plaintexts=vec![];
        if let Some(data)=step.get("receive"){
            let (e,p)=session.receive(&super::unhex(data.as_str().ok_or("invalid DMSDP transcript bytes")?)?,step.get("now_us").and_then(Value::as_u64).unwrap_or(0),true)?;events=e;plaintexts=p;
        }
        let heartbeat=if step["heartbeat"]==true{Some(super::hex(&session.heartbeat()?))}else{None};
        if step["stop_audio"]==true{session.stop_audio()?;}
        out.push(json!({"events":events,"plaintexts":plaintexts.iter().map(|v|super::hex(v)).collect::<Vec<_>>(),"pending":session.pending().iter().map(|v|super::hex(v)).collect::<Vec<_>>(),"heartbeat":heartbeat,"state":session.state()}));
    }Ok(json!({"initial":initial,"steps":out}))
}

#[cfg(test)]mod tests{
    use super::*;
    #[test]fn retired_speaker_parameters_cannot_abort_the_replacement_session(){
        for (name,kind) in [("speaker1",3),("modemSpeaker",10)]{
            let mut speaker=Speaker::named(name,kind);speaker.session=Some(7);speaker.retire();speaker.session=Some(8);speaker.ready=true;
            for id in [7,6]{
                let raw=format!("SET_PARAMETER * DMSDP/1.0\r\nCSeq: 1\r\nServiceID: {name}\r\nServiceType: {kind}\r\nDataSessionID: {id}\r\nAudioParameter: SampleRate=48000;Format=16;ChannelNum=2;Codec=0\r\n\r\n");
                let parsed=Messages::new("DMSDP").feed(raw.as_bytes()).unwrap();let result=speaker.receive(&parsed[0]);
                if id==7{let(events,replies)=result.unwrap().unwrap();assert!(events.is_empty()&&replies.is_empty());assert_eq!(speaker.session,Some(8));assert!(speaker.ready);}else{assert!(result.is_err());}
            }
        }
    }
    #[test]fn stale_close_does_not_revoke_a_new_audio_session(){
        let mut speaker=Speaker::named("modemMic",9);speaker.session=Some(8);speaker.ready=true;
        let mut messages=Messages::new("DMSDP");
        for (id,expected) in [(7,false),(8,true)]{
            let body="msdp_trigger_method: CLOSE";
            let raw=format!("SET_PARAMETER * DMSDP/1.0\r\nCSeq: 1\r\nServiceID: modemMic\r\nServiceType: 9\r\nDataSessionID: {id}\r\nContent-Length: {}\r\n\r\n{body}",body.len());
            let parsed=messages.feed(raw.as_bytes()).unwrap();assert_eq!(parsed.len(),1);
            let (events,_)=speaker.receive(&parsed[0]).unwrap().unwrap();
            assert_eq!(!events.is_empty(),expected);
            if !expected{assert_eq!(speaker.session,Some(8));assert!(speaker.ready);}
        }
    }
    #[test]fn microphone_and_modem_services_are_explicit_and_authenticated(){
        let mut s=Session::new(&[],json!({"properties":{"5002":true}}),true).unwrap();assert_eq!(s.services.len(),3);
        s.set_audio_ports((41000,-1)).unwrap();
        let trigger=frame(b"SET_PARAMETER * DMSDP/1.0\r\nCSeq: 1\r\nServiceID: mic1\r\nServiceType: 2\r\nDataSessionID: 7\r\nSimple: 1\r\nContent-Length: 28\r\n\r\nmsdp_trigger_method: OPTIONS".to_vec(),false).unwrap();
        assert!(s.receive(&trigger,0,false).is_err());
        let mut s=Session::new(&[],json!({"properties":{"5002":true}}),true).unwrap();s.set_audio_ports((41000,-1)).unwrap();s.negotiated=true;
        let decoded=|packets:Vec<Vec<u8>>|->Vec<String>{packets.into_iter().map(|p|{let frames=Decoder::new(Format::Control).feed(&p).unwrap();String::from_utf8(frames[0].payload.clone()).unwrap()}).collect()};
        let (events,_)=s.receive(&trigger,0,false).unwrap();assert_eq!(events.last().unwrap()["microphone_setup_sent"],true);
        let options=decoded(s.pending()).pop().unwrap();assert!(options.starts_with("OPTIONS * DMSDP/1.0\r\n"));assert!(options.contains("Simple: 0\r\n"));assert!(!options.contains("Transport:"));
        let crypto=frame(b"SET_PARAMETER * DMSDP/1.0\r\nCSeq: 11\r\nServiceID: mic1\r\nServiceType: 2\r\nDataSessionID: 7\r\nCryptoVer: 1\r\nCryptoSwitch: 222\r\nCryptoAlg: aes128-ctr\r\nFillp: 0\r\nTCP: 0\r\n\r\n".to_vec(),false).unwrap();
        s.receive(&crypto,0,false).unwrap();let response=decoded(s.pending()).pop().unwrap();assert!(response.contains("CryptoVer: 1\r\n"));assert!(response.contains("CSeq: 11\r\n"));
        let setup=frame(b"SETUP * DMSDP/1.0\r\nCSeq: 12\r\nServiceID: mic1\r\nServiceType: 2\r\nDataSessionID: 7\r\nTransport: RTP/AVP/UDP;unicast;client_port=42000--1\r\n\r\n".to_vec(),false).unwrap();
        let(events,_)=s.receive(&setup,0,false).unwrap();assert!(events.iter().all(|e|e["microphone_ready"]!=true));
        let response=decoded(s.pending()).pop().unwrap();assert!(response.contains("client_port=42000--1;server_port=41000--1\r\n"));assert!(response.contains("CSeq: 12\r\n"));
        // A repeated SETUP must acknowledge the same endpoint without rewinding the state.
        s.receive(&setup,0,false).unwrap();assert_eq!(decoded(s.pending()).len(),1);
        let play=frame(b"PLAY * DMSDP/1.0\r\nCSeq: 13\r\nServiceID: mic1\r\nServiceType: 2\r\nDataSessionID: 7\r\n\r\n".to_vec(),false).unwrap();
        let (events,_)=s.receive(&play,0,false).unwrap();assert_eq!(events.last().unwrap()["microphone_ready"],true);assert_eq!(events.last().unwrap()["port"],42000);assert_eq!(events.last().unwrap()["session"],7);assert_eq!(decoded(s.pending()).len(),1);
        let(events,_)=s.receive(&play,0,false).unwrap();assert!(events.iter().all(|e|e["microphone_ready"]!=true));assert_eq!(decoded(s.pending()).len(),1);
        // A replacement retires the old session; old CLOSE/PLAY/triggers must not revoke it.
        let next=frame(b"SET_PARAMETER * DMSDP/1.0\r\nCSeq: 14\r\nServiceID: mic1\r\nServiceType: 2\r\nDataSessionID: 8\r\nSimple: 1\r\nContent-Length: 28\r\n\r\nmsdp_trigger_method: OPTIONS".to_vec(),false).unwrap();
        let(events,_)=s.receive(&next,0,false).unwrap();assert!(events.iter().any(|e|e["microphone_stopped"]==true));s.pending();
        s.receive(&trigger,0,false).unwrap();assert!(s.pending().is_empty());s.receive(&play,0,false).unwrap();assert!(s.pending().is_empty());assert_eq!(s.services[0].session,Some(8));
        s.stop_audio().unwrap();assert!(s.services.iter().all(|s|s.session.is_none()));
    }
    #[test]fn null_session_preserves_fragmentation_and_negotiation(){
        let mut s=Session::new(&[],Value::Null,false).unwrap();let wire=frame(b"SET_PARAMETER * DMSDP/1.0\r\nCSeq: 7\r\nCryptoVer: 1\r\nCryptoSwitch: 222\r\nCryptoAlg: null\r\n\r\n".to_vec(),false).unwrap();
        for part in wire.chunks(1){s.receive(part,9,false).unwrap();}assert_eq!(s.state()["negotiated"],true);assert_eq!(s.pending().len(),1);assert!(s.heartbeat().unwrap().starts_with(&[0]));
        assert!(s.receive(&[0,0,0],0,false).is_err());assert!(s.heartbeat().is_err());assert!(s.receive(&[],0,false).is_err());
    }
    #[test]fn private_json_escaping_and_clock_wrapping(){assert_eq!(ascii_json(&json!({"name":"车😀"})).unwrap(),b"{\"name\":\"\\u8f66\\ud83d\\ude00\"}");assert_eq!(wrapped("-1").unwrap(),u32::MAX);assert_eq!(wrapped("4_294_967_297").unwrap(),1);assert!(wrapped("1__0").is_err());}
    #[test]fn speaker_requires_negotiation_and_valid_rtp_ports(){let mut s=Session::new(&[],Value::Null,true).unwrap();assert!(s.set_audio_ports((1,0)).is_err());s.set_audio_ports((48000,-1)).unwrap();let packet=frame(b"SET_PARAMETER * DMSDP/1.0\r\nCSeq: 1\r\nServiceID: speaker1\r\nServiceType: 3\r\nDataSessionID: 1\r\nSimple: 1\r\nContent-Length: 28\r\n\r\nmsdp_trigger_method: OPTIONS".to_vec(),false).unwrap();assert!(s.receive(&packet,0,false).is_err());}
}
