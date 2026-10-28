//! Stateful encrypted HiSight RTSP. Network/media IO stays in the adapter.
use super::{Result,crypto::{Crypto,wipe},wire::Messages,hex,unhex};
use serde_json::{Value,json};
use std::{collections::BTreeMap,io::Read};

const LIMIT:usize=65000;
fn sequence(s:&str)->Result<()>{if s.is_empty()||s.len()>9||!s.bytes().all(|b|b.is_ascii_digit()){Err("invalid HiSight sequence".into())}else{Ok(())}}
fn message(start:&str,seq:&str,body:&[u8],headers:&[(&str,String)])->Result<Vec<u8>>{
    sequence(seq)?;let mut out=format!("{start}\r\nCSeq: {seq}\r\n");
    for (name,value) in headers{if !value.is_ascii()||value.bytes().any(|b|matches!(b,0|10|13)){return Err("invalid HiSight header".into());}out.push_str(&format!("{name}: {value}\r\n"));}
    if !body.is_empty(){out.push_str(&format!("Content-Type: text/parameters\r\nContent-Length: {}\r\n",body.len()));}
    out.push_str("\r\n");let mut bytes=out.into_bytes();bytes.extend(body);Ok(bytes)
}
fn metadata(m:&super::wire::Message)->Value{
    let mut out=json!({"method":m.start.split(' ').next().unwrap_or(""),"header_names":m.headers.keys().collect::<Vec<_>>(),"body_bytes":m.body.len()});
    for name in ["cseq","cryptover","cryptoability","cryptoswitch","udpka","lowdelay"]{
        if let Some(v)=m.headers.get(name).filter(|v|sequence(v).is_ok()){out[name]=v.parse::<u32>().unwrap().into();}
    }out
}
fn record_message(payload:&[u8])->Result<super::wire::Message>{
    let split=payload.windows(4).position(|p|p==b"\r\n\r\n");
    let (head,body)=match split{Some(n)=>(&payload[..n],&payload[n+4..]),None=>{
        let mut end=payload.len();while end>0&&matches!(payload[end-1],b'\r'|b'\n'){end-=1;}(&payload[..end],&[][..])
    }};
    if head.len()>8192||!head.is_ascii(){return Err("invalid HiSight header".into());}
    // The observed source omits ANNOUNCE Content-Length and miscounts SETUP
    // Transport as body. Only this explicitly length-delimited protocol uses
    // the outer record's body boundary; DMSDP retains strict Content-Length.
    let text=std::str::from_utf8(head).map_err(|_|"invalid HiSight text")?;
    let mut normalized=String::new();
    for row in text.split("\r\n").filter(|s|!s.is_empty()&&!s.to_ascii_lowercase().starts_with("content-length:")){normalized.push_str(row);normalized.push_str("\r\n");}
    normalized.push_str(&format!("Content-Length: {}\r\n\r\n",body.len()));
    let mut bytes=normalized.into_bytes();bytes.extend(body);let mut parser=Messages::new("RTSP");
    let mut messages=parser.feed(&bytes)?;parser.finish()?;
    if messages.len()!=1{return Err("invalid HiSight message count".into());}Ok(messages.remove(0))
}
fn port(transport:&str,name:&str)->Option<u16>{transport.split(';').find_map(|field|{
    let (key,value)=field.split_once('=')?;
    if key!=name||value.is_empty()||!value.bytes().all(|b|b.is_ascii_digit()){return None;}
    value.parse::<u16>().ok().filter(|p|*p!=0)
})}

pub struct Session{
    key:Vec<u8>,crypto:Crypto,buffer:Vec<u8>,failed:bool,pending:Vec<Vec<u8>>,
    encrypted:bool,options_sent:bool,target:String,sequence:u32,setup:Option<u32>,
    media:Option<u16>,input:Option<u16>,peer_teardown:bool,teardown:Option<u32>,acknowledged:bool,
}
impl Drop for Session{fn drop(&mut self){wipe(&mut self.key);wipe(&mut self.buffer);}}
impl Session{
    pub fn new(key:&[u8])->Result<Self>{
        if !matches!(key.len(),16|32){return Err("invalid authenticated HiSight key".into());}
        Ok(Self{key:key[..16].to_vec(),crypto:Crypto::load()?,buffer:vec![],failed:false,pending:vec![],encrypted:false,options_sent:false,target:"*".into(),sequence:2,setup:None,media:None,input:None,peer_teardown:false,teardown:None,acknowledged:false})
    }
    fn pack(&self,data:&[u8],plain:bool)->Result<Vec<u8>>{
        if self.failed{return Err("HiSight session requires reset".into());}
        let payload=if self.encrypted&&!plain{
            let mut iv=[0u8;16];std::fs::File::open("/dev/urandom").and_then(|mut f|f.read_exact(&mut iv)).map_err(|_|"cannot obtain HiSight IV")?;
            let mut payload=iv.to_vec();payload.extend(self.crypto.transform(&self.key,&iv,data)?);payload
        }else{data.to_vec()};
        if payload.is_empty()||payload.len()>LIMIT{return Err("HiSight record exceeds limit".into());}
        let mut out=(payload.len() as u32).to_be_bytes().to_vec();out.extend(payload);Ok(out)
    }
    pub fn initial(&self)->Result<Vec<u8>>{self.pack(&message("ANNOUNCE * RTSP/1.0","1",b"encrypt_description: encrypt_list=aes128ctr;version=1\r\n",&[])?,true)}
    fn queue(&mut self,data:Vec<u8>,plain:bool)->Result<()>{
        if self.pending.len()>=64{return Err("HiSight response queue exceeds limit".into());}
        self.pending.push(self.pack(&data,plain)?);Ok(())
    }
    pub fn request(&mut self,method:&str)->Result<u32>{
        if !self.encrypted||self.peer_teardown||!matches!(method,"SETUP"|"PLAY"){return Err("invalid HiSight request state".into());}
        self.sequence=self.sequence.checked_add(1).filter(|n|*n<=999999999).ok_or("HiSight sequence exhausted")?;
        self.queue(message(&format!("{method} {} RTSP/1.0",self.target),&self.sequence.to_string(),&[],&[("Transport","RTP/AVP/UDP;unicast;client_port=0".into())])?,false)?;Ok(self.sequence)
    }
    pub fn teardown(&mut self)->Result<Option<Vec<u8>>>{
        if !self.encrypted||self.media.is_none()||self.peer_teardown||self.teardown.is_some()||self.failed{return Ok(None);}
        self.sequence=self.sequence.checked_add(1).filter(|n|*n<=999999999).ok_or("HiSight sequence exhausted")?;
        self.teardown=Some(self.sequence);self.pack(&message(&format!("TEARDOWN {} RTSP/1.0",self.target),&self.sequence.to_string(),&[],&[])?,false).map(Some)
    }
    pub fn state(&self)->Value{json!({"encrypted":self.encrypted,"media_endpoint":self.media,"input_endpoint":self.input,"setup_sequence":self.setup,"peer_teardown":self.peer_teardown,"teardown_acknowledged":self.acknowledged})}
    pub fn pending(&mut self)->Vec<Vec<u8>>{std::mem::take(&mut self.pending)}
    pub fn receive(&mut self,data:&[u8],capture:bool)->Result<(Vec<Value>,Vec<Vec<u8>>)>{
        if self.failed{return Err("HiSight session requires reset".into());}
        if data.len()>65536{return Err("HiSight input chunk exceeds limit".into());}
        let result=self.receive_inner(data,capture);
        if result.is_err(){self.failed=true;wipe(&mut self.buffer);self.buffer.clear();self.pending.clear();self.media=None;self.input=None;}
        result
    }
    fn receive_inner(&mut self,data:&[u8],capture:bool)->Result<(Vec<Value>,Vec<Vec<u8>>)>{
        let mut events=vec![];let mut plaintexts=vec![];let mut count=0;
        for chunk in data.chunks(4096){self.buffer.extend(chunk);
            while self.buffer.len()>=4{
                let size=u32::from_be_bytes(self.buffer[..4].try_into().unwrap()) as usize;
                if size==0||size>LIMIT{return Err("invalid HiSight record length".into());}
                if self.buffer.len()<size+4{break;}
                count+=1;if count>64{return Err("too many HiSight records".into());}
                let payload=if self.encrypted{
                    if size<=16{return Err("invalid encrypted HiSight record".into());}
                    self.crypto.transform(&self.key,&self.buffer[4..20],&self.buffer[20..size+4])?
                }else{self.buffer[4..size+4].to_vec()};
                self.buffer.drain(..size+4);let m=record_message(&payload)?;
                if capture{plaintexts.push(payload);}events.push(metadata(&m));
                let seq=m.headers.get("cseq").ok_or("missing HiSight sequence")?;sequence(seq)?;
                let method=m.start.split(' ').next().unwrap_or("");
                match method{
                    "ANNOUNCE"=>{
                        if self.encrypted||!m.body.windows(9).any(|v|v==b"aes128ctr"){return Err("unsupported HiSight encryption negotiation".into());}
                        self.queue(message("RTSP/1.0 200 OK",seq,&[],&[])?,true)?;self.encrypted=true;events.push(json!({"hisight_encryption":true}));
                    },
                    _ if !self.encrypted&&method!="RTSP/1.0"=>return Err("HiSight message before encryption negotiation".into()),
                    "OPTIONS"=>{
                        self.queue(message("RTSP/1.0 200 OK",seq,&[],&[("Public","hisight1.0, GET_PARAMETER, SET_PARAMETER".into())])?,false)?;
                        if !self.options_sent{self.queue(message("OPTIONS * RTSP/1.0","2",&[],&[("Require","hisight1.0".into())])?,false)?;self.options_sent=true;}
                    },
                    "GET_PARAMETER"=>{
                        let body=std::str::from_utf8(&m.body).map_err(|_|"invalid HiSight capability request")?;
                        if !body.is_ascii(){return Err("invalid HiSight capability request".into());}
                        let requested:std::collections::BTreeSet<_>=body.lines().filter(|l|!l.trim().is_empty()).map(|l|l.split(':').next().unwrap().trim()).collect();
                        let capabilities=[("his_version","1.0"),("his_video_formats","codecs 1;fps 30;gop 30;bitrate 2000000;vbr-min 1000000;vbr-max 3000000;dpi 160;scr-w 800;scr-h 480;width 800;height 480"),("his_audio_codecs","1"),("his_device_type","device_type 4;subtype 0;"),("his_uibc_capability","input_category_list=GENERIC;generic_cap_list=left_point_down, left_point_up, left_move, left_key_down, left_key_up;")];
                        let body=capabilities.iter().filter(|(k,_)|requested.contains(k)).map(|(k,v)|format!("{k}: {v}\r\n")).collect::<String>();
                        self.queue(message("RTSP/1.0 200 OK",seq,body.as_bytes(),&[])?,false)?;events.push(json!({"capabilities_replied":true,"requested":requested}));
                    },
                    "SET_PARAMETER"=>{
                        let body=std::str::from_utf8(&m.body).map_err(|_|"invalid HiSight parameters")?;
                        if !body.is_ascii(){return Err("invalid HiSight parameters".into());}
                        let parameters:BTreeMap<_,_>=body.lines().filter_map(|l|l.split_once(':')).map(|(k,v)|(k.trim().to_ascii_lowercase(),v.trim())).collect();
                        events.push(json!({"parameter_names":parameters.keys().collect::<Vec<_>>()}));
                        self.queue(message("RTSP/1.0 200 OK",seq,&[],&[])?,false)?;
                        if let Some(value)=parameters.get("his_presentation_url"){
                            let target=value.split_whitespace().next().ok_or("invalid HiSight presentation URL")?;
                            let suffix=target.strip_prefix("rtsp://").ok_or("invalid HiSight presentation URL")?;
                            if suffix.is_empty()||suffix.len()>256||!suffix.bytes().all(|b|b.is_ascii_alphanumeric()||b".:/_?=&%-".contains(&b)){return Err("invalid HiSight presentation URL".into());}
                            self.target=target.into();
                        }
                        if parameters.get("his_trigger_method")==Some(&"SETUP"){self.setup=Some(self.request("SETUP")?);}
                        else if parameters.get("his_trigger_method")==Some(&"TEARDOWN"){self.peer_teardown=true;}
                    },
                    "TEARDOWN"=>{self.queue(message("RTSP/1.0 200 OK",seq,&[],&[])?,false)?;self.peer_teardown=true;},
                    "RTSP/1.0" if self.teardown.is_some_and(|n|seq==&n.to_string())=>{self.acknowledged=m.start.starts_with("RTSP/1.0 200 ");},
                    "RTSP/1.0" if self.setup.is_some_and(|n|seq==&n.to_string())=>{
                        if !m.start.starts_with("RTSP/1.0 200 "){return Err("HiSight setup refused".into());}
                        let transport=m.headers.get("transport").ok_or("missing HiSight media port")?;
                        self.media=Some(port(transport,"server_port").ok_or("missing HiSight media port")?);self.input=port(transport,"remotectl_port");events.push(json!({"media_port":self.media}));
                    },_=>{},
                }
            }
        }Ok((events,plaintexts))
    }
}

pub fn differential(v:&Value)->Result<Value>{
    let key=unhex(v["key"].as_str().ok_or("missing synthetic key")?)?;let mut session=Session::new(&key)?;
    let steps=v["steps"].as_array().filter(|v|v.len()<=256).ok_or("invalid HiSight transcript")?;let mut out=vec![];
    for step in steps{
        let mut events=vec![];let mut plaintexts=vec![];
        if let Some(data)=step.get("receive"){let (e,p)=session.receive(&unhex(data.as_str().ok_or("invalid HiSight transcript bytes")?)?,true)?;events=e;plaintexts=p;}
        let teardown=if step["teardown"]==true{session.teardown()?}else{None};
        if step["play"]==true{session.request("PLAY")?;}
        out.push(json!({"events":events,"plaintexts":plaintexts.iter().map(|v|hex(v)).collect::<Vec<_>>(),"pending":session.pending().iter().map(|v|hex(v)).collect::<Vec<_>>(),"teardown":teardown.map(|v|hex(&v)),"state":session.state()}));
    }Ok(json!({"steps":out}))
}
