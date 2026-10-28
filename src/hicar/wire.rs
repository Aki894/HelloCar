//! Independent Nearby, DMSDP and HiSight framing. Never resync inside payload.
use super::Result;
use std::collections::BTreeMap;
pub const MAX_PAYLOAD: usize = 65536;
pub const MAX_UINT: u32 = (1<<28)-1;

pub fn uint(mut n: u32) -> Result<Vec<u8>> {
    if n>MAX_UINT {return Err("integer exceeds 28 bits".into());}
    let mut out=Vec::new();
    while n>=128 {out.push((n&127) as u8);n>>=7;}
    out.push(n as u8|128);Ok(out)
}
// None is a valid incomplete prefix, distinct from malformed input.
pub fn read_uint(data:&[u8], pos:&mut usize)->Result<Option<u32>> {
    let mut n=0;
    for shift in (0..28).step_by(7) {
        let Some(&b)=data.get(*pos) else{return Ok(None);};
        *pos+=1;n|=((b&127) as u32)<<shift;
        if b&128!=0 {return Ok(Some(n));}
    }
    Err("unterminated integer".into())
}
pub fn crc16(data:&[u8])->u16 {
    let mut crc=0u16;
    for &b in data {crc^=b as u16;for _ in 0..8{crc=(crc>>1)^if crc&1!=0{0xa001}else{0};}}
    crc
}
pub fn tlv(tag:u32,value:&[u8])->Result<Vec<u8>> {
    if value.len()>MAX_PAYLOAD {return Err("TLV exceeds limit".into());}
    let mut out=uint(tag)?;out.extend(uint(value.len() as u32)?);out.extend(value);Ok(out)
}
pub fn tlvs(data:&[u8])->Result<Vec<(u32,Vec<u8>)>> {
    let mut pos=0;let mut out=Vec::new();
    while pos<data.len() {
        let tag=read_uint(data,&mut pos)?.ok_or("truncated TLV tag")?;
        let size=read_uint(data,&mut pos)?.ok_or("truncated TLV length")? as usize;
        if size>MAX_PAYLOAD || size>data.len()-pos {return Err("invalid TLV value length".into());}
        out.push((tag,data[pos..pos+size].to_vec()));pos+=size;
    }
    Ok(out)
}

#[derive(Clone,Copy)]
pub enum Format { Nearby, Module, Control, HiSight }
#[derive(PartialEq,Eq)]
pub struct Frame {pub kind:u32,pub flags:u32,pub options:Vec<u8>,pub payload:Vec<u8>}
impl std::fmt::Debug for Frame{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{
    f.debug_struct("Frame").field("kind",&self.kind).field("flags",&self.flags)
        .field("option_bytes",&self.options.len()).field("payload_bytes",&self.payload.len()).finish()
}}
impl Frame {
    pub fn encode(&self,format:Format)->Result<Vec<u8>> {
        let size=self.payload.len();
        let mut out=match format {
            Format::Nearby|Format::Module=>{
                if size>MAX_PAYLOAD || self.options.len()>256 {return Err("frame exceeds limit".into());}
                let mut v=vec![0x7f];v.extend(uint(self.kind)?);
                if matches!(format,Format::Nearby){v.extend(uint(self.flags)?);v.extend(uint(self.options.len() as u32)?);v.extend(&self.options);}
                v.extend(uint(size as u32)?);v
            },
            Format::Control=>{
                if !matches!(self.kind,0|0xab) || !(1..1498).contains(&size){return Err("invalid control frame".into());}
                let mut v=vec![self.kind as u8];v.extend((size as u16).to_be_bytes());v
            },
            Format::HiSight=>{
                if !(1..=2*1024*1024).contains(&size){return Err("invalid HiSight record".into());}
                (size as u32).to_be_bytes().to_vec()
            },
        };
        out.extend(&self.payload);
        if matches!(format,Format::Nearby|Format::Module){out.extend(crc16(&out).to_le_bytes());}
        Ok(out)
    }
}
pub struct Decoder {format:Format, buffer:Vec<u8>, failed:bool}
impl Decoder {
    pub fn new(format:Format)->Self {Self{format,buffer:Vec::new(),failed:false}}
    fn take(&self)->Result<Option<(Frame,usize)>> {
        let d=&self.buffer;
        if d.is_empty(){return Ok(None);}
        let mut pos=1;let mut flags=0;let mut options=Vec::new();
        let (kind,length,checksum)=match self.format {
            Format::Nearby|Format::Module=>{
                if d[0]!=0x7f{return Err("invalid Nearby marker".into());}
                let Some(kind)=read_uint(d,&mut pos)? else{return Ok(None);};
                if matches!(self.format,Format::Nearby){
                    let Some(f)=read_uint(d,&mut pos)? else{return Ok(None);};flags=f;
                    let Some(size)=read_uint(d,&mut pos)? else{return Ok(None);};let size=size as usize;
                    if size>256{return Err("options exceed limit".into());}
                    if d.len()-pos<size{return Ok(None);}
                    options.extend(&d[pos..pos+size]);pos+=size;
                }
                let Some(n)=read_uint(d,&mut pos)? else{return Ok(None);};
                if n as usize>MAX_PAYLOAD{return Err("payload exceeds limit".into());}
                (kind,n as usize,true)
            },
            Format::Control=>{
                if !matches!(d[0],0|0xab){return Err("invalid control marker".into());}
                if d.len()<3{return Ok(None);}
                pos=3;let n=u16::from_be_bytes([d[1],d[2]]) as usize;
                if !(1..1498).contains(&n){return Err("invalid control size".into());}
                (d[0] as u32,n,false)
            },
            Format::HiSight=>{
                if d.len()<4{return Ok(None);}
                pos=4;let n=u32::from_be_bytes(d[..4].try_into().unwrap()) as usize;
                if !(1..=2*1024*1024).contains(&n){return Err("invalid HiSight size".into());}
                (0,n,false)
            },
        };
        let end=pos+length;let total=end+if checksum{2}else{0};
        if d.len()<total{return Ok(None);}
        if checksum && crc16(&d[..end])!=u16::from_le_bytes([d[end],d[end+1]]){return Err("CRC mismatch".into());}
        Ok(Some((Frame{kind,flags,options,payload:d[pos..end].to_vec()},total)))
    }
    pub fn feed(&mut self,data:&[u8])->Result<Vec<Frame>> {
        if self.failed{return Err("decoder requires reset".into());}
        let mut result=Vec::new();
        let parsed=(||{
            for chunk in data.chunks(4096){
                self.buffer.extend(chunk);
                while let Some((frame,n))=self.take()?{result.push(frame);self.buffer.drain(..n);}
            }
            Ok(result)
        })();
        if parsed.is_err(){self.failed=true;self.buffer.clear();}
        parsed
    }
    pub fn finish(&self)->Result<()> {if self.failed||!self.buffer.is_empty(){Err("incomplete or failed stream".into())}else{Ok(())}}
}

#[derive(PartialEq,Eq)]
pub struct Message {pub start:String,pub headers:BTreeMap<String,String>,pub body:Vec<u8>}
impl std::fmt::Debug for Message{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{
    f.debug_struct("Message").field("method",&self.start.split(' ').next().unwrap_or(""))
        .field("header_names",&self.headers.keys().collect::<Vec<_>>()).field("body_bytes",&self.body.len()).finish()
}}
pub struct Messages {protocol:&'static str,buffer:Vec<u8>,failed:bool}
fn header_name(s:&str)->bool {
    !s.is_empty() && s.len()<=64 && s.as_bytes()[0].is_ascii_alphabetic()
        && s.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-')
}
impl Messages {
    pub fn new(protocol:&'static str)->Self{Self{protocol,buffer:Vec::new(),failed:false}}
    fn take(&self)->Result<Option<(Message,usize)>> {
        let Some(end)=self.buffer.windows(4).position(|v|v==b"\r\n\r\n") else{
            return if self.buffer.len()>8192{Err("control header exceeds limit".into())}else{Ok(None)};
        };
        if end>8192 || !self.buffer[..end].is_ascii(){return Err("invalid control header".into());}
        let header=std::str::from_utf8(&self.buffer[..end]).map_err(|_|"invalid text header")?;
        let mut rows=header.split("\r\n");let start=rows.next().unwrap();
        let tokens:Vec<_>=start.split(' ').collect();let version=format!("{}/1.0",self.protocol);
        let request=tokens.len()==3 && !tokens[0].is_empty() && tokens[0].bytes().all(|b|b.is_ascii_uppercase()||b==b'_')
            && !tokens[1].is_empty() && !tokens[1].bytes().any(|b|b.is_ascii_whitespace()) && tokens[2]==version;
        let response=start.strip_prefix(&(version+" ")).is_some_and(|tail|{
            tail.len()>=3 && matches!(tail.as_bytes()[0],b'1'..=b'5') && tail.as_bytes()[1..3].iter().all(u8::is_ascii_digit)
                && (tail.len()==3 || tail.as_bytes()[3]==b' ' && tail.len()>4 && tail.as_bytes()[4..].iter().all(|b|(32..=126).contains(b)))
        });
        if !request&&!response{return Err("invalid control start line".into());}
        let mut headers=BTreeMap::new();
        for row in rows {
            let (key,value)=row.split_once(':').ok_or("invalid header row")?;
            if !header_name(key)||headers.len()>=64 || headers.insert(key.to_ascii_lowercase(),value.trim().to_owned()).is_some(){return Err("duplicate or invalid header".into());}
        }
        let length=headers.get("content-length").map(String::as_str).unwrap_or("0");
        if length.is_empty()||length.len()>5||!length.bytes().all(|b|b.is_ascii_digit()){return Err("invalid content length".into());}
        let length:usize=length.parse().map_err(|_|"invalid content length")?;
        if length>MAX_PAYLOAD{return Err("control body exceeds limit".into());}
        let n=end+4+length;if self.buffer.len()<n{return Ok(None);}
        Ok(Some((Message{start:start.into(),headers,body:self.buffer[end+4..n].to_vec()},n)))
    }
    pub fn feed(&mut self,data:&[u8])->Result<Vec<Message>>{
        if self.failed{return Err("message decoder requires reset".into());}
        let parsed=(||{let mut out=Vec::new();for chunk in data.chunks(4096){self.buffer.extend(chunk);
            while let Some((m,n))=self.take()?{out.push(m);self.buffer.drain(..n);}
        }Ok(out)})();
        if parsed.is_err(){self.failed=true;self.buffer.clear();}parsed
    }
    pub fn finish(&self)->Result<()>{if self.failed||!self.buffer.is_empty(){Err("incomplete message stream".into())}else{Ok(())}}
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn framing_splits_crc_and_fail_closed(){
        assert_eq!(crc16(b"123456789"),0xbb3d);
        for format in [Format::Nearby,Format::Module,Format::Control,Format::HiSight]{
            let f=Frame{kind:if matches!(format,Format::Control){0xab}else{3},flags:1,options:vec![],payload:vec![7;130]};
            let wire=f.encode(format).unwrap();for split in 0..=wire.len(){let mut d=Decoder::new(format);
                let mut frames=d.feed(&wire[..split]).unwrap();frames.extend(d.feed(&wire[split..]).unwrap());d.finish().unwrap();assert_eq!(frames.len(),1);assert_eq!(frames[0].payload,f.payload);
            }
        }
        let mut d=Decoder::new(Format::Nearby);assert!(d.feed(&[1]).is_err());assert!(d.feed(&[]).is_err());
    }
    #[test] fn integers_tlv_and_truncation(){
        for n in [0,127,128,16384,MAX_UINT]{let mut p=0;assert_eq!(read_uint(&uint(n).unwrap(),&mut p).unwrap(),Some(n));}
        assert!(uint(MAX_UINT+1).is_err());assert!(read_uint(&[0;4],&mut 0).is_err());
        assert_eq!(tlvs(&tlv(4,b"test").unwrap()).unwrap(),vec![(4,b"test".to_vec())]);assert!(tlvs(&[0x81]).is_err());
    }
    #[test] fn text_rejects_duplicates_and_truncation(){
        let data=b"SETUP * RTSP/1.0\r\nCSeq: 2\r\nContent-Length: 2\r\n\r\n{}";
        for split in 0..=data.len(){let mut d=Messages::new("RTSP");let mut m=d.feed(&data[..split]).unwrap();m.extend(d.feed(&data[split..]).unwrap());d.finish().unwrap();assert_eq!(m[0].body,b"{}");}
        let mut d=Messages::new("DMSDP");assert!(d.feed(b"OPTIONS * DMSDP/1.0\r\nX: 1\r\nx: 2\r\n\r\n").is_err());assert!(d.feed(&[]).is_err());
    }
}
