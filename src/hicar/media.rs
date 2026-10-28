//! RTP/ADTS, clock mapping, PES assembly and unencrypted UIBC event bodies.
use super::Result;
use std::collections::BTreeMap;

const RATES:[u32;13]=[96000,88200,64000,48000,44100,32000,24000,22050,16000,12000,11025,8000,7350];
#[derive(Clone)]
pub struct Aac {pub data:Vec<u8>,pub rate:u32,pub channels:u8,pub samples:u32}
pub fn adts(data:&[u8])->Result<Vec<Aac>>{
    let mut offset=0;let mut out=Vec::new();
    while offset<data.len(){
        let h=data.get(offset..offset+7).ok_or("truncated ADTS header")?;
        if h[0]!=255||h[1]&0xf6!=0xf0{return Err("invalid ADTS header".into());}
        let rate=(h[2]>>2&15) as usize;let channels=(h[2]&1)<<2|h[3]>>6;
        let n=((h[3] as usize&3)<<11)|(h[4] as usize)<<3|(h[5] as usize)>>5;
        let header=if h[1]&1!=0{7}else{9};
        if rate>=RATES.len()||!matches!(channels,1|2)||n<=header||n>8191||n>data.len()-offset{return Err("unsupported or truncated ADTS frame".into());}
        out.push(Aac{data:data[offset..offset+n].to_vec(),rate:RATES[rate],channels,samples:1024*((h[6]&3) as u32+1)});offset+=n;
    }
    if out.is_empty(){return Err("empty AAC payload".into());}Ok(out)
}
pub struct Rtp {pub sequence:u16,pub timestamp:u32,pub stream:u32,pub frames:Vec<Aac>}
pub fn rtp(data:&[u8])->Result<Rtp>{
    if data.len()<12||data[0]>>6!=2||data[1]&127!=96{return Err("invalid audio RTP header".into());}
    let mut offset=12+4*(data[0]&15) as usize;let mut end=data.len();
    if offset>end{return Err("truncated RTP CSRC".into());}
    if data[0]&16!=0 {
        let ext=data.get(offset..offset+4).ok_or("truncated RTP extension")?;
        offset+=4+4*u16::from_be_bytes([ext[2],ext[3]]) as usize;
    }
    if data[0]&32!=0{let pad=data[end-1] as usize;if pad==0||offset>end||pad>end-offset{return Err("invalid RTP padding".into());}end-=pad;}
    if offset>=end{return Err("empty RTP payload".into());}
    Ok(Rtp{sequence:u16::from_be_bytes([data[2],data[3]]),timestamp:u32::from_be_bytes(data[4..8].try_into().unwrap()),
        stream:u32::from_be_bytes(data[8..12].try_into().unwrap()),frames:adts(&data[offset..end])?})
}
struct Stream {expected:u16,pending:BTreeMap<u16,(u32,Vec<Aac>)>,timestamp:Option<u32>,sample_offset:u64,rate:Option<u32>}
pub struct AudioFrame {pub aac:Aac,pub timestamp:u32,pub stream:u32,pub sample_offset:u64}
pub struct Audio {streams:BTreeMap<u32,Stream>,pub frames:u64,pub packets:u64,pub samples:u64,pub lost:u64,pub duplicates:u64}
impl Audio {
    pub fn new()->Self{Self{streams:BTreeMap::new(),frames:0,packets:0,samples:0,lost:0,duplicates:0}}
    pub fn receive(&mut self,data:&[u8])->Result<Vec<AudioFrame>>{
        let packet=rtp(data)?;let id=packet.stream&0xfff;
        if !self.streams.contains_key(&id){
            if self.streams.len()>=8{return Err("too many RTP sources".into());}
            self.streams.insert(id,Stream{expected:packet.sequence,pending:BTreeMap::new(),timestamp:None,sample_offset:0,rate:None});
        }
        let state=self.streams.get_mut(&id).unwrap();let distance=packet.sequence.wrapping_sub(state.expected);
        if distance>=32768||state.pending.contains_key(&packet.sequence){self.duplicates+=1;return Ok(vec![]);}
        if distance>16{self.lost+=distance as u64;state.expected=packet.sequence;state.pending.clear();}
        state.pending.insert(packet.sequence,(packet.timestamp,packet.frames));
        if state.pending.len()>=8&&!state.pending.contains_key(&state.expected){
            let nearest=*state.pending.keys().min_by_key(|n|n.wrapping_sub(state.expected)).unwrap();
            self.lost+=nearest.wrapping_sub(state.expected) as u64;state.expected=nearest;
        }
        let mut out=Vec::new();
        while let Some((timestamp,frames))=state.pending.remove(&state.expected){
            self.packets+=1;
            for aac in frames {
                if state.timestamp!=Some(timestamp)||state.rate!=Some(aac.rate){state.timestamp=Some(timestamp);state.rate=Some(aac.rate);state.sample_offset=0;}
                self.frames+=1;self.samples+=aac.samples as u64;
                let samples=aac.samples;
                out.push(AudioFrame{aac,timestamp,stream:id,sample_offset:state.sample_offset});state.sample_offset+=samples as u64;
            }state.expected=state.expected.wrapping_add(1);
        }Ok(out)
    }
}

pub fn local_rtp_time(timestamp:u32,now:u64,offset:i64,updated:u64)->Option<u64>{
    if now.saturating_sub(updated)>60_000_000{return None;}
    let peer=((now as i128+offset as i128)*90000).div_euclid(1000000);
    let delta=timestamp.wrapping_sub(peer as u32) as i32 as i128;
    ((peer+delta)*1000000).div_euclid(90000).checked_sub(offset as i128)?.try_into().ok()
}
pub fn touch(x:u16,y:u16,action:u8,elapsed:u32)->Result<Vec<u8>>{
    if x>=800||y>=480||action>2{return Err("invalid negotiated touch".into());}
    let mut out=vec![action,0,11,1,0];out.extend(x.to_be_bytes());out.extend(y.to_be_bytes());out.extend(elapsed.to_be_bytes());out.push(0);Ok(out)
}
pub fn key(name:&str,down:bool)->Result<Vec<u8>>{
    let code:u16=match name{"up"=>19,"down"=>20,"left"=>21,"right"=>22,"enter"=>23,"back"=>4,"home"=>3,"play_pause"=>85,"next"=>87,"previous"=>88,_=>return Err("unsupported input key".into())};
    let mut out=vec![if down{3}else{4},0,9,0];out.extend(code.to_be_bytes());out.extend([0;6]);Ok(out)
}

pub struct Video {parts:Vec<u8>,sequence:Option<u16>,timestamp:Option<u32>}
impl Video {
    pub fn new()->Self{Self{parts:Vec::new(),sequence:None,timestamp:None}}
    pub fn receive(&mut self,data:&[u8])->Result<Option<(u8,u32,Vec<u8>)>>{
        if data.len()<12||data[0]>>6!=2||data[0]&32!=0{return Err("invalid HiSight RTP header".into());}
        let kind=data[1]&127;if !matches!(kind,96..=98){return Err("invalid HiSight RTP type".into());}
        let sequence=u16::from_be_bytes([data[2],data[3]]);let timestamp=u32::from_be_bytes(data[4..8].try_into().unwrap());
        if self.sequence.is_some_and(|s|s.wrapping_add(1)!=sequence)||self.timestamp.is_some_and(|t|t!=timestamp){self.parts.clear();}
        self.sequence=Some(sequence);self.timestamp=Some(timestamp);
        let mut offset=12+4*(data[0]&15) as usize;
        if data[0]&16!=0{if kind==96{let ext=data.get(offset..offset+4).ok_or("truncated HiSight extension")?;offset+=4+u16::from_be_bytes([ext[2],ext[3]]) as usize;}else{offset+=1;}}
        if offset>=data.len()||self.parts.len()+data.len()-offset>2*1024*1024{return Err("invalid HiSight media size".into());}
        self.parts.extend(&data[offset..]);if data[1]&128==0{return Ok(None);}
        let pes=std::mem::take(&mut self.parts);
        if pes.len()<14||&pes[..3]!=b"\0\0\x01"||pes[6]!=0x84{return Err("invalid PES header".into());}
        let size=u16::from_be_bytes([pes[4],pes[5]]) as usize;
        if size!=0&&size+6!=pes.len(){return Err("invalid PES length".into());}
        let mut offset=14;if pes[7]&1!=0&&pes[8]!=0{offset+=pes[8] as usize+1;}
        if offset+16>=pes.len(){return Err("truncated encrypted ES".into());}
        Ok(Some((kind,timestamp,pes[offset..].to_vec())))
    }
}

#[cfg(test)]mod tests {
    use super::*;
    fn packet(seq:u16,ssrc:u32)->Vec<u8>{let mut p=vec![128,96];p.extend(seq.to_be_bytes());p.extend(100u32.to_be_bytes());p.extend(ssrc.to_be_bytes());p.extend([255,241,76,128,1,127,252,0,0,0,0]);p}
    #[test]fn usage_bits_reorder_wrap_and_same_timestamp(){
        let mut a=Audio::new();assert_eq!(a.receive(&packet(65535,0x1003eb)).unwrap()[0].sample_offset,0);
        assert!(a.receive(&packet(1,0x103eb)).unwrap().is_empty());let frames=a.receive(&packet(0,0x43eb)).unwrap();
        assert_eq!(frames.len(),2);assert_eq!(frames[0].sample_offset,1024);assert_eq!(frames[1].stream,1003);
        assert!(a.receive(&packet(1,1003)).unwrap().is_empty());assert_eq!((a.frames,a.lost,a.duplicates),(3,0,1));
    }
    #[test]fn invalid_adts_and_padding(){assert!(adts(&[]).is_err());let mut p=packet(0,1);p[0]|=32;*p.last_mut().unwrap()=0;assert!(rtp(&p).is_err());}
    #[test]fn clock_wrap_and_input(){let now=900000000000;let offset=123456789;let stamp=(((now+offset)*90000)/1000000) as u32;
        assert!(local_rtp_time(stamp,now,offset as i64,now).unwrap().abs_diff(now)<12);
        assert!(local_rtp_time(stamp,now+60000001,offset as i64,now).is_none());
        assert_eq!(touch(400,240,2,99).unwrap()[0],2);assert!(touch(800,1,0,0).is_err());assert_eq!(key("enter",false).unwrap()[0],4);
    }
}
