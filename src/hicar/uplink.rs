//! Bounded PCM16 microphone encoder and encrypted HiCar RTP packets.
use super::{Result,crypto::Crypto};
use std::{collections::VecDeque,io::{Read,Write,ErrorKind},path::Path,process::{Child,ChildStdin,ChildStdout,Command,Stdio},time::{Duration,Instant}};
use std::os::fd::AsRawFd;

// CarLife captures 16 kHz mono; HiCar mic1 negotiates AAC-LC at 48 kHz stereo.
const CAPTURE_RATE:u32=16000;
const ENCODED_RATE:u32=48000;
const RTP_RATE:u32=90000;
// HiCar's virtual microphone consumer opens AudioStream type 1100. The lower
// twelve RTP SSRC bits select that stream; a DMSDP DataSessionID is a separate
// control-plane identifier and must never be substituted here.
const MICROPHONE_STREAM:u32=1100;
fn rtp_timestamp(samples:u64)->u32{((samples as u128*RTP_RATE as u128/ENCODED_RATE as u128) & u32::MAX as u128) as u32}

fn monotonic_us()->u64{let mut t=libc::timespec{tv_sec:0,tv_nsec:0};unsafe{libc::clock_gettime(libc::CLOCK_MONOTONIC,&mut t);}t.tv_sec as u64*1_000_000+t.tv_nsec as u64/1000}
// Native QueueAACBuffer uses the capture timeUs on the shared 90 kHz clock,
// not a new zero-based audio timeline for each microphone activation.
// Native DataSession::AudioRecord adds GetTimeOffsetUs before packetization,
// so the on-wire clock belongs to the phone (peer), including signed offsets.
fn absolute_timestamp(origin_us:u64,samples:u64,peer_offset_us:i64)->u32{(((origin_us as i128+peer_offset_us as i128)*RTP_RATE as i128).div_euclid(1_000_000)as u32).wrapping_add(rtp_timestamp(samples))}

pub struct Uplink{
    child:Child,input:ChildStdin,output:ChildStdout,queue:VecDeque<(Vec<u8>,usize,Instant)>,encoded:Vec<u8>,
    pub generation:u64,pub port:u16,sequence:u16,samples:u64,origin_us:Option<u64>,
}
impl Drop for Uplink{fn drop(&mut self){let _=self.child.kill();let _=self.child.wait();}}
impl Uplink{
    pub fn new(binary:&Path,generation:u64,port:u16)->Result<Self>{
        if generation==0||port==0{return Err("invalid microphone generation or endpoint".into());}
        let capture_rate=CAPTURE_RATE.to_string();let encoded_rate=ENCODED_RATE.to_string();
        let mut child=Command::new(binary).args(["-hide_banner","-loglevel","error","-nostdin","-threads","1","-probesize","32","-analyzeduration","0","-f","s16le","-ar",capture_rate.as_str(),"-ac","1","-i","pipe:0","-vn","-threads","1","-ar",encoded_rate.as_str(),"-ac","2","-c:a","aac","-b:a","64000","-f","adts","-flush_packets","1","pipe:1"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|_|"cannot start microphone AAC encoder")?;
        let input=child.stdin.take().ok_or("missing microphone input")?;let output=child.stdout.take().ok_or("missing microphone output")?;
        for fd in [input.as_raw_fd(),output.as_raw_fd()]{let flags=unsafe{libc::fcntl(fd,libc::F_GETFL)};if flags<0||unsafe{libc::fcntl(fd,libc::F_SETFL,flags|libc::O_NONBLOCK)}<0{let _=child.kill();let _=child.wait();return Err("cannot configure microphone pipes".into());}}
        Ok(Self{child,input,output,queue:VecDeque::new(),encoded:vec![],generation,port,sequence:0,samples:0,origin_us:None})
    }
    pub fn feed(&mut self,generation:u64,data:Vec<u8>)->Result<()>{
        if generation!=self.generation{return Ok(());}
        if data.is_empty()||data.len()>16384||data.len()%2!=0{return Err("invalid microphone PCM".into());}
        if self.queue.len()>=6{
            // Capture bursts are normal after scheduler jitter. Drop an old
            // complete block, never revoke the negotiated microphone service.
            if let Some(i)=self.queue.iter().position(|(_,offset,_)|*offset==0){self.queue.remove(i);}else{return Ok(());}
        }
        if self.origin_us.is_none(){self.origin_us=Some(monotonic_us());}
        self.queue.push_back((data,0,Instant::now()));Ok(())
    }
    pub fn poll(&mut self,crypto:&Crypto,key:&[u8],peer_offset_us:i64)->Result<Vec<Vec<u8>>>{
        for _ in 0..6{
            let Some((data,offset,at))=self.queue.front_mut()else{break;};
            if at.elapsed()>Duration::from_millis(160)&&*offset==0{self.queue.pop_front();continue;}
            if at.elapsed()>Duration::from_secs(2){return Err("microphone encoder stalled".into());}
            match self.input.write(&data[*offset..]){Ok(0)=>return Err("microphone encoder closed".into()),Ok(n)=>{*offset+=n;if *offset==data.len(){self.queue.pop_front();}},Err(e)if e.kind()==ErrorKind::WouldBlock=>break,Err(_)=>return Err("microphone encoder input failed".into())}
        }
        let mut bytes=[0u8;4096];for _ in 0..4{match self.output.read(&mut bytes){Ok(0)=>return Err("microphone encoder ended".into()),Ok(n)=>{self.encoded.extend(&bytes[..n]);if self.encoded.len()>32768{return Err("microphone encoded buffer exceeded".into());}},Err(e)if e.kind()==ErrorKind::WouldBlock=>break,Err(_)=>return Err("microphone encoder output failed".into())}}
        let mut packets=vec![];
        while self.encoded.len()>=7{
            if self.encoded[0]!=255||self.encoded[1]&0xf6!=0xf0{return Err("invalid encoded microphone ADTS".into());}
            let n=((self.encoded[3]&3)as usize)<<11|(self.encoded[4]as usize)<<3|(self.encoded[5]as usize)>>5;
            if !(7..=1400).contains(&n){return Err("microphone AAC packet exceeds MTU".into());}if self.encoded.len()<n{break;}
            let aac=self.encoded.drain(..n).collect::<Vec<_>>();let frames=super::media::adts(&aac)?;
            if frames.len()!=1||frames[0].rate!=ENCODED_RATE||frames[0].channels!=2||frames[0].samples!=1024{return Err("unexpected microphone AAC format".into());}
            let now=monotonic_us();let elapsed=self.samples as u128*1_000_000/ENCODED_RATE as u128;
            if now as u128>self.origin_us.unwrap_or(now) as u128+elapsed+200_000{self.origin_us=Some(now.saturating_sub(elapsed.min(u64::MAX as u128)as u64));}
            let mut rtp=vec![0x80,96];rtp.extend(self.sequence.to_be_bytes());rtp.extend(absolute_timestamp(self.origin_us.ok_or("microphone has no capture clock")?,self.samples,peer_offset_us).to_be_bytes());rtp.extend(MICROPHONE_STREAM.to_be_bytes());rtp.extend(aac);
            self.sequence=self.sequence.wrapping_add(1);self.samples=self.samples.wrapping_add(frames[0].samples as u64);
            let mut iv=[0u8;16];std::fs::File::open("/dev/urandom").and_then(|mut f|f.read_exact(&mut iv)).map_err(|_|"microphone IV unavailable")?;
            let encrypted=crypto.transform(key,&iv,&rtp)?;let mut packet=vec![0xab];packet.extend(((16+encrypted.len())as u16).to_be_bytes());packet.extend(iv);packet.extend(encrypted);packets.push(packet);
        }Ok(packets)
    }
}

#[cfg(test)]mod tests{
    use super::*;
    #[test]fn encoded_audio_clock_uses_output_samples_and_wraps(){
        assert_eq!(MICROPHONE_STREAM,1100);assert_eq!(CAPTURE_RATE,16000);assert_eq!(ENCODED_RATE,48000);
        assert_eq!(absolute_timestamp(123_000_000,0,0),11_070_000);
        assert_eq!(absolute_timestamp(123_000_000,1024,0).wrapping_sub(absolute_timestamp(123_000_000,0,0)),1920);
        assert_eq!(absolute_timestamp(123_000_000,0,2_000_000),11_250_000);
        assert_eq!(absolute_timestamp(123_000_000,0,-2_000_000),10_890_000);
        assert_eq!(absolute_timestamp(0,0,-1_000_000),0u32.wrapping_sub(90000));
        assert_eq!(rtp_timestamp(0),0);assert_eq!(rtp_timestamp(1024),1920);
        assert_eq!(rtp_timestamp(48000),90000);
        assert_eq!(rtp_timestamp(u64::MAX),((u64::MAX as u128*90000/48000)&u32::MAX as u128)as u32);
    }
}
