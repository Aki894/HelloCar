//! HiCar media IO owner. Only configuration/statistics use private JSON IPC.
#[cfg(unix)]
mod unix {
use super::super::{Result,crypto::{Crypto,wipe},media,unhex};
use serde_json::{Value,json};
use std::{collections::{VecDeque,BTreeSet,BTreeMap},io::{Read,Write,ErrorKind},net::{Ipv4Addr,SocketAddrV4,TcpStream,UdpSocket},
    os::{fd::{AsRawFd,FromRawFd,OwnedFd},unix::net::UnixStream},path::{Path,PathBuf},process::{Child,ChildStdin,ChildStdout,Command,Stdio},time::{Duration,Instant}};

const MAX_VIDEO:usize=512*1024;
const MAX_RTP:usize=2*1024*1024;
const MAX_QUEUE:usize=1024*1024;
const PCM:usize=3528;
const IPC_LIMIT:usize=65536;
fn now_us()->u64{let mut t=libc::timespec{tv_sec:0,tv_nsec:0};unsafe{libc::clock_gettime(libc::CLOCK_MONOTONIC,&mut t);}t.tv_sec as u64*1_000_000+t.tv_nsec as u64/1000}
fn nonblocking(fd:i32)->Result<()>{let flags=unsafe{libc::fcntl(fd,libc::F_GETFL)};if flags<0||unsafe{libc::fcntl(fd,libc::F_SETFL,flags|libc::O_NONBLOCK)}<0{Err("cannot make media IO nonblocking".into())}else{Ok(())}}
fn string<'a>(v:&'a Value,k:&str)->Result<&'a str>{v[k].as_str().ok_or_else(||format!("missing media field {k}"))}
fn port(v:&Value,k:&str)->Result<u16>{v[k].as_u64().and_then(|v|u16::try_from(v).ok()).filter(|v|*v!=0).ok_or_else(||format!("invalid media port {k}"))}
fn absolute(v:&Value,k:&str)->Result<PathBuf>{let s=string(v,k)?;let p=PathBuf::from(s);if s.len()>4096||s.contains('\0')||!p.is_absolute(){return Err("invalid media path".into());}Ok(p)}
fn encrypt(crypto:&Crypto,key:&[u8],plain:&[u8])->Result<Vec<u8>>{let mut iv=[0;16];std::fs::File::open("/dev/urandom").and_then(|mut f|f.read_exact(&mut iv)).map_err(|_|"media IV unavailable")?;let mut out=iv.to_vec();out.extend(crypto.transform(key,&iv,plain)?);Ok(out)}
fn decrypt(crypto:&Crypto,key:&[u8],record:&[u8])->Result<Vec<u8>>{if record.len()<=16{return Err("truncated encrypted media record".into());}crypto.transform(key,&record[..16],&record[16..])}
fn connect(local:Ipv4Addr,peer:Ipv4Addr,port:u16,timeout:Duration)->Result<TcpStream>{
    let raw=unsafe{libc::socket(libc::AF_INET,libc::SOCK_STREAM|libc::SOCK_NONBLOCK|libc::SOCK_CLOEXEC,0)};
    if raw<0{return Err("cannot allocate media socket".into());}let fd=unsafe{OwnedFd::from_raw_fd(raw)};
    let addr=|ip:Ipv4Addr,port:u16|libc::sockaddr_in{sin_family:libc::AF_INET as u16,sin_port:port.to_be(),sin_addr:libc::in_addr{s_addr:u32::from_ne_bytes(ip.octets())},sin_zero:[0;8]};
    let own=addr(local,0);if unsafe{libc::bind(fd.as_raw_fd(),&own as *const _ as *const libc::sockaddr,std::mem::size_of_val(&own) as libc::socklen_t)}!=0{return Err("cannot bind media source address".into());}
    let remote=addr(peer,port);let code=unsafe{libc::connect(fd.as_raw_fd(),&remote as *const _ as *const libc::sockaddr,std::mem::size_of_val(&remote) as libc::socklen_t)};
    if code!=0{
        if std::io::Error::last_os_error().raw_os_error()!=Some(libc::EINPROGRESS){return Err("media connection refused".into());}
        let mut p=libc::pollfd{fd:fd.as_raw_fd(),events:libc::POLLOUT,revents:0};
        if unsafe{libc::poll(&mut p,1,timeout.as_millis().min(i32::MAX as u128) as i32)}<=0{return Err("media connection timeout".into());}
        let mut error=0i32;let mut len=std::mem::size_of_val(&error) as libc::socklen_t;
        if unsafe{libc::getsockopt(fd.as_raw_fd(),libc::SOL_SOCKET,libc::SO_ERROR,&mut error as *mut _ as *mut libc::c_void,&mut len)}!=0||error!=0{return Err("media connection failed".into());}
    }let socket=TcpStream::from(fd);socket.set_nodelay(true).map_err(|_|"media socket option failed")?;Ok(socket)
}
fn live(kind:u8,flags:u8,data:&[u8],pts:u64)->Vec<u8>{let mut out=(12u32+data.len() as u32).to_le_bytes().to_vec();out.extend([kind,flags,0,0]);out.extend(pts.to_le_bytes());out.extend(data);out}
struct Queued{kind:u8,wire:Vec<u8>,offset:usize,at:Instant}
struct Link{path:PathBuf,socket:Option<UnixStream>,input:Vec<u8>,queue:VecDeque<Queued>,size:usize,retry:Instant,wait_key:bool,established:bool,active:bool,audio:bool,audio_role:u8,microphone:Option<Vec<u8>>,mic_pcm:VecDeque<(u64,Vec<u8>)>,sent:u64,dropped:u64,reconnects:u64}
impl Link{
    fn new(path:PathBuf)->Self{Self{path,socket:None,input:vec![],queue:VecDeque::new(),size:0,retry:Instant::now(),wait_key:true,established:false,active:false,audio:false,audio_role:0,microphone:None,mic_pcm:VecDeque::new(),sent:0,dropped:0,reconnects:0}}
    fn clear(&mut self){self.queue.clear();self.size=0;self.wait_key=true;}
    fn push(&mut self,kind:u8,flags:u8,data:&[u8],pts:u64){let wire=live(kind,flags,data,pts);if self.queue.len()>=128||self.size+wire.len()>MAX_QUEUE{self.disconnect();}self.size+=wire.len();self.queue.push_back(Queued{kind,wire,offset:0,at:Instant::now()});}
    fn prune(&mut self,kind:u8){self.queue.retain(|v|v.kind!=kind||v.offset>0);self.size=self.queue.iter().map(|v|v.wire.len()-v.offset).sum();}
    fn recover(&mut self){
        // Finish a partially written record before the reset marker. Keeping
        // its suffix preserves framing without dropping the phone session.
        self.prune(2);self.prune(6);self.wait_key=true;self.push(6,0,&[],0);
    }
    fn session(&mut self,active:bool){if self.queue.iter().any(|v|v.offset>0){self.disconnect();}self.active=active;self.established=false;self.clear();self.push(4,u8::from(active),&[],0);self.push(1,0,&[800u32.to_le_bytes(),480u32.to_le_bytes(),30u32.to_le_bytes()].concat(),0);if self.audio{self.push(5,self.audio_role,&[1],0);}if active{if let Some(v)=self.microphone.clone(){self.push(7,0,&v,0);}}else{self.microphone=None;self.mic_pcm.clear();}}
    fn audio(&mut self,active:bool){self.audio=active;self.prune(3);self.push(5,self.audio_role,&[u8::from(active)],0);}
    fn microphone(&mut self,generation:u64,active:bool){let v=json!({"generation":generation,"active":active,"sample_rate":16000,"channels":1}).to_string().into_bytes();self.microphone=active.then(||v.clone());self.mic_pcm.clear();self.push(7,0,&v,0);}
    fn media(&mut self,kind:u8,data:&[u8],pts:u64,key:bool)->bool{
        if self.socket.is_none()||!self.active||kind==2&&self.wait_key&&!key{self.dropped+=1;return false;}
        if self.size+data.len()+16>MAX_QUEUE||self.queue.iter().filter(|v|v.kind==kind).count()>=if kind==2{4}else{6}{self.dropped+=1;if kind==2{self.recover();}return false;}
        self.push(kind,if kind==3{self.audio_role}else{u8::from(kind==2&&key)},data,pts);if kind==2{self.wait_key=false;self.established=true;}true
    }
    fn disconnect(&mut self){self.established=false;self.socket=None;self.input.clear();self.mic_pcm.clear();self.clear();self.retry=Instant::now()+Duration::from_millis(250);}
    fn step(&mut self)->Vec<Value>{
        let mut controls=vec![];
        if self.socket.is_none()&&Instant::now()>=self.retry{
            match UnixStream::connect(&self.path){Ok(socket)=>{
                if socket.set_nonblocking(true).is_err(){self.retry=Instant::now()+Duration::from_millis(250);return controls;}
                let size=32768i32;unsafe{libc::setsockopt(socket.as_raw_fd(),libc::SOL_SOCKET,libc::SO_SNDBUF,&size as *const _ as *const libc::c_void,4);}
                self.socket=Some(socket);self.reconnects+=1;self.session(self.active);
            },Err(_)=>{self.retry=Instant::now()+Duration::from_millis(250);return controls;}}
        }
        let Some(socket)=self.socket.as_mut()else{return controls;};let mut broken=false;let mut recover=false;
        for _ in 0..16{
            let Some(item)=self.queue.front_mut()else{break;};
            if matches!(item.kind,2|3)&&item.at.elapsed()>Duration::from_millis(120){
                if item.offset>0{
                    // The peer already owns the frame prefix. Finish this one
                    // frame; expiry only removes records not yet written.
                    if item.at.elapsed()>Duration::from_secs(2){broken=true;break;}
                }else{
                let video=item.kind==2;self.size-=item.wire.len();self.queue.pop_front();self.dropped+=1;
                if video{recover=true;break;}continue;}
            }
            match socket.write(&item.wire[item.offset..]){
                Ok(0)=>{broken=true;break;},Ok(n)=>{item.offset+=n;self.size-=n;if item.offset==item.wire.len(){self.queue.pop_front();self.sent+=1;}else{break;}},
                Err(e) if e.kind()==ErrorKind::WouldBlock=>break,Err(_)=>{broken=true;break;}
            }
        }
        let mut bytes=[0u8;4096];
        if !broken{for _ in 0..8{match socket.read(&mut bytes){
            Ok(0)=>{broken=true;break;},Ok(n)=>{self.input.extend(&bytes[..n]);if self.input.len()>32768{broken=true;break;}},
            Err(e)if e.kind()==ErrorKind::WouldBlock=>break,Err(_)=>{broken=true;break;}
        }}}
        while !broken&&self.input.len()>=4{
            let n=u32::from_le_bytes(self.input[..4].try_into().unwrap()) as usize;
            if !(12..=16404).contains(&n){broken=true;break;}if self.input.len()<n+4{break;}
            if self.input[4..8]==[130,0,0,0]{
                let payload=&self.input[16..n+4];
                if !(10..=16392).contains(&payload.len())||payload.len()%2!=0{broken=true;break;}
                let generation=u64::from_le_bytes(payload[..8].try_into().unwrap());if self.mic_pcm.len()>=6{self.mic_pcm.pop_front();self.dropped+=1;}self.mic_pcm.push_back((generation,payload[8..].to_vec()));self.input.drain(..n+4);continue;
            }
            if n>4096{broken=true;break;}
            if self.input[4..8]!=[129,0,0,0]{broken=true;break;}
            match serde_json::from_slice(&self.input[16..n+4]){Ok(value)=>controls.push(value),Err(_)=>{broken=true;break;}}
            self.input.drain(..n+4);
        }
        if broken{self.disconnect();controls.push(json!({"type":"touch","contacts":[]}));}else if recover{self.recover();}
        controls
    }
}

struct AudioPacket{data:Vec<u8>,offset:usize,at:Instant}
struct Decoder{child:Child,input:ChildStdin,output:ChildStdout,queue:VecDeque<AudioPacket>,pcm:Vec<u8>,origin:u64,samples:u64,submitted_us:u64,rate:u32,channels:u8}
impl Drop for Decoder{fn drop(&mut self){let _=self.child.kill();let _=self.child.wait();}}
impl Decoder{
    fn new(binary:&Path,rate:u32,channels:u8,pts:u64)->Result<Self>{
        if !matches!(rate,8000|16000|24000|32000|44100|48000)||!matches!(channels,1|2){return Err("unsupported AAC format".into());}
        let mut child=Command::new(binary).args(["-hide_banner","-loglevel","error","-nostdin","-threads","1","-probesize","32","-analyzeduration","0","-f","aac","-i","pipe:0","-vn","-threads","1","-ac","2","-ar","44100","-c:a","pcm_s16le","-f","s16le","-flush_packets","1","pipe:1"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|_|"cannot start native AAC decoder")?;
        let input=child.stdin.take().ok_or("missing decoder input")?;let output=child.stdout.take().ok_or("missing decoder output")?;
        if nonblocking(input.as_raw_fd()).is_err()||nonblocking(output.as_raw_fd()).is_err(){let _=child.kill();let _=child.wait();return Err("cannot configure decoder IO".into());}
        Ok(Self{child,input,output,queue:VecDeque::new(),pcm:vec![],origin:pts,samples:0,submitted_us:0,rate,channels})
    }
    fn feed(&mut self,data:Vec<u8>,samples:u32)->Result<()>{
        let submitted=self.submitted_us+samples as u64*1_000_000/self.rate as u64;
        if self.queue.len()>=16||data.len()>65536||submitted.saturating_sub(self.samples*1_000_000/44100)>250_000{return Err("decoder latency budget exceeded".into());}
        self.submitted_us=submitted;self.queue.push_back(AudioPacket{data,offset:0,at:Instant::now()});Ok(())}
    fn step(&mut self)->Result<()>{
        if self.child.try_wait().map_err(|_|"decoder status failed")?.is_some(){return Err("decoder exited".into());}
        for _ in 0..4{
            let Some(item)=self.queue.front_mut()else{break;};if item.at.elapsed()>Duration::from_millis(500){return Err("decoder queue expired".into());}
            match self.input.write(&item.data[item.offset..]){Ok(0)=>return Err("decoder input closed".into()),Ok(n)=>{item.offset+=n;if item.offset==item.data.len(){self.queue.pop_front();}else{break;}},Err(e)if e.kind()==ErrorKind::WouldBlock=>break,Err(_)=>return Err("decoder write failed".into())}
        }
        let mut bytes=[0u8;4096];for _ in 0..8{
            let room=(6*PCM).saturating_sub(self.pcm.len());if room==0{break;}
            match self.output.read(&mut bytes[..room.min(4096)]){Ok(0)=>return Err("decoder output closed".into()),Ok(n)=>self.pcm.extend(&bytes[..n]),Err(e)if e.kind()==ErrorKind::WouldBlock=>break,Err(_)=>return Err("decoder read failed".into())}
        }
        Ok(())
    }
    fn take_pcm(&mut self)->Option<(Vec<u8>,u64)>{
        if self.pcm.len()<PCM{return None;}
        let chunk=self.pcm.drain(..PCM).collect();let pts=self.origin+self.samples*1_000_000/44100;self.samples+=882;Some((chunk,pts))
    }
}
/// One sample clock owns all decoded streams. Decoder IO never consumes PCM;
/// only a playout tick removes one block from each bounded decoder buffer.
#[derive(Default)]
struct AudioPlayout{next:Option<Instant>,underruns:u64,late:u64}
impl AudioPlayout{
    fn reset(&mut self){self.next=None;}
    fn due(&mut self,now:Instant,available:bool)->bool{
        const PERIOD:Duration=Duration::from_millis(20);
        let Some(next)=self.next else{
            if available{self.next=Some(now+Duration::from_millis(40));}
            return false;
        };
        if now<next{return false;}
        if !available{self.underruns+=1;self.next=None;return false;}
        // Ordinary scheduler jitter must not accumulate into a slower clock.
        // After a missed whole slot, rebase instead of bursting old PCM ticks.
        self.next=Some(if now.duration_since(next)>=PERIOD{self.late+=1;now+PERIOD}else{next+PERIOD});
        true
    }
}
struct InputPacket{wire:Vec<u8>,offset:usize,due:Instant,release:Option<String>}
struct Clock{socket:UdpSocket,next:Instant,waiting:Option<(i64,Instant)>,count:u8,samples:Vec<(i64,i64)>}
impl Clock{
    fn new(local:Ipv4Addr,peer:Ipv4Addr,port:u16)->Result<Self>{let socket=UdpSocket::bind(SocketAddrV4::new(local,0)).map_err(|_|"clock bind failed")?;socket.connect(SocketAddrV4::new(peer,port)).map_err(|_|"clock peer failed")?;socket.set_nonblocking(true).map_err(|_|"clock socket mode failed")?;Ok(Self{socket,next:Instant::now(),waiting:None,count:0,samples:vec![]})}
    fn step(&mut self,crypto:&Crypto,key:&[u8])->Option<(i64,i64,u64)>{
        let mut bytes=[0u8;1500];for _ in 0..8{
            let n=match self.socket.recv(&mut bytes){Ok(n)=>n,Err(e)if e.kind()==ErrorKind::WouldBlock=>break,Err(_)=>break};
            if n<20||bytes[0]!=0xab||u16::from_be_bytes([bytes[1],bytes[2]]) as usize!=n-3{continue;}
            let Ok(data)=decrypt(crypto,key,&bytes[3..n])else{continue;};if data.len()!=32{continue;}
            let t1=i64::from_le_bytes(data[..8].try_into().unwrap());let t2=i64::from_le_bytes(data[8..16].try_into().unwrap());let t3=i64::from_le_bytes(data[16..24].try_into().unwrap());
            let Some((sent,_))=self.waiting else{continue;};if sent!=t1||t3<t2{continue;}
            let arrived=now_us() as i128;let rtt=(arrived-t1 as i128)-(t3 as i128-t2 as i128);let offset=((t2 as i128-t1 as i128)+(t3 as i128-arrived)).div_euclid(2);
            if (0..=100000).contains(&rtt){if let (Ok(rtt),Ok(offset))=(i64::try_from(rtt),i64::try_from(offset)){self.samples.push((rtt,offset));}}
            self.waiting=None;self.next=Instant::now()+Duration::from_millis(20);
        }
        if self.waiting.is_some_and(|(_,deadline)|Instant::now()>=deadline){self.waiting=None;self.next=Instant::now()+Duration::from_millis(20);}
        if self.waiting.is_none()&&self.count>=5{
            let sample=self.samples.iter().min_by_key(|v|v.0).copied();self.samples.clear();self.count=0;self.next=Instant::now()+Duration::from_secs(30);
            return sample.map(|(rtt,offset)|(rtt,offset,now_us()));
        }
        if self.waiting.is_none()&&Instant::now()>=self.next{
            let sent=now_us() as i64;let mut body=sent.to_le_bytes().to_vec();body.extend([0u8;24]);
            if let Ok(data)=encrypt(crypto,key,&body){let mut packet=vec![0xab];packet.extend((data.len() as u16).to_be_bytes());packet.extend(data);
                match self.socket.send(&packet){Ok(_)=>{self.count+=1;self.waiting=Some((sent,Instant::now()+Duration::from_millis(500)));},Err(_)=>self.next=Instant::now()+Duration::from_millis(20)}
            }
        }None
    }
}
struct Engine{
    uplink:Option<super::super::uplink::Uplink>,mic_generation:u64,mic_packets:u64,mic_service:Option<String>,
    key:Vec<u8>,crypto:Crypto,local:Ipv4Addr,peer:Ipv4Addr,audio_binary:PathBuf,udp:UdpSocket,link:Link,
    video:Option<TcpStream>,video_bytes:Vec<u8>,video_decoder:media::Video,video_open:bool,video_ended:bool,
    input:Option<TcpStream>,input_port:Option<u16>,input_queue:VecDeque<InputPacket>,contact:Option<(u16,u16)>,keys:BTreeSet<String>,input_next:Instant,input_start:Instant,
    audio_ports:BTreeMap<String,u16>,audio:media::Audio,audio_ready:bool,audio_generation:u64,decoders:BTreeMap<u32,Decoder>,playout:AudioPlayout,parameters:[Option<Vec<u8>>;2],
    clock:Option<Clock>,clock_offset:Option<i64>,clock_updated:Option<u64>,clock_rtt:Option<i64>,video_frames:u64,epoch_video_frames:u64,key_frames:u64,input_events:u64,audio_frames:u64,pcm_blocks:u64,invalid:u64,audio_resets:u64,
}
impl Drop for Engine{fn drop(&mut self){self.stop_video();self.decoders.clear();self.link.session(false);let until=Instant::now()+Duration::from_millis(100);while !self.link.queue.is_empty()&&Instant::now()<until{let _=self.link.step();std::thread::sleep(Duration::from_millis(2));}wipe(&mut self.key);}}
impl Engine{
    fn new(config:&mut Value)->Result<Self>{
        let crypto=Crypto::load()?;
        let local=string(config,"local_ip")?.parse::<Ipv4Addr>().map_err(|_|"invalid local media address")?;
        let peer=string(config,"peer_ip")?.parse::<Ipv4Addr>().map_err(|_|"invalid selected media address")?;
        let audio_binary=absolute(config,"audio_binary")?;let source=absolute(config,"live_socket")?;
        let udp=UdpSocket::bind(SocketAddrV4::new(local,0)).map_err(|_|"cannot bind audio socket")?;udp.set_nonblocking(true).map_err(|_|"cannot configure audio socket")?;
        let mut key=unhex(string(config,"key")?)?;if !matches!(key.len(),16|32){wipe(&mut key);return Err("invalid authenticated media key".into());}
        if let Some(Value::String(text))=config.get_mut("key"){unsafe{wipe(text.as_bytes_mut());}}
        if key.len()>16{wipe(&mut key[16..]);key.truncate(16);}
        Ok(Self{uplink:None,mic_generation:0,mic_packets:0,mic_service:None,key,crypto,local,peer,audio_binary,udp,link:Link::new(source),video:None,video_bytes:vec![],video_decoder:media::Video::new(),video_open:false,video_ended:false,input:None,input_port:None,input_queue:VecDeque::new(),contact:None,keys:BTreeSet::new(),input_next:Instant::now(),input_start:Instant::now(),audio_ports:BTreeMap::new(),audio:media::Audio::new(),audio_ready:false,audio_generation:0,decoders:BTreeMap::new(),playout:AudioPlayout::default(),parameters:[None,None],clock:None,clock_offset:None,clock_updated:None,clock_rtt:None,video_frames:0,epoch_video_frames:0,key_frames:0,input_events:0,audio_frames:0,pcm_blocks:0,invalid:0,audio_resets:0})
    }
    fn state(&self)->Value{json!({"active":self.link.active&&self.link.socket.is_some()&&self.link.established,"connected":self.link.socket.is_some(),"waiting_key":self.link.wait_key,"video_open":self.video_open,"video_ended":self.video_ended,"input_connected":self.input.is_some(),"video_frames":self.video_frames,"epoch_video_frames":self.epoch_video_frames,"key_frames":self.key_frames,"audio_frames":self.audio_frames,"pcm_blocks":self.pcm_blocks,"input_events":self.input_events,"audio_generation":self.audio_generation,"audio_ready":self.audio_ready,"audio_packets":self.audio.packets,"audio_lost":self.audio.lost,"audio_duplicates":self.audio.duplicates,"rejected":self.invalid,"audio_resets":self.audio_resets,"audio_underruns":self.playout.underruns,"mix_late":self.playout.late,"pcm_queued_blocks":self.decoders.values().map(|d|d.pcm.len()/PCM).sum::<usize>(),"pending":self.link.queue.len(),"pending_bytes":self.link.size,"sent":self.link.sent,"dropped":self.link.dropped,"reconnects":self.link.reconnects,"clock_offset_us":self.clock_offset,"clock_updated_us":self.clock_updated,"clock_rtt_us":self.clock_rtt,"microphone_active":self.uplink.is_some(),"microphone_packets":self.mic_packets,"audio_streams":self.decoders.len(),"call_active":self.link.audio_role==3&&(self.audio_ready||self.mic_service.as_deref()==Some("modemMic"))})}
    fn stop_audio(&mut self){self.audio_ready=false;self.decoders.clear();self.playout.reset();self.link.audio(false);}
    fn reset_decoder(&mut self,id:u32){self.decoders.remove(&id);self.audio_resets+=1;if self.decoders.is_empty()&&self.link.audio_role!=3{self.link.audio(false);}}
    fn stop_microphone(&mut self){self.mic_service=None;if self.uplink.take().is_some(){self.link.microphone(self.mic_generation,false);}}
    fn stop_video(&mut self){self.stop_microphone();self.release_inputs();self.flush_input();self.video=None;self.video_bytes.clear();self.video_open=false;self.video_ended=true;self.input=None;self.input_queue.clear();self.contact=None;self.keys.clear();self.stop_audio();self.link.session(false);}
    fn command(&mut self,v:&Value)->Result<Value>{match string(v,"op")?{
        "microphone-start"=>{
            let service=v["service"].as_str().unwrap_or("mic1");if !matches!(service,"mic1"|"modemMic"){return Err("invalid microphone service".into());}
            self.stop_microphone();self.mic_generation=self.mic_generation.checked_add(1).ok_or("microphone generation exhausted")?.max(now_us());
            let remote=port(v,"port")?;v["session"].as_u64().filter(|id|*id>0&&*id<=u32::MAX as u64).ok_or("invalid microphone control session")?;
            self.uplink=Some(super::super::uplink::Uplink::new(&self.audio_binary,self.mic_generation,remote)?);self.mic_service=Some(service.into());self.link.microphone(self.mic_generation,true);
        },
        "microphone-stop"=>{if v["service"].is_null()||v["service"].as_str()==self.mic_service.as_deref(){self.stop_microphone();}},
        "audio-service"=>{
            let service=string(v,"service")?;if !matches!(service,"speaker1"|"modemSpeaker"){return Err("invalid audio service".into());}
            let active=v["active"].as_bool().ok_or("invalid audio service state")?;
            if active{self.audio_ports.insert(service.into(),port(v,"port")?);}else{self.audio_ports.remove(service);}
            // A new DMSDP stream may restart sequence numbers on the same SSRC.
            // Flush that audio epoch instead of rejecting fresh audio as a replay
            // until its sequence catches up with the previous route.
            if (service=="modemSpeaker")== (self.link.audio_role==3){self.decoders.clear();self.playout.reset();self.audio=media::Audio::new();self.link.prune(3);}
        },
        "audio-role"=>{let role=v["role"].as_u64().filter(|n|*n==0||*n==3).ok_or("invalid call audio role")? as u8;if self.link.audio_role!=role{self.stop_audio();self.audio=media::Audio::new();self.link.audio_role=role;if role==3{self.link.audio(true);}}},
        "set-video"=>{
            if self.video.is_some(){return Err("video transport already open".into());}
            let video=connect(self.local,self.peer,port(v,"media_port")?,Duration::from_secs(2))?;
            let input_port=if v["input_port"].is_null(){None}else{Some(port(v,"input_port")?)};
            let input=if let Some(p)=input_port{Some(connect(self.local,self.peer,p,Duration::from_secs(2))?)}else{None};
            self.video=Some(video);self.input=input;self.input_port=input_port;self.video_open=true;self.video_ended=false;self.epoch_video_frames=0;self.video_decoder=media::Video::new();self.parameters=[None,None];self.input_start=Instant::now();
        },
        "audio-begin"=>{self.stop_audio();if self.link.audio_role==3&&self.mic_service.as_deref()==Some("modemMic"){self.link.audio(true);}self.audio_generation=self.audio_generation.checked_add(1).ok_or("audio generation exhausted")?;self.audio=media::Audio::new();},
        "audio-ready"=>self.audio_ready=true,
        "audio-stop"=>{self.stop_audio();if self.link.audio_role==3&&self.mic_service.as_deref()==Some("modemMic"){self.link.audio(true);}},
        "clock-update"=>{self.clock_offset=Some(v["offset_us"].as_i64().ok_or("invalid clock offset")?);self.clock_updated=Some(v["updated_us"].as_u64().ok_or("invalid clock time")?);},
        "clock-start"=>self.clock=Some(Clock::new(self.local,self.peer,port(v,"port")?)?),
        "status"=>{},"close"=>return Ok(json!({"closed":true})),_=>return Err("unknown media command".into()),
    }Ok(json!({"state":self.state()}))}
    fn video_frame(&mut self,data:&[u8]){
        let frame=match self.video_decoder.receive(data){Ok(v)=>v,Err(_)=>{self.invalid+=1;self.link.recover();return;}};
        let Some((kind,_,record))=frame else{return;};if kind!=96{return;}
        let data=match decrypt(&self.crypto,&self.key,&record){Ok(v)=>v,Err(_)=>{self.invalid+=1;self.link.recover();return;}};
        if data.len()>MAX_VIDEO-1024{self.invalid+=1;self.link.recover();return;}
        let Some(units)=nal_units(&data)else{self.invalid+=1;self.link.recover();return;};let key=units.iter().any(|v|v[0]&31==5);
        for unit in &units{let kind=unit[0]&31;if matches!(kind,7|8)&&unit.len()<=32768{let mut parameter=vec![0,0,0,1];parameter.extend(*unit);self.parameters[(kind-7) as usize]=Some(parameter);}}
        let frame=if key{match (&self.parameters[0],&self.parameters[1]){(Some(sps),Some(pps))=>{let mut out=sps.clone();out.extend(pps);out.extend(&data);out},_=>return,}}else{data};
        if frame.len()>MAX_VIDEO{self.invalid+=1;self.link.recover();return;}
        let activating=!self.link.active;if activating{if !key{return;}self.link.session(true);}
        if self.link.media(2,&frame,now_us(),key){self.video_frames+=1;self.epoch_video_frames+=1;if key{self.key_frames+=1;}}
        else if activating{self.link.session(false);}
    }
    fn read_video(&mut self){
        let mut ended=false;let mut bytes=[0u8;65536];if let Some(socket)=self.video.as_mut(){for _ in 0..4{match socket.read(&mut bytes){
            Ok(0)=>{ended=true;break;},Ok(n)=>{self.video_bytes.extend(&bytes[..n]);if self.video_bytes.len()>MAX_RTP+65540{ended=true;break;}},Err(e)if e.kind()==ErrorKind::WouldBlock=>break,Err(_)=>{ended=true;break;}
        }}}
        for _ in 0..64{
            if self.video_bytes.len()<4{break;}let n=u32::from_be_bytes(self.video_bytes[..4].try_into().unwrap()) as usize;
            if n==0||n>MAX_RTP{ended=true;break;}if self.video_bytes.len()<n+4{break;}
            let packet=self.video_bytes[4..n+4].to_vec();self.video_bytes.drain(..n+4);self.video_frame(&packet);
        }if ended{self.stop_video();}
    }
    fn read_audio(&mut self){
        let mut bytes=[0u8;65536];for _ in 0..16{
            let (n,peer)=match self.udp.recv_from(&mut bytes){Ok(v)=>v,Err(e)if e.kind()==ErrorKind::WouldBlock=>break,Err(_)=>break};
            if peer.ip()!=std::net::IpAddr::V4(self.peer)||!self.audio_ready{continue;}
            // DMSDP advertises each sender UDP port. During a call, discard
            // normal music/navigation datagrams before decoding, and vice versa.
            // Keep fallback compatibility for senders that choose another port.
            if !audio_port_allowed(&self.audio_ports,self.link.audio_role,peer.port()){continue;}
            if n<20||bytes[0]!=0xab||u16::from_be_bytes([bytes[1],bytes[2]]) as usize!=n-3{self.invalid+=1;continue;}
            let decoded=match decrypt(&self.crypto,&self.key,&bytes[3..n]){Ok(v)=>v,Err(_)=>{self.invalid+=1;continue;}};
            let frames=match self.audio.receive(&decoded){Ok(v)=>v,Err(_)=>{self.invalid+=1;continue;}};
            for frame in frames{
                // Match the proven bridge sink: both video and PCM begin on
                // local arrival time. RTP clock mapping remains diagnostic
                // until source/HU cross-stream timing is independently tested.
                let pts=now_us();let format=(frame.aac.rate,frame.aac.channels);
                let id=frame.stream;
                if self.decoders.get(&id).is_none_or(|d|(d.rate,d.channels)!=format){
                    self.decoders.remove(&id);
                    if self.decoders.len()>=4{self.invalid+=1;continue;}
                    match Decoder::new(&self.audio_binary,format.0,format.1,pts){Ok(d)=>{let first=self.decoders.is_empty();self.decoders.insert(id,d);if first{self.link.audio(true);self.playout.reset();}},Err(_)=>{self.invalid+=1;continue;}}
                }
                if self.decoders.get_mut(&id).is_some_and(|d|d.feed(frame.aac.data,frame.aac.samples).is_err()){self.reset_decoder(id);}self.audio_frames+=1;
            }
        }
    }
    fn pack_input(&self,body:&[u8])->Result<Vec<u8>>{let mut plain=vec![255;6];plain.extend(body);let record=encrypt(&self.crypto,&self.key,&plain)?;let mut out=vec![0,0];out.extend(((record.len()+4) as u16).to_be_bytes());out.extend(record);Ok(out)}
    fn queue_input(&mut self,body:Vec<u8>,delay:Duration,release:Option<String>){if let Ok(wire)=self.pack_input(&body){let due=self.input_next.max(Instant::now());self.input_next=due+delay;self.input_queue.push_back(InputPacket{wire,offset:0,due,release});}}
    fn release_inputs(&mut self){
        if self.input_queue.front().is_some_and(|p|p.offset>0){self.input=None;self.input_queue.clear();self.input_next=Instant::now();return;}
        self.input_queue.clear();self.input_next=Instant::now();
        if let Some((x,y))=self.contact.take(){if let Ok(body)=media::touch(x,y,1,self.input_start.elapsed().as_millis() as u32){self.queue_input(body,Duration::ZERO,None);}}
        for key in self.keys.clone(){if let Ok(body)=media::key(&key,false){self.queue_input(body,Duration::ZERO,Some(key));}}
    }
    fn feedback(&mut self,v:Value){
        if v["type"]=="keyframe"{self.link.recover();return;}
        if self.input.is_none(){
            if self.video_open{if let Some(port)=self.input_port{self.input=connect(self.local,self.peer,port,Duration::from_millis(100)).ok();if self.input.is_some(){self.release_inputs();}}}
            if self.input.is_none(){return;}
        }
        if self.input_queue.len()>=32{self.release_inputs();return;}
        if v["type"]=="key-press"{
            let name=match v["code"].as_u64(){Some(0)=>"home",Some(1)=>"back",Some(2)=>"enter",Some(3)=>"left",Some(4)=>"right",Some(5)=>"up",Some(6)=>"down",Some(7)=>"play_pause",Some(8)=>"next",Some(9)=>"previous",_=>return};
            if let (Ok(down),Ok(up))=(media::key(name,true),media::key(name,false)){self.keys.insert(name.into());self.queue_input(down,Duration::from_millis(40),None);self.queue_input(up,Duration::from_millis(40),Some(name.into()));self.input_events+=1;}
        }else if v["type"]=="touch"{
            let Some(contacts)=v["contacts"].as_array().filter(|v|v.len()<=10)else{return;};
            let (xy,action)=if contacts.is_empty(){let Some(xy)=self.contact.take()else{return;};(xy,1)}else{
                let point=&contacts[0];let (Some(x),Some(y),Some(down))=(point["x"].as_f64(),point["y"].as_f64(),point["down"].as_bool())else{return;};
                if !x.is_finite()||!y.is_finite()||!(0.0..=1.0).contains(&x)||!(0.0..=1.0).contains(&y){return;}
                let xy=((x*800.0) as u16,(y*480.0) as u16);let xy=(xy.0.min(799),xy.1.min(479));let action=if down{if self.contact.is_some(){2}else{0}}else{1};self.contact=down.then_some(xy);(xy,action)
            };
            if let Ok(body)=media::touch(xy.0,xy.1,action,self.input_start.elapsed().as_millis() as u32){self.queue_input(body,Duration::from_millis(if action==1{40}else{20}),None);self.input_events+=1;}
        }
    }
    fn flush_input(&mut self){
        let Some(socket)=self.input.as_mut()else{return;};let mut failed=false;
        for _ in 0..4{let Some(packet)=self.input_queue.front_mut()else{break;};if Instant::now()<packet.due{break;}
            match socket.write(&packet.wire[packet.offset..]){Ok(0)=>{failed=true;break;},Ok(n)=>{packet.offset+=n;if packet.offset==packet.wire.len(){if let Some(key)=&packet.release{self.keys.remove(key);}self.input_queue.pop_front();}else{break;}},Err(e)if e.kind()==ErrorKind::WouldBlock=>break,Err(_)=>{failed=true;break;}}
        }if failed{self.input=None;self.input_queue.clear();}
    }
    fn step(&mut self){
        self.read_video();self.read_audio();
        if let Some(clock)=self.clock.as_mut(){if let Some((rtt,offset,updated))=clock.step(&self.crypto,&self.key){self.clock_rtt=Some(rtt);self.clock_offset=Some(offset);self.clock_updated=Some(updated);}}
        let mut failed=vec![];
        for (id,decoder) in &mut self.decoders{if decoder.step().is_err(){failed.push(*id);}}
        for id in failed{self.reset_decoder(id);}
        if self.playout.due(Instant::now(),self.decoders.values().any(|d|d.pcm.len()>=PCM)){
            let blocks:Vec<_>=self.decoders.values_mut().filter_map(Decoder::take_pcm).collect();
            let pts=blocks.iter().map(|(_,t)|*t).max().unwrap_or(0);
            let pcm=mix_pcm(blocks.iter().map(|(pcm,_)|pcm.as_slice()));if self.link.media(3,&pcm,pts,false){self.pcm_blocks+=1;}
        }
        let controls=self.link.step();for v in controls{self.feedback(v);}self.flush_input();
        let mut failed=false;
        while let Some((generation,pcm))=self.link.mic_pcm.pop_front(){if let Some(u)=self.uplink.as_mut(){if u.feed(generation,pcm).is_err(){failed=true;break;}}}
        if let Some(u)=self.uplink.as_mut(){match u.poll(&self.crypto,&self.key,self.clock_offset.unwrap_or(0)){
            Ok(packets)=>{for packet in packets{match self.udp.send_to(&packet,SocketAddrV4::new(self.peer,u.port)){Ok(n)if n==packet.len()=>self.mic_packets+=1,Err(e)if e.kind()==ErrorKind::WouldBlock=>{},_=>{failed=true;break;}}}},
            Err(_)=>failed=true,
        }}
        if failed{self.invalid+=1;self.stop_microphone();println!("{}",json!({"event":"microphone_error","capture_stopped":true}));}
    }
    fn pollfds(&self)->Vec<libc::pollfd>{
        let mut fds=vec![libc::pollfd{fd:self.udp.as_raw_fd(),events:libc::POLLIN,revents:0}];
        for fd in [self.video.as_ref().map(AsRawFd::as_raw_fd),self.link.socket.as_ref().map(AsRawFd::as_raw_fd),self.clock.as_ref().map(|c|c.socket.as_raw_fd())].into_iter().flatten(){fds.push(libc::pollfd{fd,events:libc::POLLIN,revents:0});}
        for d in self.decoders.values().filter(|d|d.pcm.len()<6*PCM){fds.push(libc::pollfd{fd:d.output.as_raw_fd(),events:libc::POLLIN,revents:0});}fds
    }
}
fn audio_port_allowed(ports:&BTreeMap<String,u16>,role:u8,port:u16)->bool{
    let normal=ports.get("speaker1").copied();let call=ports.get("modemSpeaker").copied();
    if normal==call{return true;} // Some receivers multiplex both services.
    if role==3{normal!=Some(port)}else{call!=Some(port)}
}
#[test]fn service_ports_isolate_call_and_media_without_unknown_port_lockout(){
    let ports=BTreeMap::from([("speaker1".into(),1000),("modemSpeaker".into(),2000)]);
    assert!(!audio_port_allowed(&ports,3,1000));assert!(audio_port_allowed(&ports,3,2000));
    assert!(audio_port_allowed(&ports,0,1000));assert!(!audio_port_allowed(&ports,0,2000));assert!(audio_port_allowed(&ports,0,3000));
}
#[test]fn pruning_audio_keeps_partial_record_without_disconnecting_the_source(){
    let mut link=Link::new(PathBuf::from("/unused"));let (a,_b)=UnixStream::pair().unwrap();link.socket=Some(a);link.active=true;link.established=true;
    link.push(3,0,&[0;32],1);link.queue.front_mut().unwrap().offset=4;link.size-=4;link.push(3,0,&[0;32],2);link.audio(false);
    assert!(link.socket.is_some());assert!(link.established);assert_eq!(link.queue.len(),2);assert_eq!(link.queue[0].offset,4);assert_eq!(link.queue[1].kind,5);
}
#[test]fn video_backpressure_finishes_partial_frame_before_reset_marker(){
    let mut link=Link::new(PathBuf::from("/unused"));let (a,_b)=UnixStream::pair().unwrap();link.socket=Some(a);link.active=true;link.established=true;
    link.push(2,0,&[0;32],1);link.queue.front_mut().unwrap().offset=4;link.size-=4;link.push(2,0,&[0;32],2);link.recover();
    assert!(link.socket.is_some());assert!(link.established);assert!(link.wait_key);assert_eq!(link.queue.len(),2);assert_eq!(link.queue[0].offset,4);assert_eq!(link.queue[1].kind,6);
}
#[test]fn microphone_burst_drops_old_complete_blocks_without_resetting_projection(){
    let mut link=Link::new(PathBuf::from("/unused"));let (a,mut b)=UnixStream::pair().unwrap();a.set_nonblocking(true).unwrap();link.socket=Some(a);link.active=true;link.established=true;
    let mut packets=vec![];for i in 0..10u64{let mut pcm=i.to_le_bytes().to_vec();pcm.extend([0;640]);packets.extend(live(130,0,&pcm,0));}b.write_all(&packets).unwrap();link.step();
    assert!(link.socket.is_some());assert!(link.established);assert_eq!(link.mic_pcm.len(),6);assert_eq!(link.mic_pcm.front().unwrap().0,4);assert_eq!(link.dropped,4);
}

fn mix_pcm<'a>(blocks:impl Iterator<Item=&'a [u8]>)->Vec<u8>{let mut mixed=vec![0i32;PCM/2];for block in blocks{for (sample,data) in mixed.iter_mut().zip(block.chunks_exact(2)){*sample+=i16::from_le_bytes([data[0],data[1]])as i32;}}mixed.into_iter().flat_map(|sample|(sample.clamp(i16::MIN as i32,i16::MAX as i32)as i16).to_le_bytes()).collect()}
#[test]fn pcm_mixer_saturates_without_changing_sample_layout(){let a=[30000i16.to_le_bytes(),(-30000i16).to_le_bytes()].concat();let output=mix_pcm([a.as_slice(),a.as_slice()].into_iter());assert_eq!(output.len(),PCM);assert_eq!(&output[..4],&[i16::MAX.to_le_bytes(),i16::MIN.to_le_bytes()].concat());}
#[test]fn playout_clock_has_no_scheduler_drift_or_pcm_overwrite(){
    for poll_us in [5200,6000,11000]{
        let epoch=Instant::now();let mut clock=AudioPlayout::default();let mut pcm=VecDeque::new();let mut produced=0;let mut played=vec![];let mut last=None;
        for elapsed in (0..2_500_000u64).step_by(poll_us as usize){
            while produced<100&&produced*20_000<=elapsed{pcm.push_back(produced);produced+=1;}
            assert!(pcm.len()<=6,"playout must stay inside decoder PCM budget");
            if clock.due(epoch+Duration::from_micros(elapsed),!pcm.is_empty()){
                played.push(pcm.pop_front().unwrap());
                if let Some(previous)=last{let gap=elapsed-previous;assert!((20_000-poll_us..=20_000+poll_us).contains(&gap));}
                last=Some(elapsed);
            }
            if played.len()==100{break;}
        }
        assert_eq!(played,(0..100).collect::<Vec<_>>());assert!(pcm.is_empty());assert_eq!(clock.underruns,0);assert_eq!(clock.late,0);
    }
}
#[test]fn playout_underflow_and_stall_do_not_burst_expired_slots(){
    let epoch=Instant::now();let mut clock=AudioPlayout::default();assert!(!clock.due(epoch,true));
    assert!(clock.due(epoch+Duration::from_millis(40),true));
    assert!(!clock.due(epoch+Duration::from_millis(60),false));assert_eq!(clock.underruns,1);
    assert!(!clock.due(epoch+Duration::from_millis(200),true));
    assert!(clock.due(epoch+Duration::from_millis(240),true));
    assert!(clock.due(epoch+Duration::from_millis(400),true));assert_eq!(clock.late,1);
    assert!(!clock.due(epoch+Duration::from_millis(400),true));assert!(!clock.due(epoch+Duration::from_millis(419),true));
    assert!(clock.due(epoch+Duration::from_millis(420),true));
}
fn nal_units(data:&[u8])->Option<Vec<&[u8]>>{
    let mut starts=vec![];let mut pos=0;
    while pos+3<=data.len(){if data[pos..].starts_with(&[0,0,0,1]){starts.push((pos,4));pos+=4;}else if data[pos..].starts_with(&[0,0,1]){starts.push((pos,3));pos+=3;}else{pos+=1;}}
    let first=starts.first()?.0;
    // Annex-B permits leading zero bytes, not arbitrary bytes before the
    // first start code. RTP/PES validity and decryption alone do not establish
    // a decodable access unit; never forward malformed ES into CarLife.
    if data[..first].iter().any(|b|*b!=0){return None;}
    let mut out=vec![];for (index,(start,size)) in starts.iter().enumerate(){
        let end=starts.get(index+1).map(|v|v.0).unwrap_or(data.len());if start+size>=end{return None;}
        let unit=&data[start+size..end];if unit[0]&128!=0||!(1..=23).contains(&(unit[0]&31)){return None;}out.push(unit);
    }Some(out)
}
fn read_initial(socket:&mut UnixStream)->Result<Value>{
    socket.set_read_timeout(Some(Duration::from_secs(10))).map_err(|_|"private media timeout failed")?;
    let mut header=[0;4];socket.read_exact(&mut header).map_err(|_|"private media configuration unavailable")?;let n=u32::from_be_bytes(header) as usize;
    if n==0||n>IPC_LIMIT{return Err("private media configuration exceeds limit".into());}let mut bytes=vec![0;n];socket.read_exact(&mut bytes).map_err(|_|"truncated private media configuration")?;
    let result=serde_json::from_slice(&bytes).map_err(|_|"invalid private media configuration".to_owned());wipe(&mut bytes);result
}
fn reply(value:Value)->Result<Vec<u8>>{let data=serde_json::to_vec(&value).map_err(|_|"private media response failed")?;if data.len()>IPC_LIMIT{return Err("private media response exceeds limit".into());}let mut out=(data.len() as u32).to_be_bytes().to_vec();out.extend(data);Ok(out)}
pub fn run(fd:i32)->Result<()>{
    if fd<3{return Err("media worker requires private IPC fd".into());}
    let mut socket=unsafe{UnixStream::from_raw_fd(fd)};socket.peer_addr().map_err(|_|"media IPC is not a Unix socket")?;
    unsafe{libc::signal(libc::SIGTERM,libc::SIG_IGN);}
    let mut config=read_initial(&mut socket)?;let mut engine=Engine::new(&mut config)?;
    let port=engine.udp.local_addr().map_err(|_|"audio port unavailable")?.port();
    socket.set_write_timeout(Some(Duration::from_secs(2))).map_err(|_|"private media write timeout failed")?;
    socket.write_all(&reply(json!({"ok":true,"ready":true,"audio_ports":[port,-1],"state":engine.state()}))?).map_err(|_|"private media ready failed")?;
    socket.set_nonblocking(true).map_err(|_|"private media mode failed")?;
    let mut input=vec![];let mut output:VecDeque<(Vec<u8>,usize)>=VecDeque::new();let mut closing=false;
    loop{
        engine.step();let mut data=[0;8192];
        for _ in 0..4{match socket.read(&mut data){Ok(0)=>return Ok(()),Ok(n)=>{input.extend(&data[..n]);if input.len()>IPC_LIMIT+4{return Err("private media request exceeds limit".into());}},Err(e)if e.kind()==ErrorKind::WouldBlock=>break,Err(_)=>return Err("private media IPC failed".into())}}
        for _ in 0..16{
            if input.len()<4{break;}let n=u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;if n==0||n>IPC_LIMIT{return Err("invalid private media length".into());}if input.len()<n+4{break;}
            let command:Value=serde_json::from_slice(&input[4..n+4]).map_err(|_|"invalid media command")?;input.drain(..n+4);
            let mut value=match engine.command(&command){Ok(v)=>v,Err(e)=>json!({"ok":false,"error":e})};if value["ok"].is_null(){value["ok"]=true.into();}closing|=value["closed"]==true;
            if output.len()>=32{return Err("private media reply backpressure".into());}output.push_back((reply(value)?,0));if closing{break;}
        }
        while let Some((data,offset))=output.front_mut(){match socket.write(&data[*offset..]){Ok(0)=>return Ok(()),Ok(n)=>{*offset+=n;if *offset==data.len(){output.pop_front();}else{break;}},Err(e)if e.kind()==ErrorKind::WouldBlock=>break,Err(_)=>return Ok(())}}
        if closing&&output.is_empty(){return Ok(());}
        let mut fds=engine.pollfds();fds.push(libc::pollfd{fd:socket.as_raw_fd(),events:libc::POLLIN,revents:0});unsafe{libc::poll(fds.as_mut_ptr(),fds.len() as libc::nfds_t,5);}
    }
}
}
pub fn run(fd:i32)->super::Result<()>{
    #[cfg(unix)]{unix::run(fd)}
    #[cfg(not(unix))]{let _=fd;Err("HiCar media worker requires Linux/Unix".into())}
}
