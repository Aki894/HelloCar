//! Explicit bounded development commands. No automatic hardware changes.
use super::{Result,wire::{Format,Frame,Decoder,Messages},json,media,crypto::Crypto,hex,unhex};
use serde_json::{Value,json as value};
use std::io::{self,BufRead,Write,Read};
fn string<'a>(v:&'a Value,k:&str)->Result<&'a str>{v.get(k).and_then(Value::as_str).ok_or_else(||format!("missing string {k}"))}
fn number(v:&Value,k:&str)->Result<u64>{v.get(k).and_then(Value::as_u64).ok_or_else(||format!("missing unsigned integer {k}"))}
fn bounded_u32(v:&Value,k:&str)->Result<u32>{number(v,k)?.try_into().map_err(|_|format!("{k} exceeds u32"))}
fn bytes(v:&Value,k:&str)->Result<Vec<u8>>{unhex(string(v,k)?)}
fn chunks(v:&Value)->Result<Vec<Vec<u8>>>{
    let a=v.get("chunks").and_then(Value::as_array).ok_or("missing input chunks")?;
    if a.len()>4096{return Err("too many chunks".into());}a.iter().map(|s|unhex(s.as_str().ok_or("chunk must be hex")?)).collect()
}
fn format(v:&Value)->Result<Format>{match string(v,"format")?{"nearby"=>Ok(Format::Nearby),"module"=>Ok(Format::Module),"control"=>Ok(Format::Control),"hisight"=>Ok(Format::HiSight),_=>Err("unknown framing".into())}}
fn frame(v:&Value)->Result<Frame>{Ok(Frame{kind:bounded_u32(v,"kind")?,flags:v.get("flags").map(|_|bounded_u32(v,"flags")).transpose()?.unwrap_or(0),
    options:v.get("options").map(|_|bytes(v,"options")).transpose()?.unwrap_or_default(),payload:bytes(v,"payload")?})}
fn codec(v:&Value)->Result<Value>{
    match string(v,"op")? {
        "uint"=>Ok(value!({"hex":hex(&super::wire::uint(bounded_u32(v,"value")?)?)})),
        "nearby-session"=>super::session::differential(v),
        "hisight-session"=>super::hisight::differential(v),
        "dmsdp-session"=>super::dmsdp::differential(v),
        "radio-contract"=>super::radio::differential(v),
        "crc"=>Ok(value!({"crc":super::wire::crc16(&bytes(v,"data")?)})),
        "tlv"=>Ok(value!({"hex":hex(&super::wire::tlv(bounded_u32(v,"tag")?,&bytes(v,"data")?)?)})),
        "tlvs"=>Ok(value!({"values":super::wire::tlvs(&bytes(v,"data")?)?.iter().map(|(t,p)|value!([t,hex(p)])).collect::<Vec<_>>()})),
        "encode"=>Ok(value!({"hex":hex(&frame(v)?.encode(format(v)?)?)})),
        "decode"=>{
            let mut d=Decoder::new(format(v)?);let mut out=Vec::new();
            for c in chunks(v)?{for f in d.feed(&c)?{out.push(value!({"kind":f.kind,"flags":f.flags,"options":hex(&f.options),"payload":hex(&f.payload)}));}}d.finish()?;Ok(value!({"frames":out}))
        },
        "text"=>{
            let protocol=match string(v,"protocol")?{"DMSDP"=>"DMSDP","RTSP"=>"RTSP",_=>return Err("invalid protocol".into())};
            let mut d=Messages::new(protocol);let mut out=Vec::new();for c in chunks(v)?{for m in d.feed(&c)?{out.push(value!({"start":m.start,"headers":m.headers,"body":hex(&m.body)}));}}d.finish()?;Ok(value!({"messages":out}))
        },
        "json"=>{let mut d=json::Stream::new();let mut values=Vec::new();for c in chunks(v)?{values.extend(d.feed(&c)?);}d.finish()?;Ok(value!({"values":values}))},
        "envelope"=>{let (op,data)=json::envelope(string(v,"data")?.as_bytes(),v["identity_seen"]==true)?;Ok(value!({"operation":op,"data":data}))},
        "adts"=>Ok(value!({"frames":media::adts(&bytes(v,"data")?)?.iter().map(|f|value!({"data":hex(&f.data),"rate":f.rate,"channels":f.channels,"samples":f.samples})).collect::<Vec<_>>()})),
        "audio"=>{
            let mut a=media::Audio::new();let mut out=Vec::new();for c in chunks(v)?{for f in a.receive(&c)?{
                out.push(value!({"data":hex(&f.aac.data),"rate":f.aac.rate,"channels":f.aac.channels,"samples":f.aac.samples,"rtp_timestamp":f.timestamp,"stream":f.stream,"timestamp_offset_samples":f.sample_offset}));
            }}Ok(value!({"frames":out,"lost":a.lost,"duplicates":a.duplicates,"packets":a.packets,"samples":a.samples}))
        },
        "clock"=>{let offset=v["offset"].as_i64().ok_or("invalid clock offset")?;
            Ok(value!({"local_pts":media::local_rtp_time(bounded_u32(v,"timestamp")?,number(v,"now")?,offset,number(v,"updated")?)}))},
        "touch"=>{let x=number(v,"x")?.try_into().map_err(|_|"x outside u16")?;let y=number(v,"y")?.try_into().map_err(|_|"y outside u16")?;
            let action=number(v,"action")?.try_into().map_err(|_|"action outside u8")?;Ok(value!({"hex":hex(&media::touch(x,y,action,bounded_u32(v,"elapsed")?)?)}))},
        "key"=>Ok(value!({"hex":hex(&media::key(string(v,"name")?,v["down"].as_bool().ok_or("invalid key action")?)?)})),
        "identity"=>{let id=super::identity::Identity::parse(string(v,"record")?.as_bytes())?;
            Ok(value!({"wire_id":id.wire_id(string(v,"model")?,string(v,"address")?,&Crypto::load()?)?}))},
        "cipher"=>Ok(value!({"hex":hex(&Crypto::load()?.transform(&bytes(v,"key")?,&bytes(v,"iv")?,&bytes(v,"data")?)?)})),
        "video"=>{
            let mut d=media::Video::new();let crypto=Crypto::load()?;let key=bytes(v,"key")?;let mut out=Vec::new();
            for c in chunks(v)?{if let Some((kind,timestamp,data))=d.receive(&c)?{out.push(value!({"kind":kind,"timestamp":timestamp,"data":hex(&crypto.transform(&key,&data[..16],&data[16..])?)}));}}
            Ok(value!({"frames":out}))
        },
        _=>Err("unknown codec operation".into()),
    }
}
const MAX_LINE:u64=8*1024*1024;
fn line(input:&mut impl BufRead)->Result<Option<Value>>{
    let mut data=Vec::new();let n=input.take(MAX_LINE+1).read_until(b'\n',&mut data).map_err(|_|"cannot read development input")?;
    if n==0{return Ok(None);}if n as u64>MAX_LINE{return Err("development input exceeds limit".into());}
    // Codec requests can hold large hex media; use the strict JSON visitor with
    // a distinct outer diagnostic limit rather than the 64 KiB business limit.
    serde_json::from_slice(&data).map(Some).map_err(|_|"invalid development JSON".into())
}
fn send(v:&Value)->Result<()>{let mut out=io::stdout().lock();serde_json::to_writer(&mut out,v).map_err(|_|"cannot write development output")?;
    out.write_all(b"\n").and_then(|_|out.flush()).map_err(|_|"cannot flush development output".into())}
pub fn run(args:&[String])->Result<()>{
    let mut input=io::stdin().lock();
    match args.first().map(String::as_str){
        Some("run")=>super::backend::run(&args[1..]),
        Some("media-worker") if args.len()==2=>super::live::run(args[1].parse().map_err(|_|"invalid private socket fd")?),
        Some("radio-worker") if args.len()==2=>super::radio::run(args[1].parse().map_err(|_|"invalid private socket fd")?),
        Some("codec") if args.len()==1=>{while let Some(v)=line(&mut input)?{send(&match codec(&v){Ok(v)=>value!({"ok":true,"result":v}),Err(e)=>value!({"ok":false,"error":e})})?;}Ok(())},
        #[cfg(unix)]
        Some("auth-worker") if args.len()==1=>auth_worker(&mut input),
        #[cfg(unix)]
        Some("session-worker") if args.len()==2=>super::session::worker::run(args[1].parse().map_err(|_|"invalid private socket fd")?),
        #[cfg(unix)]
        Some("identity-check") if args.len()==1=>{
            let config=line(&mut input)?.ok_or("missing identity check configuration")?;
            let id=super::identity::Identity::load(std::path::Path::new(string(&config,"path")?))?;
            let crypto=Crypto::load()?;let wire=id.wire_id(string(&config,"model")?,string(&config,"address")?,&crypto)?;
            send(&value!({"schema":1,"wire_identity_sha256":hex(&crypto.sha256(wire.as_bytes())?),
                "hardware_seed_sha256":hex(&crypto.sha256(id.device_id.as_bytes())?),"name_length":id.name.chars().count()}))
        },
        _=>Err("Usage: hellocar codec | auth-worker | identity-check | session-worker FD (private adapter IPC)".into()),
    }
}
#[cfg(unix)]fn auth_worker(input:&mut impl BufRead)->Result<()>{
    use super::native::{Runtime,Session};use std::path::Path;
    let config=line(input)?.ok_or("missing private auth configuration")?;
    let runtime=Runtime::open(Path::new(string(&config,"library")?),Path::new(string(&config,"store")?),string(&config,"hardwareSeed")?)?;
    let role=number(&config,"role")?;if !matches!(role,1|2){return Err("invalid auth role".into());}
    let mut session=None;send(&value!({"ready":true}))?;
    while let Some(command)=line(input)?{
        let result:Result<Value>=(||{
            let (code,packets)=match string(&command,"op")?{
                "close"=>return Ok(value!({"closed":true})),
                "begin"=>{
                    let mut s=Session::new(&runtime,string(&config,"own")?,string(&config,"peer")?,string(&config,"pin")?,role as i32)?;
                    let result=if role==1{s.start(command["phase"]=="auth")?}else{(0,vec![])};session=Some(s);result
                },
                "receive"=>session.as_mut().ok_or("session not started")?.receive(string(&command,"data")?.as_bytes())?,
                _=>return Err("unknown auth command".into()),
            };
            let s=session.as_ref().ok_or("session not initialized")?;let summary=s.key_summary()?;
            let packets:Vec<String>=packets.into_iter().map(String::from_utf8).collect::<std::result::Result<_,_>>().map_err(|_|"native output is not UTF-8")?;
            Ok(value!({"code":code,"packets":packets,"results":s.results(),"key_hash":summary.as_ref().map(|v|&v.0),"key_length":summary.map(|v|v.1)}))
        })();
        match result{Ok(v)=>{let closed=v["closed"]==true;send(&v)?;if closed{break;}},Err(e)=>{send(&value!({"error":e}))?;break;}}
    }Ok(())
}
