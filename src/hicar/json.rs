//! Strict business JSON, including duplicate-key rejection at every depth.
use super::Result;
use serde::{Deserialize,Deserializer,de::{self,Visitor,MapAccess,SeqAccess}};
use serde_json::{Value,Map,Number};
use std::fmt;

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D:Deserializer<'de>>(d:D)->std::result::Result<Self,D::Error>{
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value=Strict;
            fn expecting(&self,f:&mut fmt::Formatter)->fmt::Result{f.write_str("strict JSON value")}
            fn visit_bool<E:de::Error>(self,v:bool)->std::result::Result<Strict,E>{Ok(Strict(v.into()))}
            fn visit_i64<E:de::Error>(self,v:i64)->std::result::Result<Strict,E>{Ok(Strict(v.into()))}
            fn visit_u64<E:de::Error>(self,v:u64)->std::result::Result<Strict,E>{Ok(Strict(v.into()))}
            fn visit_f64<E:de::Error>(self,v:f64)->std::result::Result<Strict,E>{Number::from_f64(v).map(|n|Strict(Value::Number(n))).ok_or_else(||E::custom("non-finite JSON"))}
            fn visit_str<E:de::Error>(self,v:&str)->std::result::Result<Strict,E>{Ok(Strict(v.into()))}
            fn visit_string<E:de::Error>(self,v:String)->std::result::Result<Strict,E>{Ok(Strict(v.into()))}
            fn visit_unit<E:de::Error>(self)->std::result::Result<Strict,E>{Ok(Strict(Value::Null))}
            fn visit_seq<A:SeqAccess<'de>>(self,mut a:A)->std::result::Result<Strict,A::Error>{let mut v=Vec::new();while let Some(Strict(i))=a.next_element()?{v.push(i);}Ok(Strict(v.into()))}
            fn visit_map<A:MapAccess<'de>>(self,mut a:A)->std::result::Result<Strict,A::Error>{
                let mut m=Map::new();while let Some((k,Strict(v)))=a.next_entry::<String,Strict>()?{
                    if m.insert(k,v).is_some(){return Err(de::Error::custom("duplicate JSON field"));}
                }Ok(Strict(Value::Object(m)))
            }
        }d.deserialize_any(V)
    }
}
pub fn parse(data:&[u8])->Result<Value>{
    if data.is_empty()||data.len()>65536{return Err("JSON size outside limit".into());}
    serde_json::from_slice::<Strict>(data).map(|s|s.0).map_err(|_|"invalid strict JSON".into())
}
pub struct Stream {buffer:Vec<u8>,depth:usize,quoted:bool,escaped:bool,failed:bool}
impl Stream {
    pub fn new()->Self{Self{buffer:Vec::new(),depth:0,quoted:false,escaped:false,failed:false}}
    pub fn feed(&mut self,data:&[u8])->Result<Vec<Value>>{
        if self.failed{return Err("JSON stream requires reset".into());}
        let result=(||{
            let mut values=Vec::new();for &b in data {
                if self.buffer.is_empty()&&b.is_ascii_whitespace(){continue;}
                if self.buffer.is_empty()&&b!=b'{'{return Err("expected JSON object".into());}
                self.buffer.push(b);if self.buffer.len()>65536{return Err("JSON exceeds limit".into());}
                if self.quoted {
                    if self.escaped{self.escaped=false;}else if b==b'\\'{self.escaped=true;}else if b==b'"'{self.quoted=false;}
                }else{match b {
                    b'"'=>self.quoted=true,
                    b'{'|b'['=>{self.depth+=1;if self.depth>32{return Err("JSON nesting exceeds limit".into());}},
                    b'}'|b']'=>{self.depth=self.depth.checked_sub(1).ok_or("invalid JSON nesting")?;
                        if self.depth==0{values.push(parse(&self.buffer)?);self.buffer.clear();}},
                    _=>{},
                }}
            }
            if let Err(e)=std::str::from_utf8(&self.buffer){if e.error_len().is_some(){return Err("invalid UTF-8".into());}}
            Ok(values)
        })();
        if result.is_err(){self.failed=true;self.buffer.clear();}result
    }
    pub fn finish(&self)->Result<()>{if self.failed||!self.buffer.is_empty(){Err("incomplete or failed JSON stream".into())}else{Ok(())}}
}

pub fn envelope(data:&[u8],identity_seen:bool)->Result<(u64,Value)> {
    let outer=parse(data)?;let map=outer.as_object().ok_or("auth envelope must be an object")?;
    // A_0/discover_type=1 describe our response. Harmony 4.2 sends its own
    // application version (observed 14.2.0.400) and omits discover_type.
    if map.get("version").is_some_and(|v|!v.as_str().is_some_and(|s|!s.is_empty()&&s.len()<=32&&s.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'.'|b'_'|b'-'))))
        || map.get("discover_type").is_some_and(|v|!v.as_u64().is_some_and(|n|n<=255))
        || map.get("usb_connection").is_some_and(|v|v!=&Value::Bool(false)) {return Err("unsupported auth envelope metadata".into());}
    let operation=map.get("oper_type").and_then(Value::as_u64).ok_or("invalid auth operation")?;
    if !matches!(operation,1|3)||operation==3&&!identity_seen{return Err("invalid auth sequence".into());}
    let inner=parse(map.get("data").and_then(Value::as_str).ok_or("auth data must be JSON text")?.as_bytes())?;
    if !inner.is_object(){return Err("auth body must be object".into());}
    if operation==1 {
        if identity_seen||inner.get("usb_connection").is_some_and(|v|v!=&Value::Bool(false)){return Err("invalid wireless identity handshake".into());}
        let id=inner.get("deviceId").and_then(Value::as_str).ok_or("peer identity absent")?;
        if id.is_empty()||id.len()>64{return Err("peer identity outside limit".into());}}
    Ok((operation,inner))
}

#[cfg(test)]mod tests {
    use super::*;
    #[test]fn split_utf8_escaping_and_coalescing(){
        let bytes="{\"x\":\"中文}\\\"\"}{\"a\":1}".as_bytes();
        for split in 0..=bytes.len(){let mut s=Stream::new();let mut out=s.feed(&bytes[..split]).unwrap();out.extend(s.feed(&bytes[split..]).unwrap());s.finish().unwrap();assert_eq!(out.len(),2);}
    }
    #[test]fn duplicate_nested_constant_and_poison(){
        for input in [b"{\"x\":1,\"x\":2}".as_slice(),b"{\"x\":{\"a\":1,\"a\":2}}",b"{\"x\":NaN}"]{assert!(parse(input).is_err());}
        let mut s=Stream::new();assert!(s.feed(&[b'{';33]).is_err());assert!(s.feed(b"{}").is_err());
    }
    #[test]fn wireless_envelope_sequence_and_peer_limits(){
        let request=|operation:u64,inner:Value|serde_json::to_vec(&serde_json::json!({
            "version":"A_0","discover_type":1,"oper_type":operation,"data":inner.to_string(),"usb_connection":false})).unwrap();
        let identity=request(1,serde_json::json!({"deviceId":"AB".repeat(32)}));
        assert_eq!(envelope(&identity,false).unwrap().0,1);
        assert!(envelope(&identity,true).is_err());
        assert!(envelope(&request(1,serde_json::json!({"deviceId":"X".repeat(65)})),false).is_err());
        assert!(envelope(&request(1,serde_json::json!({"deviceId":"peer","usb_connection":true})),false).is_err());
        let auth=request(3,serde_json::json!({"message":17}));
        assert!(envelope(&auth,false).is_err());assert_eq!(envelope(&auth,true).unwrap().0,3);
    }
    #[test]fn harmony_request_metadata_differs_from_accessory_response(){
        let request=serde_json::json!({"version":"14.2.0.400","oper_type":1,"synctime":0,"trace_id":"synthetic",
            "data":serde_json::json!({"deviceId":"synthetic-peer","usb_connection":false,"has_pin":false}).to_string()});
        assert_eq!(envelope(request.to_string().as_bytes(),false).unwrap().0,1);
        let mut bad=request;bad["version"]=true.into();assert!(envelope(bad.to_string().as_bytes(),false).is_err());
    }
}
