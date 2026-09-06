#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len()>64*1024{return;}
    let _=noisefence::message::validate(data);
    let _=noisefence::message::rewrite(data,true,"X-NoiseFence-Score: 99\r\n");
    let _=noisefence::engine::extract(data,64*1024);
    let _=noisefence::features::extract(data,64*1024);
    let _=noisefence::engine::domains_in_message(data);
});
