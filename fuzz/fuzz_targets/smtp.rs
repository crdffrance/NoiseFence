#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len()>2048{return;}
    if let Ok(s)=std::str::from_utf8(data){let _=noisefence::smtp::parse_path(s,"FROM:",true);let _=noisefence::smtp::parse_path(s,"TO:",false);}
    let runtime=tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    runtime.block_on(async {let mut reader=tokio::io::BufReader::new(data);let _=noisefence::smtp::line(&mut reader,512,1).await;});
});
