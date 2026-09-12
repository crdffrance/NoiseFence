#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len()>64*1024{return;}
    let _=noisefence::message::validate(data);
    let _=noisefence::message::rewrite(data,true,"X-NoiseFence-Score: 99\r\n");
    let _=noisefence::mailing::inspect(data,&Default::default(),64*1024);
    let _=noisefence::message::rewrite_with_tag(data,Some(noisefence::message::SubjectTag::Publicity),"");
    let _=noisefence::engine::extract(data,64*1024);
    let _=noisefence::features::extract(data,64*1024);
    let _=noisefence::native_filter::content_rules::Settings::default().inspect(data);
    if let Ok(input)=noisefence::native_filter::input::extract(data,64*1024) {
        assert!(input.features.validate().is_ok());
        static MATCHER:std::sync::OnceLock<noisefence::native_filter::rules::Matcher>=std::sync::OnceLock::new();
        let matcher=MATCHER.get_or_init(||noisefence::native_filter::rules::Matcher::compile(&noisefence::native_filter::rules::default_patterns()).unwrap());
        let symbols=matcher.inspect(&input);
        assert!(noisefence::adaptive::valid_vector(&noisefence::adaptive::vector(&input,&symbols)));
    }
    let _=noisefence::engine::domains_in_message(data);
});
