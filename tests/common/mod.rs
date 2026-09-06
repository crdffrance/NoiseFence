use std::sync::Arc;
pub fn config(root: &std::path::Path) -> Arc<noisefence::config::Config> {
    let mut c: noisefence::config::Config =
        toml::from_str(include_str!("../../config/development.toml")).unwrap();
    c.data_dir = root.into();
    c.smtp.listen = "127.0.0.1:0".parse().unwrap();
    c.web.listen = "127.0.0.1:0".parse().unwrap();
    c.smtp.minimum_free_bytes = 0;
    c.validate().unwrap();
    Arc::new(c)
}
pub const MESSAGE:&[u8]=b"From: Sender <sender@example.org>\r\nTo: alice@example.test\r\nSubject: Rendez-vous demain\r\nDate: Sun, 06 Sep 2026 12:00:00 +0000\r\nMessage-ID: <test@example.org>\r\n\r\nBonjour, le rendez-vous est confirme.\r\n";
