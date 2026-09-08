mod common;
use noisefence::{
    engine::Engine,
    mailing::{self, Category, Policy, Settings, Status, Verdict},
    message::{self, SubjectTag},
};
use std::sync::Arc;

fn mail(subject: &str, headers: &str, body: &str) -> Vec<u8> {
    format!("From: Offers <offers@example.org>\r\nTo: alice@example.test\r\nSubject: {}\r\nDate: Wed, 09 Sep 2026 10:00:00 +0000\r\nMessage-ID: <pub-test@example.org>\r\n{headers}\r\n{body}\r\n", message::encoded_subject(subject)).into_bytes()
}
const LIST: &str = "List-Unsubscribe: <https://example.org/unsubscribe>\r\nList-ID: Offers <offers.example.org>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n";
const OFFER: &str = "Offres exclusives : achetez maintenant, livraison offerte. Se désabonner.";
fn inspect(subject: &str, headers: &str, body: &str) -> mailing::Report {
    mailing::inspect(
        &mail(subject, headers, body),
        &Policy::default(),
        2 * 1024 * 1024,
    )
}
#[test]
fn commercial_distribution_requires_concordant_content() {
    assert!(!mailing::inspect(common::MESSAGE, &Policy::default(), 10000).is_publicity());
    for (subject, headers, body) in [
        ("Offres exclusives", LIST, OFFER),
        (
            "Our special offer",
            "",
            "Shop now. Free shipping. Unsubscribe",
        ),
        (
            "Nos promotions",
            LIST,
            "<html><body>Achetez maintenant. Livraison offerte.</body></html>",
        ),
    ] {
        let report = inspect(subject, headers, body);
        assert_eq!(report.verdict, Verdict::Promotion, "{report:?}");
    }
    for headers in [
        LIST,
        "Precedence: bulk\r\n",
        "List-ID: Team <team.example.org>\r\n",
        "X-NoiseFence-Category: publicity\r\n",
    ] {
        assert!(!inspect("Bonjour", headers, "Voici les nouvelles du projet.").is_publicity());
    }
    assert!(!inspect("Promotions", LIST, "Bonjour.").is_publicity());
    assert!(!inspect("Bonjour", "", "Offres exclusives. Achetez maintenant.").is_publicity());
    assert!(!inspect("[PUB] Bonjour", "X-NoiseFence-Status: pub\r\n", "Bonjour.").is_publicity());
}
#[test]
fn newsletters_are_configurable_and_discussions_are_excluded() {
    let raw = mail(
        "La lettre d'information hebdomadaire",
        LIST,
        "Les nouvelles de la semaine.",
    );
    assert_eq!(
        mailing::inspect(&raw, &Policy::default(), 10000).verdict,
        Verdict::Newsletter
    );
    assert!(
        !mailing::inspect(
            &raw,
            &Policy {
                include_newsletters: false,
                ..Policy::default()
            },
            10000
        )
        .is_publicity()
    );
    for extra in [
        "In-Reply-To: <original@example.org>\r\n",
        "References: <original@example.org>\r\n",
        "List-Post: <mailto:team@example.org>\r\n",
    ] {
        assert_eq!(
            inspect("Newsletter", &format!("{LIST}{extra}"), OFFER).verdict,
            Verdict::Conversation
        );
    }
    assert_eq!(
        inspect("Re: Offres exclusives", LIST, OFFER).verdict,
        Verdict::Conversation
    );
}
#[test]
fn transactions_and_security_alerts_win_over_promotional_footers() {
    for subject in [
        "Votre facture de septembre",
        "Reçu de paiement",
        "Order confirmation #123",
        "Code de connexion",
        "Your verification code",
        "Alerte de sécurité",
        "Password reset",
        "Rendez-vous demain",
        "Votre colis est arrivé",
    ] {
        assert_eq!(
            inspect(subject, LIST, OFFER).verdict,
            Verdict::Transactional,
            "{subject}"
        );
    }
    for headers in [
        "Auto-Submitted: auto-replied\r\n",
        "Content-Type: multipart/report; boundary=x\r\n",
        "Content-Type: text/calendar\r\n",
    ] {
        assert_eq!(
            inspect("Bonjour", &format!("{LIST}{headers}"), OFFER).verdict,
            Verdict::Transactional
        );
    }
    assert_eq!(
        inspect(
            "Merci",
            LIST,
            &format!("Votre code de vérification : 123456. {OFFER}")
        )
        .verdict,
        Verdict::Transactional
    );
}
#[test]
fn decoded_html_and_bounded_inputs() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let raw = mail(
        "Promotions",
        &format!(
            "{LIST}Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n"
        ),
        &STANDARD.encode("<p>Achetez maintenant. Livraison offerte.</p>"),
    );
    assert_eq!(
        mailing::inspect(&raw, &Policy::default(), 10000).verdict,
        Verdict::Promotion
    );
    for raw in [
        mail("Offres", LIST, &"x".repeat(32_001)),
        mail(&"x".repeat(501), LIST, OFFER),
        mail("Offres", &format!("{LIST}{LIST}"), OFFER),
        b"bad header\r\n\r\nbody\r\n".to_vec(),
    ] {
        let r = mailing::inspect(&raw, &Policy::default(), 2 * 1024 * 1024);
        assert_eq!(r.status, Status::Limited);
        assert!(!r.is_publicity());
    }
    assert_eq!(
        mailing::inspect(&raw, &Policy::default(), 10).status,
        Status::Limited
    );
    assert!(
        !inspect(
            "Bonjour",
            &format!("{LIST}Content-Type: text/html\r\n"),
            "<script>Offres exclusives. Achetez maintenant.</script><p>Bonjour.</p>"
        )
        .is_publicity()
    );
}
#[test]
fn subject_prefixes_are_exclusive_idempotent_and_preserve_the_body() {
    for original in [
        "Été à Montréal 🎁",
        "[SPAM] Été à Montréal 🎁",
        "[PUB] Été à Montréal 🎁",
        "[pub] [SPAM] [PUB] Été à Montréal 🎁",
    ] {
        let raw = mail(
            original,
            "X-NoiseFence-Category: publicity\r\n",
            "raw body =abc\r\n..dot",
        );
        for tag in [SubjectTag::Publicity, SubjectTag::Spam] {
            let marked =
                message::rewrite_with_tag(&raw, Some(tag), "X-NoiseFence-Category: own-result\r\n")
                    .unwrap();
            let parsed = mail_parser::MessageParser::default()
                .parse(&marked)
                .unwrap();
            assert_eq!(
                parsed.subject(),
                Some(format!("{} Été à Montréal 🎁", tag.prefix()).as_str())
            );
            assert_eq!(
                message::fields(&raw).unwrap().1,
                message::fields(&marked).unwrap().1
            );
            let again = message::rewrite_with_tag(
                &marked,
                Some(tag),
                "X-NoiseFence-Category: own-result\r\n",
            )
            .unwrap();
            assert_eq!(marked, again);
            assert_eq!(
                String::from_utf8_lossy(&marked)
                    .matches("X-NoiseFence-Category:")
                    .count(),
                1
            );
            message::validate(&marked).unwrap();
        }
    }
    let raw = mail(&format!("[SPAM] {}", "été ".repeat(200)), "", "body");
    let marked = message::rewrite_with_tag(&raw, Some(SubjectTag::Publicity), "").unwrap();
    assert!(
        message::fields(&marked)
            .unwrap()
            .0
            .iter()
            .flat_map(|h| h.split(|b| *b == b'\n'))
            .all(|l| l.len() <= 999)
    );
    let no_subject = b"From: a@example.org\r\n\r\nbody\r\n";
    assert!(
        String::from_utf8_lossy(
            &message::rewrite_with_tag(no_subject, Some(SubjectTag::Publicity), "").unwrap()
        )
        .contains("Subject: [PUB]\r\n")
    );
}
#[tokio::test]
async fn mailing_does_not_change_security_and_incomplete_never_becomes_pub() {
    let root = tempfile::tempdir().unwrap();
    let plain = common::config(root.path());
    let mut cfg = (*plain).clone();
    cfg.mailing = Some(Settings::default());
    let raw = mail("Offres exclusives", LIST, OFFER);
    let baseline = Engine::new(plain).unwrap().offline(&raw);
    let engine = Engine::new(Arc::new(cfg)).unwrap();
    let mut detected = engine.offline(&raw);
    assert_eq!(detected.score, baseline.score);
    assert_eq!(detected.features, baseline.features);
    assert_eq!(
        serde_json::to_value(&detected.decision).unwrap(),
        serde_json::to_value(&baseline.decision).unwrap()
    );
    assert_eq!(mailing::category(&detected, 95.0), Category::Publicity);
    detected.decision = None;
    detected.score = 99.;
    assert_eq!(mailing::category(&detected, 95.0), Category::Spam);
    detected.complete = false;
    assert_eq!(mailing::category(&detected, 95.0), Category::Undetermined);
    let (scan, wire) = engine
        .process(
            &raw,
            "192.0.2.1".parse().unwrap(),
            "mail.example.org",
            "offers@example.org",
            "test",
        )
        .await
        .unwrap();
    assert_eq!(mailing::category(&scan, 95.), Category::Publicity);
    assert!(!scan.pub_tagged && !scan.tagged);
    assert!(String::from_utf8_lossy(&wire).contains("X-NoiseFence-Category: publicity"));
    assert_eq!(
        mail_parser::MessageParser::default()
            .parse(&raw)
            .unwrap()
            .subject(),
        mail_parser::MessageParser::default()
            .parse(&wire)
            .unwrap()
            .subject()
    );
}
