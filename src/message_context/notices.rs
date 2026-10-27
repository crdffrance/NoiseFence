//! Structured event context, not sender trust. A title alone never qualifies.
//! Authentication, scanner coverage and threat vetoes remain in decision.rs.
use regex::Regex;
use std::sync::LazyLock;

fn normalized(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

static AMOUNT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\b(?:eur|usd|gbp)\s*[0-9]+[.,][0-9]{2}\b|[€$£]\s*[0-9]+[.,][0-9]{2}\b|\b[0-9]+[.,][0-9]{2}\s*(?:€|\$|£|eur\b|usd\b|gbp\b))").unwrap()
});
static DATE: LazyLock<Regex> = LazyLock::new(|| {
    // HTML table labels may touch their values after text extraction (à2026/…).
    // Numeric boundaries retain the whole-date requirement without changing the
    // model's feature extraction protocol or treating layout as suspicious.
    Regex::new(r"(?:^|[^0-9])(?:20[0-9]{2}[-/][0-9]{1,2}[-/][0-9]{1,2}|[0-9]{1,2}[-/][0-9]{1,2}[-/]20[0-9]{2}|[0-9]{1,2} (?:janvier|f[eé]vrier|mars|avril|mai|juin|juillet|ao[uû]t|septembre|octobre|novembre|d[eé]cembre) 20[0-9]{2})(?:$|[^0-9])").unwrap()
});

pub(super) fn transaction(subject: &str, body: &str) -> bool {
    let body = normalized(body);
    if !AMOUNT.is_match(&body) {
        return false;
    }
    static BILL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b(?:facture|facturation|invoice|billing|paiement programm[eé]|upcoming (?:automatic )?payment)\b").unwrap()
    });
    static DEBIT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b(?:ce montant sera pr[eé]lev[eé]|sera pr[eé]lev[eé] sur votre (?:carte|compte)|facture sera pay[eé]e automatiquement|will be (?:automatically )?(?:charged|debited) (?:to|from) your (?:card|account))\b").unwrap()
    });
    // An already scheduled debit has an amount, date and explicit automatic
    // collection. A bill requesting a new payment is deliberately insufficient.
    let scheduled = BILL.is_match(subject) && DEBIT.is_match(&body) && DATE.is_match(&body);
    static RECEIPT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b(?:re[cç]u de votre paiement|payment receipt|receipt for your payment)\b")
            .unwrap()
    });
    static PAID: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"\b(?:vous avez (?:envoy[eé]|effectu[eé]) un paiement|you (?:sent|made) a payment)\b",
        )
        .unwrap()
    });
    static REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b(?:transaction (?:id|number)|(?:num[eé]ro|n[°o]) de transaction)\s*:?\s*[a-z0-9][a-z0-9-]{3,40}\b").unwrap()
    });
    let receipt = RECEIPT.is_match(subject) && PAID.is_match(&body) && REFERENCE.is_match(&body);
    static ORDER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\byour\b.{0,40}\border\b").unwrap());
    let order = ORDER.is_match(subject)
        && body.contains("thanks for ordering")
        && body.contains("total")
        && body.contains("payments")
        && DATE.is_match(&body);
    scheduled || receipt || order
}

pub(super) fn service(subject: &str, body: &str) -> bool {
    let body = normalized(body);
    static MONITOR: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^monitor is (?:up|down):\s*\S").unwrap());
    let monitor = MONITOR.is_match(subject)
        && body.contains("monitor name")
        && body.contains("checked url")
        && body.contains("incident started at")
        && body.contains("root cause")
        && DATE.is_match(&body);
    static BACKUP: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b(?:t[aâ]che de sauvegarde|backup (?:task|job))\b").unwrap()
    });
    static EVENT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b(?:[eé]chec|suspendue?|r[eé]solu|failed|suspended|resolved)\b").unwrap()
    });
    static HOST: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b(?:hôte|host)[:\s]*[a-z0-9]").unwrap());
    let backup = BACKUP.is_match(subject)
        && EVENT.is_match(subject)
        && HOST.is_match(&body)
        && (body.contains("événement détecté à") || body.contains("event detected at"))
        && DATE.is_match(&body)
        && (body.contains("rapport a été généré automatiquement")
            || body.contains("report was generated automatically"));
    static APPLICATION: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b(?:candidature|application)\b").unwrap());
    let application = APPLICATION.is_match(subject)
        && [
            "remercions pour ta candidature",
            "remercions pour votre candidature",
            "thank you for your application",
            "we have received your application",
        ]
        .iter()
        .any(|p| body.contains(p))
        && [
            "l'étudier",
            "l’étudier",
            "étudier votre candidature",
            "review your application",
            "reviewing your application",
        ]
        .iter()
        .any(|p| body.contains(p));
    monitor || backup || application
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn financial_events_need_details_and_an_existing_transaction() {
        assert!(transaction(
            "votre facture est arrivée",
            "Facture du 06/10/2026 : 12,34 €. Ce montant sera prélevé le 16/10/2026."
        ));
        assert!(transaction(
            "paiement programmé à venir",
            "12,34 € sera prélevé sur votre carte **** 1234 le 12 octobre 2026."
        ));
        assert!(transaction(
            "reçu de votre paiement",
            "Vous avez envoyé un paiement de 12,34 €. Numéro de transaction : AB1234XYZ."
        ));
        for body in [
            "Facture urgente : payez maintenant 12,34 €.",
            "Ce montant sera prélevé bientôt.",
            "12,34 € sera prélevé sur votre carte.",
        ] {
            assert!(!transaction("votre facture", body), "{body}");
        }
        assert!(!transaction(
            "reçu de votre paiement",
            "Vous avez envoyé un paiement de 12,34 €."
        ));
    }

    #[test]
    fn operational_notifications_need_structured_body_evidence() {
        let body = "Monitor name: Example. Checked URL: https://example.test. Root cause: timeout. Incident started at 2026-10-10 12:00.";
        assert!(service("monitor is down: example", &body.to_lowercase()));
        assert!(!service(
            "monitor is down: example",
            "Your account needs an urgent update."
        ));
        assert!(!service("special offer", &body.to_lowercase()));
        assert!(service("[critique] échec de la tâche de sauvegarde", "Hôte example. Événement détecté à 2026/10/10 12:00. Ce rapport a été généré automatiquement.".to_lowercase().as_str()));
        assert!(service(
            "merci pour ta candidature !",
            "Nous te remercions pour ta candidature. Nous allons prendre le temps de l'étudier."
                .to_lowercase()
                .as_str()
        ));
        assert!(!service(
            "candidature à distance",
            "We are recruiting. Send your bank details to apply."
        ));
    }

    #[test]
    fn adjacent_html_table_labels_preserve_event_context() {
        let raw = b"Subject: Backup job failed\r\nContent-Type: text/html\r\n\r\n<table><tr><td>Host</td><td>example</td></tr><tr><td>Event detected at</td><td>2026/10/10 12:00</td></tr></table><p>This report was generated automatically.</p>";
        assert!(crate::message_context::inspect(raw).passive_service_notice);
        assert!(!service(
            "backup job failed",
            "Host example. Event detected at unknown. This report was generated automatically."
        ));
    }
}
