# Protocoles et dépendances

Les versions exactes sont verrouillées dans `Cargo.lock` et `web/package-lock.json`.
La compilation courante utilise `mail-auth 0.12.1`, `mail-parser 0.11.8`, Tokio,
rustls et SQLite embarqué. Les sessions SMTP, la persistance, les tentatives de
livraison, le moteur de score et l’entraînement sont implémentés dans ce projet.

| Référence | Application et limites |
|---|---|
| [SMTP RFC 5321](https://www.rfc-editor.org/rfc/rfc5321) | Enveloppes, transactions, CRLF/dot-stuffing, réponses, responsabilité après 250, tentatives et échecs. Les domaines littéraux et routes source obsolètes restent hors périmètre. |
| [SIZE RFC 1870](https://www.rfc-editor.org/rfc/rfc1870) | Taille annoncée et limite effective du DATA. |
| [8BITMIME RFC 6152](https://www.rfc-editor.org/rfc/rfc6152) | Corps 8 bits relayés uniquement à un relais annonçant la capacité. |
| [PIPELINING RFC 2920](https://www.rfc-editor.org/rfc/rfc2920) | Commandes traitées et réponses ordonnées ; frontière DATA et STARTTLS stricte. |
| [STARTTLS RFC 3207](https://www.rfc-editor.org/rfc/rfc3207) | Session remise à zéro après négociation ; certificat du relais vérifié. |
| [Messages RFC 5322](https://www.rfc-editor.org/rfc/rfc5322), [RFC 2047](https://www.rfc-editor.org/rfc/rfc2047) | En-têtes pliés et objets encodés préservés, corps inchangé. Les en-têtes UTF-8 bruts nécessitent SMTPUTF8, désactivé. |
| [SPF RFC 7208](https://www.rfc-editor.org/rfc/rfc7208), [DKIM RFC 6376](https://www.rfc-editor.org/rfc/rfc6376) | Vérification sur l’IP réelle et l’original, avant toute modification. |
| [DMARC RFC 9989](https://www.rfc-editor.org/info/rfc9989/) | `mail-auth 0.12.1` implémente la recherche DNS hiérarchique et l’alignement ; contrôle du code de `src/dmarc/verify.rs` effectué. Pas de rapports agrégés DMARC dans cette version. |
| [ARC RFC 8617](https://www.rfc-editor.org/rfc/rfc8617) | Vérification de la chaîne d’origine et scellement après marquage. Aucune hypothèse de confiance automatique chez Proton. |
| [Authentication-Results RFC 8601](https://www.rfc-editor.org/rfc/rfc8601) | Résultats entrants supprimés après vérification de l’original, résultats locaux reconstruits. |
| [DSN RFC 3464](https://www.rfc-editor.org/rfc/rfc3464) | Avis multipart/report, destinataire en échec et expéditeur d’enveloppe vide. L’extension ESMTP DSN n’est pas annoncée. |

Ce tableau définit le périmètre développé. Il ne constitue pas une certification
de conformité à toutes les exigences et options des RFC. Les tests d’interopérabilité
et de livraison réels restent nécessaires avant changement des MX.
