# Admission SMTP expérimentale : greylisting et teergrubing

`src/smtp_admission.rs` fournit une décision **par destinataire à RCPT**, avant
DATA et avant toute acceptation durable. Le module ne reçoit pas de corps,
n'accepte ni ne livre de message et n'envoie jamais de challenge ou d'email de
vérification. Son résultat porte la version `smtp-admission-1`.

Il est désactivé par défaut. Son mode par défaut est `observe` : une activation
seule collecte des décisions hypothétiques, sans réponse de refus ni sommeil
artificiel. Le raccordement est présent dans `Config`, Engine, la réception RCPT
et la maintenance du Store. Les décisions apparaissent dans les logs SMTP ;
elles ne sont pas ajoutées aux diagnostics de message ni au résultat `Scan`.
L'analyse hors SMTP ne simule pas de tentative de greylisting. Aucun réglage de
production n'est activé par cette implémentation.

Le greylisting mesure la capacité à réessayer, pas la légitimité d'un message.
Les retards de livraison et les changements de serveur sortant doivent être
mesurés avant une expérimentation en enforcement. Le
[RFC 6647](https://www.rfc-editor.org/rfc/rfc6647.html) décrit ces compromis ; les
tests synthétiques ne démontrent aucun gain de capture sur le trafic réel.

## Réglages et activation explicite

Table facultative de premier niveau, lue par
`Config.smtp_admission: Option<Settings>` :

```toml
[smtp_admission]
enabled = false
mode = "observe"
retry_delay_seconds = 300
retry_max_age_seconds = 86400
retention_seconds = 604800
max_entries = 10000
tarpit_delay_ms = 0
tarpit_max_concurrent = 8
tarpit_session_budget_ms = 5000
```

`Config::validate()` appelle `Settings::validate()` ; les valeurs hors limites
et les champs inconnus sont rejetés. Une table absente désactive la fonctionnalité.
Pour observer, choisir `enabled = true`, `mode = "observe"`. Le report SMTP
réelle exige **à la fois** `enabled = true` et `mode = "enforce"`. Le tarpit
exige en plus `tarpit_delay_ms > 0`. Le mode global `filter.mode = "observe"`
abaisse le mode effectif d'admission à `observe`, même si la table demande
`enforce`. Engine applique ce verrou à la construction du contrôleur ; le module
d'admission ne lit pas `Config` lui-même. En dehors du mode global d'observation,
le mode explicite de la table reste applicable.

Les réglages de cette table sont chargés depuis TOML au démarrage ; leur
modification exige un redémarrage. La console peut changer le mode global :
Engine emploie alors `with_mode()` en conservant la capacité de sommeil partagée.
Une session contrôlée adopte la nouvelle politique au prochain MAIL, après
la fin ou le reset de sa transaction courante. Une transaction déjà commencée
conserve son instantané de politique.

| Réglage | Limite validée | Sens |
|---|---|---|
| `retry_delay_seconds` | 1 à 3 600 s | Temps minimum depuis la première observation |
| `retry_max_age_seconds` | Strictement supérieur au délai, au plus 7 jours | Fin du cycle sans retry réussi |
| `retention_seconds` | 1 s à 30 jours | Durée fixe après un retry réussi |
| `max_entries` | 1 à 100 000 par mode | Capacité de tuples, sans éviction des cycles vivants |
| `tarpit_delay_ms` | 0 à 5 000 ms | Sommeil demandé avant un 451 de greylisting |
| `tarpit_max_concurrent` | 1 à 64 | Sommeils simultanés pour un contrôleur partagé |
| `tarpit_session_budget_ms` | 0 à 10 000 ms | Somme des réservations de délai par socket |

## Raccordement SMTP et interface

Au démarrage, `serve_controlled` appelle `initialize` via `Store::run` avant
d'accepter des sessions. Si le module est désactivé, cette initialisation ne
crée aucune table. Une erreur d'initialisation interrompt actuellement le
listener, **y compris en observation** ; le repli permissif décrit ci-dessous
s'applique aux contrôles RCPT d'un listener déjà démarré.

À RCPT, le parseur, les limites d'enveloppe et `Config::recipient()` passent
avant l'admission. Un destinataire inconnu reçoit 550 sans accès à l'état
de greylisting. La séquence interne est la suivante :

```rust,ignore
// Une seule instance par connexion TCP ; conserver à travers les resets SMTP.
let mut delay_budget = noisefence::smtp_admission::DelayBudget::default();

// state.engine partage Admission et un sémaphore de quatre contrôles DB.
let admission = state.engine.smtp_admission.as_ref().unwrap();
let decision = match state.engine.admission_checks.clone().try_acquire_owned() {
    Ok(permit) => {
        let checker = admission.clone();
        let sender = from.as_ref().unwrap().clone();
        let address = recipient.address.clone();
        let check = state.store.run(move |db| {
            let _permit = permit; // reste détenu si le timeout SMTP expire
            checker.check(db, peer, &sender, &address, noisefence::now())
        });
        match tokio::time::timeout(std::time::Duration::from_millis(500), check).await {
            Ok(Ok(decision)) => decision,
            _ => admission.unavailable(),
        }
    }
    Err(_) => admission.unavailable(),
};
// Un timeout peut laisser le travail DB se terminer ; unavailable ne dort pas.
// Pour un délai candidat, le contrôle a terminé et libéré le mutex DB.
let delay_outcome = admission.delay(&decision, &mut delay_budget).await;
if let Some(response) = decision.smtp_reply() {
    // reply(io, response).await?;
    // Ne pas ajouter ce destinataire à la liste acceptée ; passer au RCPT suivant.
} else {
    // Continuer les contrôles habituels puis ajouter le destinataire et répondre 250.
}
```

Signatures publiques :

```rust,ignore
Admission::new(Settings) -> anyhow::Result<Admission>
admission.with_mode(Mode) -> Admission
admission.reconfigured(Settings) -> anyhow::Result<Admission>
admission.initialize(&mut rusqlite::Connection) -> anyhow::Result<()>
admission.check(&mut rusqlite::Connection, std::net::SocketAddr,
                &str, &str, i64) -> anyhow::Result<Decision>
admission.unavailable() -> Decision
admission.prune(&mut rusqlite::Connection, i64) -> anyhow::Result<usize>
admission.delay(&Decision, &mut DelayBudget) -> impl Future<Output = DelayOutcome>
decision.smtp_reply() -> Option<&'static str>
```

Le timestamp est une heure Unix serveur en secondes, échantillonnée dans le
travail DB. Les heures négatives ou débordantes sont des erreurs. Une horloge
revenue avant `first_seen` ou `passed_at` produit `clock_skew`, sans accorder de
passage. Les délais de sommeil utilisent l'horloge monotone de Tokio.

`Decision` est sérialisable et contient `version`, `mode`, `status`,
`would_defer`, `retry_after_seconds`, `candidate_delay_ms` et `enforced`.
`smtp_reply()` est la seule décision de réponse à utiliser. `None` signifie que
cette couche permet de continuer RCPT, sans court-circuiter une autre politique
ni garantir une acceptation du message. Ne pas fonder un refus sur
`would_defer` : il reste vrai en observation. `DelayOutcome` distingue sommeil,
observation, saturation, budget épuisé et absence de délai applicable.

## Identité et confidentialité

Chaque clé associe **mode, IP de socket, empreinte MAIL FROM, empreinte RCPT TO**.
L'API exige `SocketAddr` ; l'intégrateur doit lui transmettre exclusivement le
pair réellement accepté, comme le fait la réception SMTP. Aucun HELO,
`Received`, `Authentication-Results`,
`X-Originating-IP` ou autre en-tête ne participe à cette identité. Derrière un
proxy, la clé est donc l'IP du proxy ; ne pas remplacer celle-ci par un en-tête
déclaratif pour tenter de retrouver le client.

L'IP est stockée en octets, sur 4 ou 16 octets. Une IPv4 mappée en IPv6,
par exemple `::ffff:192.0.2.7`, devient la même IPv4. Les autres IPv6 restent
entières ; aucun regroupement /24 ou /64 n'accorde de confiance. La graphie
IPv6, le port, le flowinfo et le scope ID ne font pas partie de la clé.

Les adresses sont les chemins déjà validés par le parseur SMTP, sans chevrons.
L'expéditeur nul est `""`. L'entrée est bornée à 254 octets ASCII sans contrôle.
Le module met le domaine en minuscules et conserve la casse de la partie locale.
Le raccordement lui transmet `recipient.address`, l'adresse autorisée renvoyée
par `Config::recipient()`, avec sa graphie canonique ; les variantes équivalentes
pour ce routage ont donc déjà été rapprochées. Il transmet l'adresse de l'alias,
jamais seulement `recipient.destination` : deux adresses partageant une boîte
de transfert restent séparées. Le module ne supprime pas les suffixes `+tag`.
Le RCPT spécial `postmaster` est résolu vers `relay.postmaster` avant le contrôle ;
l'API seule accepte aussi le nom nu, sans distinction de casse.

MAIL FROM et RCPT TO sont stockés sous forme d'empreintes SHA-256 avec séparation
des rôles, longueur encodée et sel aléatoire de 32 octets propre à la base.
Le sel persiste dans la même transaction d'initialisation et n'est jamais régénéré
par un redémarrage. Il ne s'agit pas d'une anonymisation : un détenteur de la base
et du sel peut tester des adresses candidates. L'IP reste une donnée personnelle.
Protéger la base, son WAL et les sauvegardes comme le spool. `Decision` ne contient
ni adresse ni IP. Le raccordement journalise toutefois l'IP de socket séparément,
avec la décision et le résultat du délai, au niveau `info` sous
`SMTP admission checked`. La rétention de ces logs dépend de l'exploitation,
pas de `retention_seconds`. Les adresses d'enveloppe n'y sont pas ajoutées par
ce contrôle. Les empreintes ne constituent jamais une preuve d'authentification.

## Transitions durables et limites de stockage

Le schéma appartient au module : `smtp_admission_meta_v1` et
`smtp_admission_entries_v1`. `initialize` est idempotent et transactionnel. Il ne
modifie ni les tables du Store, ni `PRAGMA user_version`, ni ses PRAGMAs.
Les états `observe` et `enforce` ont des espaces distincts et des capacités
distinctes : une observation ne préautorise pas une future mise en enforcement.

| Situation | État renvoyé | Effet sur le tuple |
|---|---|---|
| Absent ou expiré | `first_seen` | Début d'un cycle, 451 candidat |
| Avant le délai minimum | `too_soon` | 451 candidat, aucune prolongation |
| Délai atteint, âge maximum non atteint | `retry_passed` | Passage du tuple jusqu'à une expiration fixe |
| Déjà passé et non expiré | `passed` | Continuer, sans renouveler la rétention |
| Aucune place après nettoyage borné | `capacity` | Continuer, aucune insertion/éviction vivante |
| Erreur DB/exécuteur | `unavailable` via le caller | 451 en enforcement, continuer en observation |
| Horloge antérieure à l'état observé | `clock_skew` | Même politique temporaire, aucun passage |

La fenêtre de retry est `[first_seen + délai, first_seen + âge maximum[`. À la
borne maximale exacte, le cycle recommence. Après succès, l'expiration est
`passed_at + retention_seconds` ; même un trafic continu ne la repousse pas.
Les échéances déjà enregistrées sont conservées après un changement de réglage ;
les nouvelles échéances utilisent les nouveaux réglages. Abaisser `max_entries`
bloque les insertions jusqu'à ce que l'expiration ramène le nombre sous le plafond
réglé ; cela ne supprime pas immédiatement les tuples existants.

Chaque contrôle utilise `BEGIN IMMEDIATE`, puis nettoyage, lecture, vérification
de capacité, insertion ou promotion, et commit. Une clé SQL unique empêche les
doublons. Un échec de commit ne produit pas de décision réussie. Le verrouillage
est assuré aussi entre connexions SQLite indépendantes, selon les
[transactions SQLite](https://www.sqlite.org/lang_transaction.html).

La durabilité disque exige une connexion fichier avec WAL et
`synchronous=FULL`, déjà employés par `Store::open`, ainsi qu'un stockage qui
honore les synchronisations. Le module ne réduit pas ces garanties. Une base
en mémoire est seulement un support de tests. Voir les garanties de
[synchronous dans SQLite](https://www.sqlite.org/pragma.html#pragma_synchronous).

Chaque contrôle enlève au plus 256 expirations via un index, plus éventuellement
l'expiration de sa propre clé. `prune` enlève au plus 256 lignes à chaque appel,
dans les deux espaces. `Store::cleanup()` appelle ce nettoyage une fois, même
lorsque l'admission est désactivée. La boucle de relais appelle `cleanup` tous
les 30 ticks d'une seconde, soit environ 30 s lorsqu'elle fonctionne normalement,
y compris sans nouvelle connexion SMTP. Chaque passage traite un seul lot,
sans vider immédiatement un arriéré supérieur à 256 lignes. Si la boucle de
maintenance est arrêtée, retardée ou échoue avant cet appel, les lignes expirées
peuvent rester physiquement présentes ; elles ne peuvent pas être réutilisées.

Au réglage maximal, au plus 200 000 tuples sont retenus simultanément dans les
deux modes.
Le plein **laisse passer les nouvelles clés** et expose `capacity` : il évite de
renvoyer indéfiniment un 451 dont aucun état de retry n'a pu être enregistré.
Les tuples existants suivent encore leur politique. Cette exception est un choix
de disponibilité, mesurable et contournable par saturation ; elle ne doit pas
être présentée comme un contrôle antispam exhaustif. Il n'y a pas d'éviction
silencieuse qui réinitialiserait les timers de clients légitimes.

La borne de lignes ne constitue pas une limite en octets du WAL ou des
sauvegardes. Conserver la maintenance SQLite et les checkpoints du Store ; les
lecteurs longs peuvent retarder la récupération du WAL. Les durées et le nombre
de lignes bornent l'état logique, sans garantir un effacement forensique des
anciens octets.

## Réponses, DATA et resets

Un candidat devient, uniquement en enforcement,
`451 4.7.1 Temporary greylisting; please retry later`. Une indisponibilité de
l'état devient `451 4.3.0 Admission state unavailable; please retry later`.
Les constantes incluent CRLF et ne reflètent aucune entrée SMTP. Ces réponses
partent à **RCPT, avant DATA, avant l'écriture du message dans la file et
avant toute réponse finale d'acceptation**. La responsabilité après acceptation
SMTP est décrite par le
[RFC 5321 §6.1](https://www.rfc-editor.org/rfc/rfc5321.html#section-6.1).

Ne jamais annoncer 250 pour un destinataire différé et ne jamais créer sa
livraison. Les autres RCPT gardent leur décision indépendante. DATA peut ensuite
traiter les destinataires effectivement acceptés ; si aucun ne l'est, conserver
le rejet de séquence SMTP existant. L'ordre des RCPT, les duplications ou le
succès d'un premier destinataire ne doivent pas préautoriser les suivants.
Le retour 451 ne nécessite ni DSN local, ni notification, ni challenge : le MTA
distant conserve la responsabilité de réessayer.

La session ne met pas les décisions d'admission en cache. Elle réinitialise
l'enveloppe à RSET, EHLO/HELO et fin de transaction DATA ; un nouveau MAIL démarre
la transaction suivante. Chaque RCPT refait le contrôle durable. Après STARTTLS
réussi, HELO, MAIL et RCPT sont oubliés et une nouvelle séquence SMTP est requise ;
ce reset suit le
[RFC 3207 §4.2](https://www.rfc-editor.org/rfc/rfc3207.html#section-4.2).
La base de retries survit à ces événements. L'IP de transport et le budget de
délai restent attachés à la socket : un RSET ou STARTTLS ne recharge pas le budget.

## Sommeils et ressources

Le teergrubing optionnel s'applique seulement aux états `first_seen` et `too_soon`.
Il ne temporise ni passage, ni panne DB, ni capacité pleine. `observe` expose le
délai candidat mais retourne immédiatement sans réserver de budget ni permis.
L'observation effectue toutefois des accès SQLite ordinaires, avec leur latence.

Engine partage un seul `Admission` pour le listener. Un contrôleur neuf par
session créerait autant de sémaphores indépendants et annulerait la borne
globale. Lors d'un changement du mode global, `with_mode(Mode)` conserve les
réglages et le même sémaphore, y compris les permis détenus par les sessions
antérieures. Un aller-retour enforce → observe → enforce ne crée donc pas de
capacité supplémentaire. Changer le mode n'active pas un contrôleur désactivé.
L'API `reconfigured(Settings)` permet aussi d'actualiser la politique en
partageant le même
sémaphore avec les sessions existantes. Une modification de
`tarpit_max_concurrent` est refusée et exige un redémarrage du listener. Lors
d'une première activation après désactivation, initialiser les tables avant
d'utiliser le nouveau contrôleur. Ne pas réutiliser simplement l'ancien
contrôleur si ses réglages ou le mode effectif ont changé. Le raccordement actuel
utilise `with_mode` ; les autres réglages d'admission restent ceux du TOML de
démarrage. Les limites de connexions globales et par IP restent applicables.

`delay` utilise `try_acquire` : si tous les permis de sommeil sont occupés, il
renvoie `busy` sans queue et le 451 reste applicable. Le temps réservé est le
minimum du délai configuré, du délai candidat et du budget de session restant.
Il est débité avant l'attente, même si la future est ensuite annulée. Annuler ou
laisser tomber la future libère immédiatement son permis ; aucune tâche de
sommeil n'est détachée. Les bornes portent sur le temps demandé : une pause de
l'exécuteur ou de l'OS peut retarder le réveil effectif.

**Ne jamais détenir un permis `State.processing`, une transaction ou un mutex du
Store pendant ce sommeil.** Le raccordement termine le contrôle réussi via
l'exécuteur bloquant, puis temporise avant la réponse RCPT. Il acquiert les
permis rares de traitement DATA seulement ensuite.

Le sémaphore partagé de quatre contrôles DB est acquis sans attente avant
`Store::run`. Son permis reste détenu dans la fermeture bloquante jusqu'à la fin
du travail, même si le délai applicatif de 500 ms a expiré. Un contrôle saturé,
en erreur ou expiré produit `unavailable` immédiatement après constat, sans
tarpit ; en observation, RCPT continue. Un travail SQLite ayant dépassé le
timeout peut encore modifier l'état durable, mais son résultat n'est plus
utilisé pour la réponse courante. Le busy timeout SQLite du Store est de 10 s ;
il ne constitue pas un timeout d'exécution total. La borne de quatre travaux
reste donc nécessaire pour empêcher l'accumulation après des timeouts SMTP.

## Vérification

```sh
cargo test --test smtp_admission
cargo test --test smtp_admission_smtp
```

Validation locale du 10 septembre 2026 : **22 tests du module et six tests SMTP
réussis**, avec sockets loopback et une véritable négociation STARTTLS. Ces tests
ne contactent aucun relais externe et ne valident pas une mise en production.

`tests/smtp_admission.rs` couvre les réglages, l'absence d'effets par défaut,
les reprises avec réouverture d'une base fichier WAL/FULL, l'initialisation
idempotente, la concurrence de connexions indépendantes, la capacité atomique,
les rollbacks d'insertion/promotion, la contention SQLite, les bornes de retry,
l'expiration malgré trafic, le nettoyage borné sans SMTP, la séparation des
destinataires et des modes, le MAIL nul, IPv4/IPv6, les empreintes salées,
l'observation immédiate, le budget de délai, la libération après annulation
et le partage de capacité après reconfiguration et changement du seul mode.

`tests/smtp_admission_smtp.rs` couvre le transport : les 451
sur le fil, l'absence de message/livraison pour un RCPT différé, un retry après
redémarrage, les transactions mixtes et alias, le chemin `filter.mode = observe`,
les séquences STARTTLS/RSET, le budget conservé après reset, la saturation des
sommeils, la disponibilité des permis DATA pendant un tarpit et les changements
de mode dans la console avec une session antérieure toujours temporisée.
Les statistiques de retry en observation sont hypothétiques : puisque le message
continue, une seconde enveloppe identique peut être un autre message, pas une
retransmission.
