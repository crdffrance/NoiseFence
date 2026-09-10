# Analyse isolée des pièces jointes et file SMTP durable

Le traitement sélectionne les pièces Office, inscrit leurs références dans la
transaction d’acceptation du message, puis confie leur analyse au service isolé
en arrière-plan. SMTP n’attend pas l’exécution d’Office. Le module est désactivé
par défaut ; `ResearchOnly` ne modifie ni le score ni la livraison.

Le connecteur et ses limites sont décrits dans [sandbox.md](sandbox.md). Les tests
emploient uniquement des octets synthétiques et des serveurs HTTP sur la boucle
locale. Ils ne démontrent ni l’isolation d’une VM réelle, ni l’exécution effective
d’une macro, ni l’innocuité d’un document. Aucun CAPE réel n’a été contacté pour
ces tests et aucun réglage de production n’a été activé.

## Configuration

`sandbox` configure le connecteur. La section facultative `sandbox_pipeline`
configure la sélection, la conservation et la quarantaine éventuelle. Son
activation exige un backend explicitement activé et des tailles compatibles.
Aucune vérification réseau n’est effectuée pendant cette validation.

Exemple de section après configuration du service isolé :

```toml
[sandbox_pipeline]
enabled = true
quarantine_selected = false
quarantine_days = 14
max_raw_bytes = 33554432
max_parts = 256
max_attachments = 8
max_attachment_bytes = 16777216
max_total_attachment_bytes = 33554432
max_outbox_jobs = 1000
max_pending_raw_bytes = 268435456
submission_timeout_secs = 3600
retry_interval_secs = 15
max_attempts = 256
batch_size = 8
retention_days = 30
```

`enabled` et `quarantine_selected` valent `false` par défaut. L’activation de
`quarantine_selected` est une politique distincte : tout message sélectionné est
retenu pour **tous ses destinataires**, sans être qualifié de malveillant. Cette
option est refusée avec le mode global `observe`.

La conservation est limitée à 1–30 jours. Les plafonds absolus sont : 64 Mio de
message, 512 parties MIME, 32 pièces sélectionnées, 32 Mio par pièce, 64 Mio de
pièces cumulées, 10 000 tâches conservées, 4 Gio de messages retenus pour la remise
locale, 32 tâches par passage, 10 000 tentatives, 24 heures avant expiration de
remise et 300 secondes entre tentatives. Les limites du connecteur s’appliquent
aussi. Un quota de système de fichiers reste nécessaire pour borner l’ensemble
des fichiers SQLite, WAL et spool.

## Acceptation SMTP et reprise

Le véritable chemin SMTP suit ces étapes :

1. `Engine::process_smtp` prépare un reçu opaque sur le message original, après
   calcul de son empreinte. La sélection utilise le budget CPU des analyses
   locales : 500 ms et 1 à 4 permis selon la configuration. Une tâche dépassant
   le délai conserve son permis jusqu’à sa fin effective.
2. Le reçu contient des indices MIME, tailles, types Office et empreintes, sans
   noms de fichiers ni contenu. Un Scan enregistré, un JSON ou un en-tête reçu
   ne peut pas reconstruire ce reçu de confiance.
3. `Store::enqueue` le lie aux octets effectivement conservés après réécriture
   des en-têtes, puis écrit et synchronise le spool.
4. La même transaction SQLite crée le message, tous les destinataires, leurs
   politiques et les lignes de remise au connecteur. Une quarantaine demandée
   explicitement retient tous les destinataires et enregistre l’action canonique
   `sandbox_selected` dans le Scan conservé.
5. SMTP répond `250` seulement après cette transaction. Un échec de quota ou
   d’enregistrement annule l’ensemble, supprime la copie non acceptée et produit
   `451`. Aucun job CAPE n’est créé avant l’acceptation.

En observation, une sélection trop volumineuse, incomplète ou indisponible peut
produire un rapport limité sans reçu ; les parties non sélectionnées ne sont pas
analysées. Cette limitation reste visible dans le diagnostic. Avec une
quarantaine de sélection explicite, une sélection incomplète ou un budget CPU
occupé entraîne `451` plutôt qu’un contournement silencieux de la politique.

La sélection utilise les extensions et types MIME Office connus. Le contenu est
décodé avant calcul d’empreinte. Les doublons identiques de même type dans un
message ne créent qu’une tâche. Les archives et messages attachés ne sont pas
ouverts récursivement. Ce mécanisme ne valide pas complètement le format Office
et ne détecte pas la présence d’une macro. Un mauvais encodage reste une analyse
incomplète, jamais une preuve de malveillance.

`sandbox_service` possède le client réutilisé uniquement dans le daemon `Serve`.
Les analyses hors ligne et les autres points d’entrée ne soumettent pas de
fichiers. Le worker récupère un lot borné, relit le spool et vérifie sa taille,
son empreinte, le type et l’empreinte de la pièce décodée. Les liens symboliques,
fichiers non réguliers ou multiplement liés sont refusés. Un fichier absent ou
modifié devient non concluant, sans classification « malware ».

Les intentions et baux sont durables. Un bail de 300 secondes empêche une seconde
instance de reprendre une remise active ; un arrêt brutal permet sa reprise
après expiration du bail. Le verrou partagé du worker survit à l’annulation de
son attente jusqu’à la fin du passage déjà démarré.

`Client::enqueue_created_at` reçoit la date d’origine de la ligne SQLite, jamais
la date d’une tentative. Le connecteur persiste localement la pièce et déduplique
le tuple message/pièce/type/disposition. Un arrêt après cette persistance, avant
l’enregistrement du numéro de tâche dans la base principale, reprend le même
tuple. Une réponse HTTP de création perdue déclenche la réconciliation du
connecteur, sans répétition aveugle de l’upload.

Chaque ligne est liée à la politique du backend réel. Un changement de backend
ou de politique ne redirige pas une pièce retenue : la ligne devient non
concluante. Une indisponibilité ou un quota du connecteur conserve la remise pour
réessai, dans les limites de délai et de nombre configurées.

## Conservation et quarantaine

Les lignes `pending` et `submitting` empêchent la suppression du message brut.
Le nettoyage vérifie cette condition lors de la sélection **et** dans la mise à
jour finale `raw_present=0`. Il ne supprime le fichier que si cette mise à jour
réussit réellement. Les obligations de livraison et de quarantaine continuent
indépendamment à retenir le spool.

La remise locale confirmée libère cette obligation particulière : le connecteur
possède alors sa copie durable. Une expiration explicite de remise la résout en
état non concluant. `prune_primary` s’exécute aussi lorsque le module ou le backend
est désactivé. Les demandes et résultats locaux expirent au plus tard 30 jours
après leur date d’origine ; les consultations masquent les résultats expirés entre
les passages de nettoyage.

Le service purge le connecteur par lots bornés avec `prune_before`. Backend
désactivé, `Client::prune_local` fonctionne sans client HTTP, identifiants ou réseau
et ne crée pas de répertoire absent. Les échéances sont appliquées par la
maintenance périodique ; un processus arrêté ne peut pas effacer matériellement
les fichiers.

La purge conserve seulement les réservations distantes minimales non résolues :
identifiant de job, éventuel numéro de tâche et indicateur de tâches multiples.
Les contenus, empreintes de message/pièce, résultats et provenance sont effacés.
Une date limite persistante interdit de recréer une ancienne demande après cet
effacement. Un résultat absent après purge devient non concluant, sans nouvelle
soumission. Les réservations ne sont jamais libérées en supposant que CAPE s’est
arrêté : leur levée exige une vérification opérateur indépendante.

La purge locale ne supprime pas les échantillons, captures ou rapports sur CAPE.
La rétention distante doit être configurée et vérifiée séparément.
La suppression logique des enregistrements locaux ne constitue pas une garantie
d’effacement physique sur SSD ; les sauvegardes et instantanés ont leur propre
politique de conservation.

Le worker ne libère **jamais automatiquement** les destinataires, y compris après
un rapport sans signatures. `NoFindings` ne signifie pas « document sûr ». Les
erreurs, délais dépassés, rapports incomplets et constats d’activité ne modifient
pas la classification SMTP. Les procédures de revue manuelle et d’expiration de
quarantaine restent applicables ; l’expiration ne remet pas le message en livraison.

## Diagnostic et journaux

Le Scan conservé expose le rapport initial : version, état de préparation,
disposition, nombres sélectionnés/ignorés et codes fixes de limitation. Les
résultats évolutifs viennent de la file principale. Le diagnostic les lit dans le
même instantané SQLite que le contrôle des droits sur le message et chaque
destinataire. Connaître un identifiant de message ne donne pas accès aux résultats.

La projection pour l’interface expose les états, causes fixes, signatures
assainies, score CAPE indicatif éventuel et version de moteur. Elle exclut les
empreintes, numéros de tâches, noms de backend, adresses internes, fichiers et
extraits privés. Les résultats restent des observations, pas un verdict de
sécurité. Le journal du worker contient des compteurs et états fixes ; les erreurs
libres du backend ne sont pas copiées dans les réponses SMTP.

`list` est une API interne plus détaillée, limitée à 32 entrées par message. Elle
n’effectue pas elle-même de contrôle d’autorisation et ne doit pas remplacer la
projection autorisée des diagnostics.

## Interfaces techniques

```rust,ignore
Settings::validate(&self) -> anyhow::Result<()>;
Settings::bind_backend(&mut self, backend: &sandbox::Settings) -> anyhow::Result<()>;
install(db: &rusqlite::Connection) -> anyhow::Result<()>;
prepare(raw: &[u8], scan: &Scan, settings: &Settings) -> anyhow::Result<Plan>;
Plan::report(&self) -> Report;
Plan::bind_queued(&mut self, raw: &[u8]) -> anyhow::Result<()>;
record(tx: &rusqlite::Transaction<'_>, id: &str, scan: &Scan, plan: &Plan)
    -> anyhow::Result<()>;
needs_raw(db: &rusqlite::Connection, message_id: &str) -> anyhow::Result<bool>;
pub const NEEDS_RAW_SQL: &str; // EXISTS corrélé, alias extérieur messages = m
expire_pending(db: &rusqlite::Connection, now: i64) -> anyhow::Result<usize>;
prune_primary(db: &rusqlite::Connection, now: i64) -> anyhow::Result<usize>;
Worker::new(settings: Settings) -> anyhow::Result<Worker>;
async Worker::tick(&self, store: &Store, client: &sandbox::Client)
    -> anyhow::Result<TickReport>;
async list(store: &Store, message_id: &str) -> anyhow::Result<Vec<Entry>>;
```

`Plan` est opaque, `Clone + Debug` et exclu de la sérialisation du Scan. Les
réglages et rapports sont sérialisables ; la liaison privée au backend est
recréée sur la copie utilisée à l’exécution. En Rust, partir de
`Settings::default()`, modifier les champs publics, puis appeler `bind_backend`.
Une désérialisation ne fournit jamais une liaison de confiance.

Les tables sont additives et conservent la version principale SQLite à 2. Une
ancienne version ignorant cette file peut supprimer une copie de recherche après
livraison : elle ne bénéficie pas de la nouvelle protection du spool. Avant un
retour à cette version, vider la file de recherche ou préserver ses copies. La
quarantaine emploie les états déjà reconnus par le schéma existant.

## Vérification

Exécuter `cargo test --locked --test sandbox_pipeline`. Les tests couvrent la
transaction atomique, les quotas, les reprises, la perte d’une réponse de
création, les baux, les fichiers absents/modifiés, les liens symboliques,
l’intégrité après réécriture, les changements de politique, l’expiration, la
quarantaine de tous les destinataires et l’absence de libération automatique.

Les tests SMTP passent par le véritable traitement `DATA`, `Engine::process_smtp`
et `Store::enqueue`. Ils vérifient `250` après persistance, `451` sur sélection ou
quota impossible, le Scan canonique, le nettoyage du spool et les diagnostics
selon les droits du destinataire. Le backend simulé ne reçoit que des fixtures
synthétiques. Ces résultats ne remplacent pas une validation d’isolation et
d’exécution sur une installation CAPE réelle.

Vérification locale du 10 septembre 2026 : **18 tests sur 18 réussis**, dont le
chemin SMTP réel, les diagnostics autorisés, l’annulation du worker et l’absence
de fausses notifications de changement lorsque le résultat est inchangé. La compilation des tests refuse les avertissements ; le contrôle rustfmt réussit.
La suite fait également partie des tests Cargo du projet.
