# Historique expéditeur–destinataire

`sender-history-1` conserve des observations SMTP locales et réévalue les retours
humains autorisés pour une relation précise entre expéditeur et destinataire.
Le module est raccordé au traitement SMTP, à la file durable et aux diagnostics
par destinataire. Sa configuration reste facultative et son mode par défaut est
`observation`. Ce mode ne modifie aucun score, verdict, préfixe, modèle ou
traitement de livraison. Le mode facultatif `adaptive`, décrit ci-dessous, peut
changer le seuil et la décision pour une livraison précise.

Le mode explicite `candidate_credit` expose uniquement une éligibilité
indicative. Il ne contourne jamais l’authentification, la recherche de logiciels
malveillants ou l’analyse du contenu. Un rapport enregistré n’est pas un cache de
confiance utilisable pour les messages suivants.

## Conditions d’apprentissage

Toutes les conditions suivantes sont nécessaires pour une relation apprise :

1. Le message original contient exactement un champ `From`, avec une seule
   boîte aux lettres non ambiguë, identique à celle extraite par le moteur. Un
   nom affiché, le chemin de retour SMTP, un champ `Authentication-Results` ou
   une affirmation ARC fournie dans le message ne prouvent pas cette identité.
2. Les observations proviennent de `Source::SmtpSession`. L’authentification et
   DMARC sont terminés localement, avec SPF valide et aligné ou DKIM valide et
   aligné. SPF/DKIM seuls, sans alignement DMARC, ne suffisent pas. Les analyses
   hors ligne et les enveloppes fournies à l’API sont exclues.
3. Le `raw_sha256` du scan correspond aux octets originaux utilisés pour préparer
   une preuve opaque. Cette preuve conserve le lien avec l’original lorsque les
   en-têtes du message mis en file sont ensuite réécrits.
4. Le message historique n’est pas une notification automatique de livraison
   (DSN), son analyse locale est complète et aucun des scanners antivirus ou de
   signatures n’a signalé de malware. Le message courant doit également remplir
   ces conditions de contenu pour être éligible.
5. Un utilisateur humain actif a émis un retour non-spam et dispose toujours de
   `console_access` sur **cette livraison**. Un retour `legitimate` ou un ancien
   retour humain binaire non-spam convient ; un retour explicite `publicity`
   n’établit pas une relation personnelle. Une prédiction de modèle ne contribue
   jamais à cet apprentissage.
6. Au moins trois groupes de campagnes distincts ont des premières observations
   séparées d’au moins 24 heures : il faut donc au minimum 48 heures de diversité.
   Les dates sont celles de réception par le serveur, jamais le champ `Date` du
   message ni la date d’un étiquetage humain effectué en lot.

Des copies des mêmes octets, des empreintes de campagne identiques ou des
simhashes à distance de Hamming <= 3 appartiennent au même groupe. Le regroupement
est transitif : une chaîne de petites mutations ne crée pas artificiellement
plusieurs campagnes. Un exemple positif exige une empreinte hexadécimale de
64 caractères et un simhash de 16 caractères. Le message courant ne compte pas
comme son propre échange antérieur. L’absence de métadonnées de campagne ne
masque toutefois pas un retour spam.

La portée est `(RCPT original, destination canonique, boîte From exacte)`.
L’adresse d’entrée et la destination comptent toutes deux pour les alias : deux
alias de locataires différents vers une même boîte ne partagent pas leur
historique. Seule la casse du domaine est normalisée ; la casse de la partie
locale, ses points et ses suffixes `+` sont conservés.

La reconnaissance d’identité est volontairement limitée aux boîtes ASCII sous
forme dot-atom, sans caractères génériques ni parties locales entre guillemets
ou internationalisées. Cette limitation de l’historique ne restreint pas la
grammaire SMTP acceptée par le serveur.

## Expiration, contradiction et révocation

Une observation reste valide lorsque `received > now - 30 jours` et
`received <= now`. Les retours doivent être dans cette même fenêtre, postérieurs
ou égaux à la réception, et jamais datés du futur. Un nouvel enregistrement de la
même observation ne prolonge pas sa durée de vie. Les lectures vérifient
l’expiration même sans maintenance ; `prune` supprime les observations expirées,
y compris lors de la maintenance normale du Store.

Un seul retour spam actuellement autorisé sur une transaction à identité
vérifiée annule tout crédit appris ou manuel dans la relation concernée, même
en présence de retours légitimes simultanés. La contradiction reste applicable
si l’analyse de contenu historique était incomplète ou avait trouvé un malware.
Une entrée manuelle de domaine vérifie les contradictions sur tout le domaine
exact, dans la même portée destinataire.

Chaque lecture consulte les retours, les comptes actifs et les droits courants
dans un seul instantané SQLite WAL. Désactiver un utilisateur, retirer son droit,
supprimer ou modifier son retour, ou supprimer la livraison prend effet à la
lecture suivante. Rétablir un retour légitime autorisé peut restaurer
l’éligibilité ; l’expiration d’une observation spam peut retirer sa contradiction.
Un changement de droit intervenant après une lecture ne réécrit pas son résultat
historique. Les diagnostics réappliquent néanmoins les droits au moment de
consulter ce résultat enregistré.

## Configuration

Le module expose `Config`, ses alias `Settings` et `Policy`, et
`validate() -> anyhow::Result<()>`. Le champ facultatif
`Config::sender_history` est raccordé à la validation principale. Une empreinte
des réglages contribue également à l’empreinte de politique des observations,
sans y recopier les adresses des entrées manuelles. Aucun réglage de production
n’est activé par cette documentation.

```toml
[sender_history]
mode = "observation"

[[sender_history.manual]]
recipient = "alice@tenant.test"
destination = "alice@tenant.test"
sender = { exact = "billing@example.org" }

[[sender_history.manual]]
recipient = "sales@alias.test"
destination = "alice@tenant.test"
sender = { domain = "partner.example" }
```

Les entrées manuelles proviennent d’une configuration administrative autorisée,
jamais du contenu d’un message ou d’une prédiction. Un éventuel éditeur de console
doit autoriser la portée exacte avant de construire une entrée. Il n’y a aucune
correspondance par caractère générique, suffixe, sous-domaine, domaine
organisationnel, nom affiché ou approximation. L’authentification alignée du
message courant reste obligatoire, même pour une entrée manuelle.

Une entrée d’expéditeur exact est prioritaire sur une entrée de domaine. Une
entrée configurée demeure jusqu’à sa suppression ; la limite de 30 jours porte
sur les transactions et leurs contradictions, pas sur la durée de vie de la
configuration administrative. Le maximum est de 256 entrées. Les erreurs de
validation ne recopient pas les adresses.

## Intégration réalisée

`Store::open` installe les tables et index additionnels dans sa migration.
Le module ne change pas `PRAGMA user_version` ni les règles de la file durable.
Le moteur partage la limite des lectures concurrentes entre les révisions de
configuration. Un rechargement remplace bien la politique : la suppression ou
le changement de portée d’une entrée affecte les messages suivants.

En mode adaptatif, après les vérifications obligatoires, `Engine::process_smtp`
appelle `inspect` avant le LLM facultatif, puis `prepare_receipt` après la décision
finale. Les modes consultatifs inspectent l’historique après l’analyse complète.
Les appels utilisent les **octets originaux**, les vrais destinataires SMTP et
le scan produit localement. La liste inclut les copies cachées et les adresses
d’entrée des alias. Les octets réécrits sont ensuite transmis à l’enqueue avec
les deux valeurs opaques conservées dans les champs éphémères de `Scan` :

```rust,ignore
#[serde(skip)]
pub sender_history_receipt: Option<sender_history::Receipt>,
#[serde(skip)]
pub sender_history_projection: Option<sender_history::Projection>,
```

Ces types implémentent `Clone` et un `Debug` expurgé, mais ni `Serialize` ni
`Deserialize`. La projection conserve sa correspondance destinataire en privé.
Il ne faut reconstruire aucune preuve à partir d’un paramètre HTTP, d’un rapport
stocké ou d’en-têtes fournis par l’expéditeur.

`Store::enqueue` écrit durablement les octets de file puis insère le message et
**toutes** les livraisons dans une transaction unique. Avant son commit, il
appelle `record_prepared` et `record_projection` lorsque les valeurs éphémères
correspondantes existent. Les erreurs d’enregistrement annulent la transaction.
Les évolutions du score et des diagnostics après préparation sont permises,
mais l’empreinte des octets, l’expéditeur, la campagne et l’authentification doivent
toujours correspondre à la preuve. Pour les données enregistrées, le module
vérifie aussi que `messages.scan` correspond à la sérialisation du scan final.

Une **projection vide est une absence de données à enregistrer** : elle ne teste
pas l’égalité des empreintes et ne bloque pas l’enqueue lorsque l’empreinte
observée est absente ou différente. Les contrôles de liaison restent obligatoires
pour toute projection non vide et pour toute preuve préparée. Les cas suivants
sont ainsi conservateurs sans transformer l’historique optionnel en rejet SMTP :

| Cas | Résultat d’historique | Enqueue |
| --- | --- | --- |
| From non pris en charge, destinataires reconnus | `NotRun`, aucun crédit ni preuve d’identité | Autorisé |
| RCPT ou destination à partie locale entre guillemets | Projection vide, aucun crédit | Autorisé |
| Mélange de destinataires reconnus et non pris en charge | Projection vide pour l’ensemble | Autorisé |
| Plus de 100 destinataires, dans la limite SMTP configurée | Projection vide, aucune évaluation partielle | Autorisé |

Une limite de stockage atteinte par `record_prepared` renvoie `Ok(false)` après
avoir enregistré la suspension conservatrice du crédit décrite plus bas.
L’enqueue peut alors valider sa transaction. Une erreur de liaison d’une preuve
ou d’un rapport non vide reste une erreur à propager : la masquer pourrait
supprimer une contradiction spam de l’historique.

Les fonctions publiques restent disponibles pour les appelants internes :

```rust,ignore
pub fn install(db: &rusqlite::Connection) -> anyhow::Result<()>;
pub fn prune(db: &rusqlite::Connection) -> anyhow::Result<usize>;
pub fn prepare_receipt(raw: &[u8], auth_scan: &Scan) -> Option<Receipt>;
pub fn record_prepared(
    db: &rusqlite::Connection, id: &str, scan: &Scan, receipt: &Receipt,
) -> anyhow::Result<bool>;
pub fn record_projection(
    db: &rusqlite::Connection, id: &str, scan: &Scan, projection: &Projection,
) -> anyhow::Result<()>;

impl History {
    pub fn new(root: &std::path::Path, settings: Settings) -> Self;
    pub async fn inspect(
        &self, raw: &[u8], auth_scan: &Scan, recipients: &[Recipient],
    ) -> Projection;
}
impl Projection {
    pub fn for_recipient(&self, index: usize) -> Option<&Report>;
    pub fn shared_report(&self) -> Option<&Report>;
}
```

`record_smtp(db, id, original_raw, scan)` reste un raccourci pour un appelant qui
possède encore les octets originaux. Des octets déjà réécrits ne permettent pas
de créer une preuve par ce raccourci. Les fonctions d’enregistrement exigent la
transaction d’enqueue active.

## Confidentialité et diagnostics

Les rapports sont enregistrés séparément du scan partagé :

```sql
CREATE TABLE recipient_research (
    delivery_id INTEGER PRIMARY KEY REFERENCES deliveries(id) ON DELETE CASCADE,
    sender_history TEXT NOT NULL
);
```

`record_projection` associe chaque livraison à sa portée inspectée et conserve
un JSON par livraison. L’opération est idempotente. Une suppression de livraison
ou de message supprime en cascade ses rapports et observations, grâce aux clés
étrangères activées sur la connexion d’écriture du Store.

`Store::diagnostics` et `diagnostics_for` chargent ce rapport uniquement pour les
livraisons déjà sélectionnées par `console_access` dans le même instantané. Avoir
accès au message via une autre livraison ne donne aucun accès à une copie cachée,
à son historique ou à ses compteurs. Connaître un identifiant de livraison cachée
ne permet pas non plus de demander son rapport. L’analyse commune ne reçoit pas
les compteurs d’historique. Tout futur export doit conserver cette autorisation
au niveau de la livraison.

`Projection::shared_report()` renvoie un rapport uniquement pour **un seul**
destinataire. Plusieurs destinataires donnent toujours `None`, même si leurs
résultats sont identiques ou leurs domaines communs. `for_recipient(index)` suit
l’ordre d’entrée et nécessite une autorisation sur la livraison avant toute
exposition. Ne pas en énumérer les résultats dans un en-tête SMTP ou un `Scan`
partagé : des compteurs seuls peuvent déjà révéler une relation en copie cachée.

`Report` ne contient qu’une version, des états fixes, des compteurs bornés et des
booléens. Aucune adresse, aucun domaine, identifiant utilisateur ou message,
empreinte, texte ou horodatage n’y figure. Les erreurs de lecture renvoient
`Unavailable` sans recopier les détails de la base. La configuration manuelle et
les observations privées contiennent encore des identités : elles restent dans
le stockage privé et les chemins d’administration autorisés.

## Limites et comportement en cas d’échec

| Ressource | Limite et comportement |
| --- | --- |
| Observations d’identité actives | 65 536 par Store ; index d’expiration et compteur transactionnel O(1) |
| Observations examinées par portée | 256 ; la 257e rend toute la portée `Limited`, y compris le crédit manuel |
| Retours autorisés par observation | 64 ; le 65e rend la portée `Limited` |
| Destinataires par opération | 100 ; au-delà, projection vide |
| Entrées manuelles | 256 |
| Message original | 32 Mio pour préparer ou inspecter une preuve |
| Scan JSON enregistré | 8 Mio ; une taille excessive ou une discordance lors d’un enregistrement annule la transaction |
| Lectures simultanées | 4 par instance partagée de `History` ; saturation : `Limited` |
| Délai de lecture | 250 ms, ouverture comprise ; attente SQLite occupé : 50 ms |

Les lectures utilisent des connexions séparées en lecture seule et un instantané
WAL. Des index couvrent expéditeur/destinataire, domaine/destinataire et retours
par message. La comparaison des campagnes est bornée par le nombre
d’observations ; une structure union-find traite leurs regroupements transitifs.
Une annulation ou un dépassement de délai interrompt SQLite. Si l’ouverture est
encore en cours, le worker constate l’abandon avant toute requête. Aucun résultat
positif partiel ne survit à une lecture échouée ou limitée. Ce délai ne peut
interrompre un appel système de fichier bloqué pendant l’ouverture.

Si l’enregistrement dépasserait la capacité globale ou ne peut représenter
sûrement toutes les portées, il conserve une valeur `overflow_until` de taille
fixe couvrant les 30 jours de l’observation omise. Pendant cette période, **toutes**
les lectures du Store sont `Limited`, y compris les entrées manuelles. Supprimer
des observations ou redémarrer n’efface pas cette suspension. Le module ne retire
pas une contradiction spam pour conserver ensuite un crédit positif ; il préfère
suspendre ce crédit indicatif. Aucun locataire n’obtient l’historique d’un autre.

Les rapports suivent la durée de conservation de leur livraison ; conserver un
ancien rapport ne prolonge jamais la confiance au-delà des 30 jours applicables
aux observations. Les pages SQLite libérées peuvent maintenir la taille maximale
historique du fichier : aucun `VACUUM` bloquant n’est exécuté pendant SMTP. Le
module n’effectue aucun appel réseau ni interrogation de répertoire externe.

## Vérification

La suite dédiée contient 30 tests : observation par défaut, crédit explicite sans
modification du scan, alignement SPF/DKIM, en-têtes falsifiés, provenance SMTP,
liaison à l’original, absence d’apprentissage sur les seules prédictions ou la
publicité, campagnes répétées ou modifiées, diversité temporelle, expiration,
révocation, isolation des alias et locataires, persistance, rollback, limites et
lectures concurrentes.

Les régressions SMTP vérifient qu’un RCPT entre guillemets, un From non pris en
charge et 101 destinataires autorisés par SMTP sont acceptés durablement sans
crédit d’historique. Le test
`persisted_diagnostics_never_disclose_a_bcc_recipients_history_or_counts` passe par
l’enqueue réel puis rouvre le Store : Bob ne voit ni l’adresse ni les trois
campagnes légitimes d’Alice en copie cachée. Le test vérifie également les
sélections par identifiant de livraison, l’accès administrateur autorisé, puis
le retrait de droits et la désactivation de compte sans effacer les rapports.

```sh
cargo test --test sender_history
cargo test --test sender_history persisted_diagnostics_never_disclose_a_bcc_recipients_history_or_counts
```

Les 29 premiers tests ont passé lors de la validation centralisée ; le test
supplémentaire de diagnostics Bcc a aussi passé séparément. Sur macOS, les tests
SMTP nécessitent l’accès à la configuration DNS système lors de la construction
du moteur et l’ouverture d’un port local. Un environnement qui refuse ces accès
les arrête avant l’échange SMTP ; les fixtures désactivent l’authentification et
n’effectuent pas de requête DNS distante.

Ces régressions synthétiques vérifient des invariants de sécurité, pas une
amélioration du taux de capture ni le calibrage d’un poids de score. L’activation de
l’adaptation dans une décision de production exige une évaluation indépendante et
une activation explicite. Les réglages de production et la documentation de
publication restent des travaux séparés.


## Adaptation explicite par destinataire

Le mode `adaptive` applique un seuil administratif distinct aux correspondants
appris ou explicitement configurés. Exemple pour un seuil normal de 95 :

```toml
[sender_history]
mode = "adaptive"
trusted_threshold = 98.0
```

Le seuil doit être fini, strictement supérieur au seuil normal et inférieur à
100. L’authentification SMTP doit être activée. Ce mode est incompatible avec
un modèle de fusion configuré : il ne modifie pas un profil de fusion validé.
Le mode Observation global conserve son absence de marquage et de quarantaine.
Aucun bonus numérique n’est ajouté au score du modèle. La décision est recalculée
avec le seuil retenu, qui figure dans les diagnostics de cette livraison.
Un résultat sous ce seuil n’est pas une preuve de légitimité.

L’adaptation exige un historique complet, une identité actuellement authentifiée
et alignée, une extraction complète et des vérifications obligatoires terminées.
Une signature suspecte, un résultat de réputation positif, une observation active
HTML/PDF/Office, un indice visuel de demande d’identifiants, un signal de règle
positif ou une analyse requise limitée/indisponible empêche cette adaptation.
Les contrôles de contenu, antivirus, OCR, réputation, SMTP et authentification
restent exécutés. Un score atteignant le seuil de confiance suit la politique
normale. Les fournisseurs demandés mais non configurés ne donnent pas de crédit.

Pour les destinataires éligibles, l’analyse LLM facultative peut être omise
lorsqu’elle aurait été demandée dans sa plage de scores. Le rapport enregistre
explicitement cette omission ; il n’invente aucun verdict LLM. Si d’autres
destinataires nécessitent ce contrôle, le message commun attend encore cet
appel, et son résultat ne modifie pas la variante des correspondants fiables.
Un message uniquement destiné à des correspondants fiables évite réellement
l’appel. Cela ne constitue pas un cache de classification des mêmes octets.

Au plus deux variantes sont produites : décision normale et décision adaptée.
Chacune possède son identifiant, ses diagnostics, ses destinataires et ses
en-têtes réécrits/scellés ARC ; le corps reste identique. Les deux fichiers sont
synchronisés puis toutes les lignes sont insérées dans **une transaction** avant
le `250` SMTP. Une erreur annule l’ensemble. Les fichiers déjà présents ne sont
jamais écrasés. La reprise, les réessais et la conservation opèrent ensuite sur
chaque variante. Les utilisateurs voient uniquement leurs variantes autorisées ;
un administrateur peut voir deux enregistrements pour une réception initiale.
La relation interne `queue_batches` et le champ `queue_id` des journaux système
permettent de les rapprocher sans exposer un autre destinataire dans la console.
Les compteurs de messages comptent ces enregistrements, pas des réceptions uniques.

Une preuve de lecture valable au plus cinq secondes est revérifiée dans la
transaction d’acceptation. Depuis `0.5.0-dev.5`, ses compteurs de modification
portent sur le couple destinataire/destination et les droits exacts ou de domaine
qui peuvent lui donner accès. Seuls les destinataires dont la décision est
adaptée contribuent à cette preuve. Une correction de Bob ne force donc pas le
réessai d’Alice, même sur un ancien message partagé, si Bob n’a pas accès à la
livraison d’Alice. Une promotion de Bob en administrateur rend en revanche ses
corrections applicables et invalide alors la preuve d’Alice.

Une correction humaine, une modification de compte, de droits ou d’observation
pertinente l’invalide ; les échéances temporelles restent propres aux
destinataires concernés. Dans ce cas, le serveur répond `451` et le prochain
essai refait l’analyse. L’arrivée de messages sans correction humaine ne crée
pas de confiance et n’invalide pas à elle seule cette preuve. Une panne ou une
analyse incomplète conserve la transmission normale sans adaptation.

Les clés de révision sont privées, absentes des scans sérialisés et bornées à
131 072 entrées. La maintenance supprime les modifications âgées d’au moins
60 secondes, au-delà de la durée de toute preuve utilisable. Une clé recréée
reçoit une nouvelle révision monotone. Si la capacité est atteinte, un compteur
global de débordement invalide les preuves en cours : des réessais sans lien
entre destinataires restent alors possibles, sans perdre une révocation. Les
anciens déclencheurs globaux sont conservés pour un retour au binaire
`0.5.0-dev.4` ; ils ne servent plus à la décision normale du nouveau binaire.

Les tests couvrent les décisions mixtes, les octets ARC, les droits,
l’apprentissage humain, les révocations concurrentes, la maintenance et le
débordement, ainsi que les appels LLM réellement omis sur des messages distincts.

Le [relevé Linux de développement](../research/sender-history-linux-validation-20260910.json)
conserve les mesures d’un exécutable optimisé, ses empreintes et ses limites.
L’essai utilise des messages synthétiques, une API LLM locale avec délai imposé,
un réseau privé et une base temporaire. Les mesures de lecture des révisions et
du traitement d’analyse sont séparées ; elles ne comprennent pas le débit de la
file et du relais. Pour reproduire les tests depuis le checkout correspondant :

```sh
NOISEFENCE_HISTORY_BENCHMARK=engine.json \
NOISEFENCE_HISTORY_REVISION_BENCHMARK=revisions.json \
cargo test --release --locked --features semantic --lib history -- --test-threads=1
```

Le test de rechargement utilise le fichier public `config/development.toml` du
checkout. Les autres fixtures nécessaires à ces tests sont générées localement
ou intégrées à l’exécutable. Aucune configuration de production n’est requise.
