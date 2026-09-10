# Confirmation explicite d’une adresse pour un envoi en quarantaine

La confirmation est désactivée par défaut. Elle concerne uniquement un envoi déjà
placé en quarantaine pour un destinataire précis. Un administrateur ou un membre
actuellement autorisé demande explicitement l’envoi du lien depuis la console.
La réception, l’analyse, la consultation du message et l’ouverture du lien ne
déclenchent aucune demande automatique.

Le lien prouve l’accès à la boîte concernée, pas la présence d’un humain ni
l’innocuité du message. Le bouton de confirmation n’est pas un CAPTCHA. Une réponse
ne crée aucune liste blanche, exception pour les messages suivants, modification
du classement, correction utilisateur ou donnée d’apprentissage.

## Configuration et parcours dans la console

`Config.challenge` contient une `challenge::Policy` facultative. Son absence ou
`enabled = false` désactive le parcours. La configuration active impose une
origine HTTPS canonique, sans chemin ni barre oblique finale, identique à
`web.public_origin`. L’adresse `notification_from` appartient à un domaine local
configuré. La durée `ttl_seconds` va de 60 à 86400 secondes, avec une valeur par
défaut de 3600 secondes ; la conservation de la quarantaine et de la preuve SMTP
peut raccourcir cette durée.

Le bouton de la console affiche d’abord la boîte From authentifiée dans une
fenêtre de confirmation. Seule la validation de cette fenêtre demande l’envoi.
`/api/v1/stats` expose `challenge_enabled`, à `false` lorsque la configuration est
absente ou désactivée.

Les opérations privées utilisent le corps JSON
`{"recipient":"alice@example.test"}` et refusent les champs inconnus :

| Méthode et chemin | Effet |
| --- | --- |
| `POST /api/v1/messages/{id}/challenge/prepare` | Vérifie l’éligibilité et retourne uniquement `{"mailbox":"…"}` ; aucune résolution DNS ni notification. |
| `POST /api/v1/messages/{id}/challenge` | Revérifie l’éligibilité, résout la route et met la notification en file ; retourne `id` et `expires_at`, sans jeton. |
| `POST /api/v1/messages/{id}/challenge/revoke` | Révoque le lien et annule les notifications encore en attente ; reste disponible lorsque la fonction est désactivée. |

Les trois opérations vérifient l’origine exacte, la session, le jeton CSRF et
l’accès au destinataire. `Actor` provient de la session authentifiée ; le navigateur
ne fournit ni rôle, ni adresse de l’auteur, ni route SMTP. La capacité privée est
limitée à quatre opérations simultanées. Le serveur relit la configuration après
la résolution DNS et revérifie les droits dans la transaction d’écriture.

## Preuve SMTP et éligibilité

`VerifiedSmtpFrom::from_dmarc` construit une preuve opaque depuis le résultat DMARC
courant et les octets originaux, uniquement dans le contexte `SmtpSession`. Il exige
une seule boîte From et l’égalité exacte de son domaine avec le domaine auteur
vérifié. Un domaine organisationnel, SPF seul, ARC, une liste blanche ou un en-tête
`Authentication-Results` ne remplacent pas cette preuve.

Le `Scan` transporte la preuve avec `serde(skip)`. Elle est clonable, son `Debug`
est expurgé et elle n’est pas désérialisable. `Store::enqueue` lie les octets finaux
avec `bind_queued`, puis appelle `proof.record` après l’insertion du message, dans
la même transaction. L’identité et le message sont donc enregistrés atomiquement.
La preuve vérifie aussi l’empreinte originale `Scan.raw_sha256`, l’analyse SMTP
complète et le Scan effectivement enregistré. Les analyses hors ligne, imports
et enveloppes fournies manuellement ne créent pas de preuve. Les anciens messages
sans preuve restent inéligibles ; aucun rattrapage depuis des en-têtes ou une
vérification DNS ultérieure n’est effectué.

Les chemins de retour vides, DSN, From multiples ou invalides, messages automatiques,
listes, envois en masse, rapports de livraison et autres challenges sont exclus.
Une détection de malware dans l’un des résultats antivirus/signatures courants ou
dans leurs preuves persistées interdit le challenge. L’absence d’alerte ne
constitue pas une nouvelle analyse de sécurité.

La préparation et la demande vérifient aussi la présence des octets, leur empreinte,
la destination d’origine, l’état en quarantaine et sa date de conservation. Une
preuve SMTP âgée de 30 jours ne permet plus de nouvelle demande.

## Routage et notification durable

L’API utilise la route configurée pour une boîte locale, sinon une résolution MX
limitée à cinq secondes. Elle respecte l’ordre de préférence et le Null MX,
supprime le point DNS final et refuse les erreurs temporaires ou NXDOMAIN. Le
repli A/AAAA concerne uniquement une réponse DNS réussie sans MX. Les routes sont
calculées côté serveur ; aucune adresse Reply-To ou destination du navigateur
n’est utilisée. Le module accepte au plus 32 routes validées ; le résolveur API
borne sa liste MX à 16. Les protections TLS et d’adresses du relais restent actives.

La demande insère une notification ordinaire dans `messages` et `deliveries`, avec
le challenge, son empreinte de jeton, les quotas et l’audit dans une même
transaction. Le fichier privé (0600) et son répertoire sont synchronisés sur disque
avant le commit SQLite. Les écritures du challenge utilisent des transactions
IMMEDIATE, y compris entre plusieurs instances de Store. `Store::recover` élimine
les fichiers orphelins d’une transaction non validée. Le relais est réveillé après
le commit ; il n’existe ni seconde file ni envoi SMTP direct dans ce module.

La notification est en français, encodée en base64 MIME pour transporter ses
accents sans imposer 8BITMIME. Elle utilise `MAIL FROM:<>`,
`Auto-Submitted: auto-generated`, `X-Auto-Response-Suppress: All` et un marqueur de
challenge. `is_dsn=1` sélectionne la protection existante contre une nouvelle DSN ;
la notification n’est pas un rapport d’échec de livraison. Son unique destinataire
est la boîte From vérifiée. Elle ne divulgue ni objet, ni corps, ni destinataires
originaux, ni Bcc. Un échec ou retard d’envoi ne libère rien. Une tentative SMTP
déjà prise en charge ne peut pas être rappelée, mais un jeton révoqué est inopérant.

Les quotas persistants sont d’une demande par envoi sur 24 heures, trois par boîte
auteur sur 24 heures (comparaison sans distinction de casse), vingt par utilisateur
sur une heure et cent globalement sur une heure. Expiration, révocation et
suppression du message ne réinitialisent pas ces quotas. DMARC authentifie un
domaine, pas le propriétaire de sa partie locale : ces limites et les droits
réduisent les abus sans démontrer le consentement du titulaire de l’adresse From.

## Réponse publique et libération

`GET /challenge` affiche une page indépendante de la console ; lorsque la fonction
est désactivée, il retourne 404. Le lien utilise un fragment :
`https://origine-configurée/challenge#JETON`. La page retire ce fragment de
l’historique avant toute soumission. Le bouton envoie ensuite
`{"token":"…"}` dans le corps JSON de `POST /challenge/submit`, sans cookies ni
référent. Un GET ne libère aucun message.

Le routeur public vérifie l’origine, refuse les paramètres de requête et borne le
corps à 1024 octets et la concurrence à huit opérations. La même réponse HTTP 200
générique couvre succès, jeton incorrect, expiré, révoqué ou rejoué, corps invalide,
origine refusée, désactivation et erreur de stockage. Les erreurs de stockage
produisent un diagnostic fixe sans contenu privé. Le CSP à empreinte de script est
conservé après fusion avec le routeur de la console. La page utilise `no-store`,
`no-referrer`, `nosniff`, `DENY` et aucune ressource externe ni analyse d’audience.

Le jeton aléatoire de 256 bits est conservé sous forme d’empreinte SHA-256 dans
`challenge_requests`, jamais dans une URL de requête, un reçu JSON ou l’audit.
Le jeton lui-même figure nécessairement dans la notification MIME en file, puis
éventuellement dans la boîte du destinataire et ses sauvegardes. Les journaux HTTP,
proxys et APM ne doivent pas enregistrer les corps POST ou les paramètres d’URL
arbitraires. Aucun jeton ne doit être ajouté aux diagnostics.

La réponse sélectionne exclusivement l’envoi associé à l’empreinte du jeton. Dans
la même transaction, elle revérifie le compte actif, son empreinte de mot de passe
et de version, le droit courant `console_access`, la destination, la preuve SMTP,
les octets, les résultats malware et la conservation. La session web de la demande
peut être fermée : les droits actuels du compte restent obligatoires. Une perte
d’éligibilité observée révoque définitivement le jeton. Désactiver la fonction
suspend les réponses ; révoquer les demandes annule définitivement leurs liens.

Une réponse valide consomme le jeton, remet uniquement l’envoi sélectionné en
`pending`, réinitialise `next_attempt`, efface son erreur et renseigne `released_at`
pour ouvrir une nouvelle période de tentatives SMTP. L’action `quarantine`, le
Scan, les octets, l’enveloppe, les autres destinataires et l’historique restent
conservés. `challenge_complete` et `quarantine_release` sont audités sous le nom du
demandeur avec l’identifiant de cet envoi. Aucun rejeu ne libère un autre envoi.

## Conservation et entretien

`Store::cleanup` appelle `challenge::prune(&Connection, now) -> Result<usize>`.
Cette fonction purge les métadonnées même
lorsque la fonction est désactivée ou que le message reste présent en file ou en
quarantaine. La fonction accepte la connexion d’une transaction existante. Son
résultat compte les demandes, identités et événements de quota supprimés.

Une demande close ou expirée, avec son empreinte de jeton et ses données associées,
est supprimée dès 30 jours après sa création, sans ajouter 30 jours à son
expiration et sans attendre la suppression du message. Les événements de quota
indépendants sont supprimés dès 24 heures, aussi par l’entretien périodique ; les
quotas récents restent valables après suppression d’une demande ou d’un message.

La preuve SMTP expire 30 jours après la création du message. Les nouveaux liens
expirent au plus tard à cette échéance : des demandes répétées ne prolongent pas
la conservation de la preuve. Une identité arrivée à échéance est supprimée dès
qu’aucun lien encore valide n’en dépend. Pour préserver les liens déjà émis avant
cette borne de conservation, leur preuve reste disponible jusqu’à leur expiration
ou consommation ; aucune nouvelle demande ne peut prolonger cette exception.

La purge ne supprime pas les messages, octets en file, états de livraison ou audits.
Leur entretien reste géré par les règles habituelles de Store. Une sauvegarde ou
une copie de notification suit sa propre conservation ; la purge des tables n’est
pas une promesse d’effacement de toutes les copies du jeton.

## Tests locaux

`cargo test --locked --offline --test challenge` utilise des bases SQLite
temporaires, des preuves synthétiques sans DNS, des requêtes HTTP en mémoire et
un serveur SMTP uniquement sur la boucle locale. Aucun service de production ni
e-mail externe n’est utilisé. Pour vérifier sans aucune action d’envoi, même
locale, exclure ce seul test de protocole :

```sh
cargo test --locked --offline --test challenge -- --skip queued_notification_uses_null_smtp_mail_from_on_loopback_protocol
```
