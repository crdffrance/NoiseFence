# Greylisting sélectif et ralentissement SMTP (0.16.2)

Dans **Administration → Filtres → Admission SMTP**, l’administrateur configure
les reports, délais, quotas, exceptions et capacités sans redémarrage. Les
modifications passent par la révision et l’audit de configuration habituels,
avec contrôle des droits et CSRF. Les utilisateurs peuvent consulter les
contrôles associés à leurs messages ; ils ne peuvent pas désactiver une
protection qui concerne les autres destinataires du même serveur.

La politique `smtp-admission-2` est facultative et désactivée par défaut. Son mode
initial est `observe`. L’activer en observation conserve les décisions
hypothétiques, sans 451 ni sommeil. `mode = "enforce"` applique les reports SMTP.
Ce **mode de transport est indépendant du mode d’observation du contenu** : le
classement, les scores, le marquage et la quarantaine ne sont pas modifiés.

## Sélection et protection des expéditeurs légitimes

Après validation du destinataire à RCPT, avant DATA, stockage, OCR et modèles :

1. Un quota à jetons contrôle les tentatives MAIL ayant atteint un destinataire
   valide. Plusieurs RCPT d’un même MAIL ne consomment qu’un jeton. Une nouvelle
   transaction consomme un nouveau jeton. Le dépassement répond `451 4.7.1` et
   impose un nouveau MAIL. RSET et STARTTLS ne réinitialisent pas le quota.
2. Le greylisting exige au moins une réputation IP positive **et** le nombre
   configuré de signaux concordants (au moins deux). Deux opérateurs RBL
   distincts comptent pour deux ; un HELO qui n’est ni domaine valide ni adresse
   IP littérale peut compléter un opérateur. Les zones du même opérateur ne
   multiplient pas ses votes. PBL et résultats DNS indisponibles ne comptent pas.
   Sans RBL positive, aucun message n’est greylisté.
3. Une IP/CIDR explicitement exemptée évite quota et greylisting. L’expéditeur
   d’enveloppe, le domaine annoncé et les en-têtes ne constituent jamais une
   preuve de confiance. Loopback est exempt pour les opérations locales.
4. Les avis à expéditeur nul et les adresses postmaster évitent le greylisting ;
   le quota reste applicable. Les destinataires inconnus et le relais ouvert
   sont refusés séparément avant tout accès à l’état de retry.

Le greylisting mesure une capacité à réessayer, **pas la légitimité du contenu**.
Un spammeur qui réessaie doit encore traverser tous les moteurs de détection.
Les grandes plateformes peuvent aussi réessayer depuis d’autres réseaux ; un
retard de livraison légitime reste possible. Aucun gain de capture ou taux de
faux positifs n’est présumé à partir des tests synthétiques.

## Retry durable, multi-MX et disponibilité

Le tuple comprend le mode, le réseau de l’IP réelle de socket (/24 IPv4, /64
IPv6), l’expéditeur et le destinataire. Les empreintes d’enveloppe sont salées
et séparées par rôle ; le port n’est pas une identité. Les alias distincts et
la casse de la partie locale ne sont pas fusionnés. Le regroupement réseau ne
confère aucune authentification ni exemption des analyses.

Le premier essai conserve un instant minimum fixe. Une tentative prématurée ne
repousse jamais cet instant. Un nouvel essai admissible ouvre une période de
passage fixe. Observation et application occupent des états distincts : le
trafic observé ne préautorise pas silencieusement l’application.

mx1, coordinateur, conserve cet état dans SQLite WAL/FULL. mx2 et les autres
workers interrogent la même autorité via HTTPS, identité de nœud révocable,
certificat vérifié, sans redirection ni proxy implicite. Seules les métadonnées
d’enveloppe et les signaux SMTP nécessaires sont transmis, aucun corps. Le
coordinateur valide à nouveau le destinataire ; les paramètres et l’heure
proviennent de sa configuration et de son horloge.

Les vérifications locales sont limitées à quatre travaux, avec attente SMTP
bornée à 500 ms ; un travail SQLite retardé garde sa capacité jusqu’à sa fin.
L’appel worker complet est borné à 750 ms et sa réponse à 4 Kio. Une erreur,
saturation ou panne de coordination **laisse passer cette couche** et signale
`unavailable`. Le worker n’ouvre pas de cycle indépendant, ce qui évite les
reports répétés d’un MX à l’autre. Les autres limites et analyses restent
applicables. Les quotas partagés sont également indisponibles pendant cette
panne : les limites locales de connexions restent la protection de secours.

## Teergrubing borné

Un sommeil Tokio optionnel précède uniquement une décision de report. Son délai
est limité par la politique et par le budget total de la connexion, conservé
après MAIL, RSET, EHLO et STARTTLS. Le permis de sommeil est partagé par toutes
les sessions du MX, même à travers une révision de configuration. La saturation
supprime l’attente supplémentaire et conserve la réponse 451.

Aucun mutex SQLite, aucune capacité d’analyse DATA et aucune tâche détachée ne
restent détenus pendant le sommeil. L’annulation libère immédiatement le permis.
Ce ralentissement ne garde pas les clients connectés pendant des minutes.

## Réglages

```toml
[smtp_admission]
enabled = false
mode = "observe"
greylisting = true
minimum_providers = 2
retry_delay_seconds = 300
retry_max_age_seconds = 86400
retention_seconds = 604800
rate_per_minute = 120          # 0 désactive ; partagé entre les MX
rate_burst = 60
max_entries = 10000           # capacité par mode, sans éviction d’un retry actif
tarpit_delay_ms = 0           # 0 désactive ; maximum 5000 ms
tarpit_max_concurrent = 8     # par MX ; 1..64
tarpit_session_budget_ms = 5000 # maximum 10000 ms
allow_networks = []           # CIDR explicites, maximum 128
```

Les quotas IPv4 sont par IP exacte ; les quotas IPv6 regroupent /64 pour éviter
une multiplication par rotation d’adresse. Le compteur se recharge sans que les
refus repoussent sa prochaine disponibilité. Sa capacité est bornée ; le plein
laisse passer les nouvelles clés. Les états inactifs de quota expirent après
24 h. Les tuples de retry sont nettoyés par lots de 256. Les compteurs quotidiens
et les diagnostics suivent une conservation de 30 jours. Aucun nouveau corps
ni pièce jointe n’est conservé.

La console affiche les compteurs de tentatives, par mode et résultat, et les
motifs de transport des messages acceptés. Les 451 apparaissent dans les logs
`SMTP intelligent admission`, mais ne sont pas des messages acceptés en file.
Les diagnostics dédupliqués ne contiennent pas d’adresses cachées. Une panne
empêchant l’enregistrement des compteurs reste visible dans les logs et dans
les diagnostics d’un message accepté.

## Déploiement et validation

Déployer 0.16.2 sur le coordinateur, puis les workers, avant d’activer la
politique. Les bundles destinés aux anciens workers omettent les nouveaux champs.
Les tables additionnelles ne changent pas le schéma de la file ; elles sont
ignorées par la version précédente. Le retour arrière ne restaure jamais une
ancienne base par-dessus des messages acceptés. Retirer la nouvelle table du
TOML si l’on revient à un binaire qui ne la connaît pas. Si la console a déjà
enregistré `smtp_admission`, un retour à 0.15.3 exige aussi une migration
explicite de ce champ dans la politique persistée ; une simple bascule de binaire
ne suffit pas. Conserver toutes les autres données et la file courante.

Les tests couvrent le retry durable, IPv4/IPv6, la concurrence, la saturation,
les changements de mode, les destinataires multiples, les exceptions, le quota,
les refus avant DATA, l’absence de score ajouté, les permissions Web, les appels
entre deux instances locales et la panne du coordinateur. Aucun essai ne
transmet de message réel à un destinataire externe.

Références : [RFC 6647](https://www.rfc-editor.org/rfc/rfc6647.html),
[greylisting Rspamd](https://docs.rspamd.com/modules/greylisting/),
[quotas Rspamd](https://docs.rspamd.com/modules/ratelimit/).
Implémentation Rust native, sans intégration du moteur Rspamd.
