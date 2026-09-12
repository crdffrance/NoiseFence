# Résultats conservés pour une décision commune

## Score visible et décision

Depuis 0.10.2, le journal, sa vue mobile et le détail affichent aussi le score des
messages « À vérifier » et « Analyse incomplète ». Le champ `score` conserve
l’indice calculé par le moteur ; `decision.score` peut être nul lorsque la
décision s’abstient. Cette absence ne signifie pas que le moteur n’a rien calculé.

La console privilégie le score de décision lorsqu’il existe, puis l’indice
enregistré du contenu. Elle indique « Score indicatif » pour une abstention et
« Score partiel » pour une analyse incomplète, avec les contrôles manquants connus
et une mention si l’extraction locale est limitée. Un indice partiel n’est pas
une estimation validée de l’ensemble du message. Les valeurs absentes ou invalides
restent indisponibles ; elles ne sont jamais remplacées par zéro.

Ce choix d’affichage ne change ni le classement, ni la confirmation, ni les
actions appliquées. Un malware reste prioritaire même avec un faible indice de
contenu. Une notification de livraison générée par le serveur possède une valeur
interne, distincte d’une analyse de trafic entrant. Les messages déjà livrés
profitent de cette présentation sans réanalyse ni modification de leur historique.

## Observations des moteurs

Les [en-têtes SMTP détaillés](message-headers.md), depuis 0.11.0, exposent également
le score disponible avec sa qualification et les contrôles incomplets. Ce format
concerne les nouveaux messages préparés, contrairement à l’affichage de l’historique.

Depuis 0.3.0-dev.8, les nouvelles analyses conservent un champ `evidence` de schéma
`noisefence-evidence-1`. Il prépare l’apprentissage d’une combinaison des moteurs.
Il n’active pas cette combinaison et ne transforme pas le score actuel en
probabilité. Les anciens messages gardent `evidence: null` ; leurs contrôles
manquants ne sont pas déduits des réglages actuels.

## Origine et états

| Origine | Signification | Export du contexte pour la fusion |
| --- | --- | --- |
| `smtp_session` | IP et enveloppe issues du serveur SMTP | Conservé avec un retour humain autorisé |
| `supplied_envelope` | Paramètres fournis au programme, notamment avec `analyze` | Exclu |
| `content_only` | Analyse locale sans session, notamment avec `scan` | Exclu |

Les états sont `disabled`, `not_run`, `complete`, `unavailable`, `busy`, `skipped`
et `limited`. `complete` indique un résultat disponible, pas nécessairement une
authentification réussie ou un message légitime. `not_run` distingue un contrôle
configuré mais non exécuté d’un contrôle désactivé. Un résultat DKIM absent avant
contrôle diffère d’une liste vide après vérification d’un message sans signature.

SPF, DKIM et DMARC ont des états individuels. Les alignements SPF et DKIM de DMARC
restent séparés. ARC est observé indépendamment, même lorsque les autres contrôles
d’authentification sont désactivés. Un ARC valide ne prouve pas la confiance de
Proton envers son signataire.

Les opérations sont marquées avant leur attente asynchrone. Au dépassement du
délai global, les résultats déjà reçus restent conservés : DKIM peut être complet
alors que SPF attend encore le DNS. Les erreurs temporaires d’ARC ou
d’authentification produisent une analyse incomplète et la transmission sans
préfixe. Les en-têtes fournis dans l’email ne peuvent pas remplir ces observations.

## Réputation et contexte

Les requêtes ZEN conservent tous leurs codes de retour. Les requêtes DBL conservent
aussi leurs rôles : enveloppe, HELO, From visible, corps. Une même recherche peut
avoir plusieurs rôles sans être comptée plusieurs fois. Les adresses mappées
IPv4/IPv6 utilisent la recherche ZEN IPv4 correspondante.

Depuis dev.21, PBL 10/11 et BCL 30 n’ajoutent plus le poids historique +4 de
réputation malveillante. Leurs codes restent disponibles pour l’évaluation ;
la confirmation emploie la même interprétation que le score.

Les domaines malveillants et légitimes compromis sont distincts. Les codes DBL
102–106 ne déclenchent plus le poids historique de domaine malveillant pour une
identité d’expéditeur. Dans les liens du corps, ils restent observés avec un poids
nul en attente de calibration. Cela suit la distinction de contexte recommandée
par Spamhaus ; aucun gain de qualité réelle n’est déduit de cette seule modification.

Le connecteur traite tous les codes, avec un maximum de 32 entrées par réponse.
Codes d’erreur, réponses de zone incohérente et codes non pris en charge deviennent
une indisponibilité. Un résultat négatif n’est retenu qu’après NXDOMAIN. Le cache
positif ne prolonge pas le TTL, avec un plafond de 60 secondes ; le résolveur gère
son cache négatif. Les limites restent une IP et douze domaines dans le délai
global existant. Après un premier domaine malveillant, les recherches suivantes
restent explicitement `not_run`.

DQS reste désactivé sans clé autorisée. Les clés, noms DNS et identités brutes ne
sont pas copiés dans `evidence`.

## Artefacts et confidentialité

Les SHA-256 des modèles lexical et sémantique correspondent aux octets chargés.
La combinaison est liée au modèle lexical déjà chargé ; une relecture ultérieure
du fichier ne peut pas en changer l’identité. Le protocole de l’encodeur, la
version de l’application, le verrou des dépendances, les réglages de détection
et le prompt LLM sont tracés. Les réglages sont empreintés sans exporter chemins,
clés, comptes cloud ou destinataires.

Le contexte LLM contient sa catégorie et ses nombres déclarés, sans son
explication textuelle. Ce ne sont ni des labels humains ni des probabilités
validées. Le score déterminant sa consultation permet d’étudier ce biais de
sélection. Le score historique final est une référence de comparaison ; il doit
rester exclu des entrées d’une fusion apprise.

Le résultat du scanner complémentaire est conservé avant sa conversion en
signal consultatif. Sa catégorie brute ne change pas la politique de livraison
qui limite ce scanner à un avis.

ClamD n’atteste pas le jeu exact de signatures chargé pour chaque INSTREAM :
`antivirus_database_sha256` et `signatures_database_sha256` restent inconnus.
Le nom du modèle cloud ne garantit pas non plus une révision immuable :
`llm_model_revision` reste inconnue. Ces limites restent à traiter pour une
validation complète ; un fichier sur disque ou un nom mutable ne constitue pas
une preuve de l’artefact réellement utilisé.

Les observations suivent la rétention de trente jours et les droits existants
par destinataire, y compris les copies cachées. Elles n’ajoutent ni corps, ni
destinataires, ni noms de domaines à la vue partagée. Elles sont disponibles dans
l’API de l’historique et les analyses CLI.

## Apprentissage

`export-learning` ajoute `evidence` au schéma de corrections existant. Il conserve
uniquement les contextes `smtp_session` supportés et cohérents, et laisse le champ
nul pour les données historiques, locales ou fournies manuellement. Les compteurs
`evidence_exported`, `missing_evidence` et `non_smtp_evidence` mesurent la couverture.
Les conflits de labels, droits, rétention et exclusions de vecteurs incomplets
restent vérifiés. Une panne externe ne retire pas des caractéristiques locales
complètes du corpus.

L’entraîneur de contenu ignore ce champ additionnel. Un entraîneur de fusion devra
exiger les artefacts attendus, utiliser des sorties hors entraînement, traiter les
corrélations et la disponibilité, puis disposer de lots distincts pour
probabilités, seuil et test. Les corrections seules restent un échantillon biaisé.

Références : [protocole de validation](../research/labeling-protocol.md),
[codes Spamhaus](https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/040-zones.html),
[contexte SMTP selon Spamhaus](https://docs.spamhaus.com/datasets/docs/source/40-real-world-usage/smtp/020-SMTP-Checks.html).
