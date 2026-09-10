# Mesurer le traitement complet

Le [premier relevé Linux de la R&D](../research/capacity-linux-dev6-20260910.json)
conserve les résultats du candidat dev.6, y compris l’échec d’inspection PNG du
profil OCR. Les 664 messages synthétiques sont livrés intacts, mais les analyses
incomplètes ne comptent pas dans le débit d’analyse complète. Ce sont de courts
lots sur un serveur partagé, avec des exclusions détaillées par profil.

Le [rejeu du correctif dev.7](../research/png-linux-validation-20260910.json)
confirme 16 messages livrés intacts et entièrement analysés, dont huit images
avec texte et QR décodés. Le p95 OCR de 708 ms dépasse encore l’objectif de
500 ms. Les 50 tests d’inspection natifs et les six jobs CI AMD64/ARM64 ont réussi
sur le commit indiqué dans le relevé ; cela ne mesure pas la qualité antispam.

Depuis dev.7, le banc OCR ajoute `ocr_requirements_met` et conserve ses compteurs
même si une autre analyse obligatoire échoue. Son code de sortie demeure en
échec et `requirements_met` exige aussi la lecture du texte et du QR attendus.

Le relevé inclut huit appels directs au worker inchangé, limités à un CPU, pour
localiser le temps passé dans Tesseract, les codes-barres et la préparation.
Ce profil exclut le superviseur/job, SMTP, l’inférence et les autres scanners.
L’attente POSIX avec délai peut comporter de courtes pauses de sondage, selon
la [documentation Python](https://docs.python.org/3/library/subprocess.html#subprocess.Popen.wait).
Une attente par notification Linux constitue une piste à mesurer et à valider
sur les arrêts/délais, sans réduire les contrôles OCR.

`model-benchmark` mesure l'extraction et l'inférence locales. Pour mesurer aussi
les connecteurs, le banc `pipeline_probe` appelle le même `Engine::process` que
la réception SMTP, plusieurs fois dans un seul processus. Il charge le modèle
une fois et conserve les caches entre essais. Il ne démarre aucun serveur SMTP,
ne met aucun message en file et ne livre aucun email.

```sh
cargo build --release --locked --features semantic --example pipeline_probe
python3 tests/pipeline_probe.py target/release/examples/pipeline_probe
```

Le workflow manuel `pipeline probe build` fournit aussi un exécutable Linux
x86-64 avec les empreintes de l'exécutable, des sources du moteur et du banc.
Il ne contient ni configuration de production, ni corpus, ni modèle entraîné.

## Définir les cas

Créer un manifeste privé, ici `reports/cases.json`, contenant un à huit cas :

```json
[
  {
    "id": "legitime-texte",
    "path": "legitime.eml",
    "source_ip": "192.0.2.10",
    "helo": "sender.example.test",
    "mail_from": "sender@example.test"
  }
]
```

Le chemin est relatif au manifeste, ou absolu. Chaque message doit être un
fichier régulier, valide, de taille inférieure ou égale à 1 Mio. Les noms de cas
sont des identifiants, sans contenu privé. L'exemple d'adresse IP ci-dessus est
réservé à la documentation : il ne représente pas un expéditeur authentifié.
Pour les vérifications DNS, indiquer le contexte réellement observé à la
réception ou documenter explicitement le caractère synthétique de ce contexte.

La configuration doit désigner les modèles et les connecteurs à mesurer, avec
leurs paramètres habituels. Conserver le même nombre de threads CPU et les
mêmes limites que sur le serveur de référence. Enregistrer séparément CPU, RAM,
charge concurrente, empreintes des modèles et version des bases antivirus.

```sh
RAYON_NUM_THREADS=4 CANDLE_NUM_THREADS=4 TOKENIZERS_PARALLELISM=false \
  target/release/examples/pipeline_probe \
  --config config/local.toml --cases reports/cases.json \
  --output reports/pipeline.jsonl --iterations 30 --warmup 3 --interval-ms 100
```

Le banc exécute les cas séquentiellement, avec quatre workers Tokio. Les cycles
de chauffe figurent dans le fichier mais sont exclus des quantiles. L'intervalle
entre appels est aussi exclu. Les mesures englobent `Engine::process`, dont la
réécriture des en-têtes, mais excluent la lecture des fichiers, le chargement du
modèle, la réception SMTP, la persistance et le relais. Ce n'est pas un test de
débit ou de surcharge du serveur SMTP.

## Contenu externe et coûts

Les vérifications DNS et les scanners suivent la configuration du moteur. Un
LLM payant configuré exige le drapeau explicite `--allow-paid-llm`. Il peut recevoir
les extraits textuels autorisés et utilise le budget durable de `data_dir`.
Ne pas remplacer ce répertoire par un répertoire vide pour contourner le budget.
Les cycles de chauffe peuvent aussi produire des appels payants.

N'utiliser que du contenu autorisé pour ces connecteurs. Les essais de coût et
de latence externes peuvent se faire sur des messages synthétiques. Les
résultats d'un message privé analysé sans réseau ne sont pas comparables à un
essai de toute la chaîne avec DNS et LLM.

## Lire les résultats

Le fichier JSONL commence par la configuration des vérifications, contient une
ligne par appel, puis un récapitulatif `record: "summary", run_finished: true`.
L'absence de ce récapitulatif indique une exécution interrompue ou échouée. Un
fichier existant est refusé ; le banc n'écrase pas une mesure antérieure.

Chaque cas présente p50, p95 et maximum en microsecondes, par rang le plus proche,
ainsi que les nombres d'analyses complètes, incomplètes et en erreur. Les échecs
restent dans `all_trials`. `complete_trials_only` est une vue complémentaire :
elle ne doit pas masquer les délais dépassés ou les services indisponibles.
Vérifier aussi les statuts des composants : un LLM limité par le budget ou jugé
inutile n'a pas exécuté une requête complète.

Le score, la version du modèle, les identifiants des raisons et les durées des
composants sont enregistrés, sans corps, objet, explication LLM ni vecteurs de
caractéristiques. Le rapport comporte l'empreinte du message. Les entrées et
résultats privés restent exclus de Git ; leur conservation relève de l'exploitant.

Ne pas additionner toutes les durées de composants : certains contrôles se
chevauchent. Ne pas agréger plusieurs cas comme s'ils représentaient la fréquence
réelle de ces messages. Un p95 sur quelques messages synthétiques vérifie ces
cas sur cette machine ; il ne démontre ni le p95 du trafic réel, ni la capture,
ni les faux positifs. Mesurer ensuite un ensemble récent représentatif, avec
les statuts des contrôles et les incertitudes, avant toute revendication globale.

## Mesure du 7 septembre 2026

Le [rapport agrégé](../research/pipeline-latency-20260907.json) mesure le moteur
0.3.0-dev.5 et le modèle hybride `research-hybrid-e5-20260907` sur Debian 13,
4 vCPU et 8 Go de RAM nominaux. Chaque profil exécute 30 mesures après trois
appels de chauffe pour chacun des quatre messages synthétiques. Les profils
sont exécutés successivement, avec concurrence 1. Les 360 analyses mesurées
sont complètes, sans erreur ; les deux scanners locaux et les vérifications DNS
configurées sont actifs. Aucun message n'est livré.

| Cas synthétique | Taille | p95 sans LLM | p95 LLM 20–98 | p95 LLM 80–98 |
| --- | ---: | ---: | ---: | ---: |
| Courriel professionnel français | 836 octets | 257 ms | 2 104 ms | 1 207 ms |
| Message court français | 435 octets | 68 ms | 1 027 ms | 67 ms |
| Leurre de portefeuille fictif | 502 octets | 127 ms | 119 ms | 132 ms |
| Paragraphe français répété | 1 Mio | 389 ms | 1 623 ms | 1 605 ms |

La borne basse de 80 supprime l'appel LLM du message court, dont le score local
est 49,42. Le gain sur ce cas s'explique par cet appel évité. Les variations des
autres cas entre exécutions ne démontrent pas un effet du réglage. Le leurre
fictif dépasse déjà la borne haute de 98 et n'appelle le LLM dans aucun profil.
Les deux profils payants totalisent 165 requêtes, chauffe comprise, et une
augmentation du registre partagé de 0,035320 €. Ce montant décrit ces essais,
pas un tarif moyen par email reçu.

Pour le schéma 3 et le seuil 95, l'ajustement LLM positif maximal vaut 1,5 dans
l'échelle avant transformation sigmoïde. À partir d'un score de 80, il conduit
au plus à `100 × sigmoid(log(80/20) + 1,5) = 94,7165`. La transformation est
croissante : les appels en dessous de 80 ne peuvent donc pas faire franchir le
seuil. La borne haute reste à 98. La relecture des 120 décisions enregistrées,
puis l'essai distinct du profil 80–98, ne changent aucun classement sur ces cas.
Les scores, raisons et indicateurs de complétude des appels omis peuvent changer.
Cette justification doit être recalculée si le seuil ou les poids changent ;
80 n'est pas une valeur universelle à copier dans toute configuration.

Ce réglage est actif sur le serveur pilote en observation. Il ne résout pas le
dépassement des 500 ms pour les cas qui utilisent encore le LLM. Le texte de
charge répété sur 1 Mio franchit d'ailleurs le seuil après l'avis LLM : ce
comportement demande une évaluation distincte de la qualité. Ces quatre cas,
non signés et répétés, ne permettent de publier ni taux de faux positifs ni
p95 du trafic réel. Les entrées et mesures détaillées restent privées ; le
rapport public contient leurs empreintes et les résultats agrégés.

## Vérification de la version 0.3.0-dev.11

Le [rapport de cette vérification](../research/pipeline-latency-0311-20260907.json)
reprend les quatre mêmes cas sur le même serveur, avec le code exact de la
version 0.3.0-dev.11 et les modèles inchangés. Le profil de mesure désactive
uniquement le LLM ; la configuration du service reste inchangée en observation.
Les vérifications DNS, la politique SMTP, le modèle hybride et les deux scanners
sont exécutés dans le traitement mesuré.

| Cas synthétique | Taille | p95 sans LLM |
| --- | ---: | ---: |
| Courriel professionnel français | 836 octets | 279 ms |
| Message court français | 435 octets | 77 ms |
| Leurre de portefeuille fictif | 502 octets | 130 ms |
| Paragraphe français répété | 1 Mio | 428 ms |

Les 120 mesures, après 12 appels de chauffe, sont complètes et sans erreur.
Les quantiles ont été recalculés à partir des 132 observations conservées.
Le pic mémoire observé du processus est de 1 253 998 592 octets ; il exclut les
scanners, qui tournent dans leurs propres services. Aucun email n'est livré et
aucun nouvel appel payant n'est effectué. La file, les modèles et la configuration
de production sont préservés.

Le rapport lie le probe au commit de la version et à l'empreinte récursive de ses
sources. L'ancienne empreinte du workflow, qui omet les sous-modules Rust, reste
identifiée séparément. Les statuts et les durées sont conservés sans contenu.
Ce résultat ne mesure pas le profil avec LLM, la concurrence, le p95 du trafic
réel, la capture ou les faux positifs. Aucun seuil n'a été ajusté à partir de
ces cas.

## Concurrence SMTP et relais (0.3.0-dev.13)

Le démon utilise déjà le runtime Tokio multithread : une tâche par connexion
SMTP et plusieurs livraisons concurrentes. Les calculs sémantiques et SQLite
s'exécutent dans le pool bloquant ; l'encodeur utilise également des threads CPU.
Les opérations réseau des scanners se chevauchent avec l'inférence. Le parsing
MIME et l'extraction lexicale restent synchrones et bornés dans les tâches de
traitement ; leur coût fait partie des mesures.

Trois limites distinctes pilotent le serveur : `smtp.max_connections` (128 par
défaut), `smtp.max_processing` (4 par défaut, entre 1 et 64), et `relay.workers`
(8 par défaut). `max_processing` couvre le téléchargement DATA, l'analyse et
la persistance, et ne peut pas dépasser le nombre de connexions. Chaque DATA
occupe un slot ; les autres expéditeurs reçoivent 451 avant le corps et doivent
réessayer. Les uploads lents occupent donc aussi un slot. Augmenter cette limite
consomme plus de mémoire et peut saturer les scanners. Le tampon disque DATA
ajoute 64 Kio par traitement actif ; la taille limite du message n'est pas une
estimation de la mémoire totale du moteur.

Avec un worker sémantique et un worker OCR, commencer par `max_processing = 1`
comme dans l'exemple de production. Monter ensuite selon les mesures ; les
connexions et livraisons restent concurrentes. L'attente du moteur sémantique
partage son délai avec l'inférence, et une tâche CPU qui dépasse son délai
conserve son slot jusqu'à sa fin. Le worker OCR reste séquentiel et un LLM
configuré peut encore ajouter de la latence : multiplier les connexions ne
multiplie pas la capacité de ces composants. Les résultats incomplets doivent
être suivis séparément. Les variables `TOKIO_WORKER_THREADS`, `RAYON_NUM_THREADS`
et `CANDLE_NUM_THREADS` peuvent borner les pools ; éviter de les dimensionner
chacun comme si les autres ne consommaient aucun cœur.

### Banc SMTP reproductible

`scripts/smtp_load.py` démarre le binaire choisi, une **nouvelle file privée** et
un récepteur SMTP local. Aucun destinataire distant n'est configurable. Le banc
n'importe jamais la configuration du service et désactive DNS, DQS et LLM. Il
refuse un répertoire existant. Les paramètres bornent messages, taille,
concurrence et durée ; sous Linux, ajouter des limites systemd CPU/mémoire.

```sh
python3 scripts/smtp_load.py --binary ./noisefence \
  --output-dir /var/tmp/nf-load-small-unique --messages 200 --concurrency 8 \
  --processing 4
python3 scripts/smtp_load.py --binary ./noisefence \
  --output-dir /var/tmp/nf-load-large-unique --messages 40 --concurrency 4 \
  --message-bytes 1048576 --processing 4
```

Ajouter `--lexical-model`, `--semantic-encoder`, `--semantic-combination` et les
options `--antivirus-socket`, `--signatures-socket`, `--vision-socket` pour mesurer
les composants locaux réels. Un worker vision configuré reçoit ici du texte sans
image : cela vérifie son chemin MIME mais **ne mesure pas le débit OCR**. Omettre
`--processing` pour comparer la version 0.3.0-dev.12, qui imposait quatre slots.
Le même binaire et le même matériel doivent être utilisés pour comparer les
réglages. Les messages sont synthétiques et répétitifs ; ils ne constituent pas
un jeu d'évaluation de la qualité.

Le résumé contient les versions et empreintes, tous les statuts des scanners,
les analyses complètes/incomplètes, le débit accepté et livré, ainsi que les
latences d'acceptation (reprises comprises). Il vérifie chaque identifiant,
l'absence de doublon et la conservation exacte des corps, puis l'état durable
`delivered` et l'intégrité SQLite. `correctness_passed` concerne la livraison ;
examiner aussi `complete` et `incomplete`. Le programme échoue si la livraison
n'est pas vérifiée, mais conserve un rapport d'échec. Le pic mémoire échantillonné
à 100 ms et le temps CPU portent sur le démon, sans les services scanners. Le
récepteur Python, le journal et le moniteur font partie de l'environnement de
mesure ; le pic réel peut être supérieur à l'échantillon observé.

Ces essais utilisent SMTP en clair sur loopback, incluent le démarrage à froid
des premiers messages et excluent le temps de chargement du modèle du débit.
Ils complètent les tests STARTTLS, reprise après interruption et accès existants.
Ils ne mesurent ni le débit de Proton, ni celui de TLS, ni un trafic Internet
réel. Toute projection en messages/jour exige un profil représentatif durable.

### Résultats sur le VPS du 8 septembre 2026

Le [rapport complet](../research/smtp-capacity-20260908.json) conserve tous les
profils, y compris ceux qui sautent des contrôles. Les essais comparent les
archives officielles 0.3.0-dev.12 et 0.3.0-dev.13 sur le VPS Debian 13 à 4 vCPU et
7 757 Mio de RAM. Le démon isolé et son client sont plafonnés ensemble à trois
cœurs et 3 Gio ; les scanners locaux utilisent leurs services habituels. Les
configurations du service et ses messages ne sont pas utilisés par le banc.

| Profil synthétique | Messages / clients | Ancien débit livré | Nouveau débit livré | Analyse complète, nouvelle version |
| --- | ---: | ---: | ---: | ---: |
| Texte 1 Kio, moteur léger, 4 traitements | 200 / 8 | 7,99/s | 151,36/s | 200/200, sans modèle ni scanners |
| Texte 1 Mio, moteur léger, 4 traitements | 40 / 4 | 6,39/s | 12,99/s | 40/40, sans modèle ni scanners |
| Rafale 1 Kio, moteur léger, 16 traitements | 1 000 / 128 | Non mesuré | 149,52/s | 1 000/1 000, sans modèle ni scanners |
| Modèle + antivirus, 1 traitement, 4 threads CPU | 100 / 8 | Non mesuré à ce réglage | 2,91/s | 100/100 |
| Modèle + antivirus, 2 traitements, 2 threads CPU | 100 / 8 | Non mesuré à ce réglage | 4,85/s | 100/100, sans image |
| Modèle + antivirus + image/QR, 1 traitement | 20 / 8 | Non mesuré | 1,35/s | 20/20 |
| Modèle + antivirus + image/QR, 2 traitements | 20 / 8 | Non mesuré | 6,08/s | **4/20 : OCR occupé pour les 16 autres** |

La livraison des 200 petits messages passe de 25,02 à 1,32 seconde. Pour les
40 gros messages, le p95 d'acceptation passe de 785 à 315 ms et le temps CPU
échantillonné du démon de 10,64 à 1,26 seconde. Ces comparaisons incluent le
récepteur Python et les écritures durables ; elles ne mesurent pas le relais TLS
vers Proton. Les 2 120 messages de l'ensemble des essais ont été retrouvés dans
le récepteur et en état durable `delivered`, sans doublon ni changement de corps.

Le profil retenu pour le serveur est `max_processing = 1`, un worker sémantique,
quatre threads de calcul et huit workers de relais. Sur le texte, l'analyse p95
est de **339 ms**, avec un pic RSS observé de 1 154 224 128 octets pour le démon.
Avec l'image synthétique de 1 300 × 650 pixels (mail d'environ 27 Kio), le p95
est de **672 ms** : les 20 textes et QR codes sont décodés. Ce dernier cas dépasse
l'objectif initial de 500 ms. Le profil à deux traitements est plus rapide pour
le texte, mais sa saturation OCR ne permet pas de le retenir pour les mails mixtes.

L'ancienne admission de quatre traitements produit seulement 2 analyses complètes
sur 100 lors de la rafale avec un worker sémantique. L'attente bornée de la
nouvelle version, seule, n'est pas suffisante : à quatre traitements, 3/100 sont
complets. Le réglage de l'admission est donc nécessaire avec ces modèles et ce
matériel. Il implique des réponses temporaires avant DATA : sur le lot de texte
retenu, 163 réponses 451 et un p95 d'acceptation de 30,71 secondes, reprises
comprises. Sur le lot OCR retenu, 79 réponses 451 et un p95 d'acceptation de
13,68 secondes. Les clients réels peuvent attendre beaucoup plus longtemps avant
leur prochaine tentative. Le p95 **d'analyse** ne doit pas être présenté comme
une latence d'arrivée sous rafale.

Pour reproduire le cas OCR depuis le dépôt, avec Pillow, `qrencode` et les fontes
DejaVu installés, utiliser `scripts/smtp_load_vision.py` avec les mêmes options
que le banc texte et `--vision-socket`. Ce complément emploie l'image publique de
`tests/vision_worker.py`, sans contenu privé ; il vérifie également la lecture du
texte et du QR pour chaque réponse OCR complète. L'archive v0.3.0-dev.13 contient
le banc texte ; le complément et ce rapport sont disponibles dans le dépôt.
Les réglages du modèle, des antivirus, de l'OCR et du LLM du service restent
actifs ; DNS et LLM ont été exclus uniquement des essais isolés. Une capacité de
production soutenue, avec le trafic réel, TLS et Proton, reste à mesurer.

## Mesurer les moteurs locaux de recherche

Depuis `0.5.0-dev.6`, `scripts/smtp_load.py --research` active les heuristiques
FR/EN et l’inspection du contenu en observation. Le démon, le récepteur SMTP et
la base sont privés au banc ; aucune livraison externe n’est réalisée. Exemple :

```sh
python3 scripts/smtp_load.py --binary target/release/noisefence \
  --output-dir var/load-research-text --messages 200 --concurrency 8 \
  --processing 4 --research --require-complete
python3 scripts/smtp_load.py --binary target/release/noisefence \
  --output-dir var/load-research-documents --messages 100 --concurrency 8 \
  --processing 4 --message-bytes 8192 --attachments --require-complete
```

`--html` utilise le HTML du banc texte. `--attachments` active aussi `--research`
et génère un message MIME avec HTML, PNG et PDF ; il exige au moins 4 096 octets
et ne se combine pas avec `--html` ou `--mailing`. Les attributs HTML et noms PDF
actifs servent d’observations attendues ; aucun de ces éléments n’est exécuté.
Ce profil ne remplace pas le banc OCR/QR de `scripts/smtp_load_vision.py`.

Le schéma `noisefence-smtp-load-2`, utilisé avec `--research`, conserve :

- `primary_complete`, le nombre de scans principaux complets enregistrés ;
- `complete` et `complete_per_second`, qui exigent aussi que l’exécution locale,
  les heuristiques et l’inspection du contenu soient toutes complètes ;
- les états absents, limités ou indisponibles, les identifiants des observations
  et les limites heuristiques rencontrées, sans extrait des messages.

`--require-complete` rend la commande non réussie si une analyse demandée est
partielle. Le rapport reste écrit : `correctness_passed` vérifie la livraison et
les observations contrôlables, tandis que `requirements_met` inclut cette exigence
de complétude. Sans `--research`, le schéma v1 conserve la définition historique.

La mesure d’analyse seule `examples/pipeline_probe.rs` applique la même définition
de complétude aux moteurs de recherche activés et expose aussi le statut OCR.
Elle conserve `primary_complete` pour permettre la comparaison avec les anciens
relevés. Les mécanismes propres à une session SMTP, comme l’historique par
destinataire, restent hors de ce parcours d’analyse seule.

Le test `python3 tests/smtp_load_research.py target/release/noisefence var/load-check`
vérifie huit livraisons documentaires et deux messages de 1 Mio. Ces deux derniers
sont livrés sans corruption mais dépassent la limite de lecture heuristique : le
test exige que le banc le signale et ne les compte pas comme analyses complètes.
Ne pas présenter un débit obtenu avec des contrôles sautés comme une capacité
d’analyse complète. La CI vérifie ce contrat sur AMD64 et ARM64.

## Worker OCR du candidat 0.5.0-dev.8

Le [relevé SMTP du 10 septembre](../research/vision-smtp-validation-20260910.json)
porte sur le binaire Linux et le worker du commit `1a370b7`. Les 136 messages
synthétiques des deux lots sont entièrement analysés et livrés intacts, sans
doublon. Les modèles lexical et sémantique, les scanners locaux, les heuristiques,
l’inspection PNG et l’OCR/QR sont actifs. Le worker utilise un socket privé ; son
empreinte complète correspond à celle reçue dans chaque analyse.

| Lot | Analyse p50 / p95 | Analyse complète et livraison | Réponses 451 avant DATA | Acceptation maximale, reprises comprises |
| --- | --- | --- | --- | --- |
| 8 messages, 4 clients | 552 / 637 ms | 8/8, 1,08/s | 22 | 7,33 s |
| 128 messages, 4 clients | 558 / 603 ms | 128/128, 1,72/s | 146 | 74,36 s |

Le deuxième lot dure 74,48 secondes. Son p95 d’acceptation est de 615 ms, mais
ce percentile masque les quelques attentes très longues : le maximum et les
réessais font partie du résultat. Le plafond reste un traitement simultané pour
conserver tous les contrôles. Le p95 d’analyse dépasse encore l’objectif de
500 ms ; cette mesure ne prouve pas un débit soutenu sur des messages variés.

Le serveur partagé dispose de 4 vCPU et 7 757 Mio de RAM. L’unité SMTP est limitée
à quatre CPU et 3 Gio, l’unité OCR à un CPU et 900 Mio, avec une priorité faible.
Leurs pics mémoire observés sont respectivement d’environ 1 229 et 77 Mio.
Les scanners antivirus et de signatures sont hors de ces deux groupes de
mesure. Le worker reprend le confinement du service livré ; quatre lectures
protégées et la création d’un socket IPv4 sont effectivement refusées dans son
contexte. Ces vérifications ne constituent pas un audit complet d’isolation.

Pour reproduire ce profil, employer `scripts/smtp_load_vision.py` avec
`--messages 128 --concurrency 4 --processing 1 --relay-workers 8 --research
--require-complete`, les modèles locaux et les sockets des scanners. Exécuter
le worker du candidat dans une unité privée avec les restrictions de
`deploy/noisefence-vision.service`. Le mode `--serve --socket` permet un socket
de test dont seuls le worker et le banc possèdent les droits d’accès ; le
déploiement normal utilise l’activation par socket systemd.

Comparer `ocr_backend_sha256` à la sortie `--capabilities` du worker dans cette
même unité. Réutiliser le socket OCR de production mesurerait l’ancien worker.
Le rapport identifie les sources, modèles et composants employés. Aucun appel
DNS, fournisseur externe, LLM, TLS ou Proton n’entre dans cette mesure ; aucune
modification du service de production n’a été nécessaire.

## Attente de capacité avant DATA (candidat 0.5.0-dev.9)

`smtp.processing_wait_ms` permet d’attendre brièvement un traitement disponible
avant d’émettre `354`. Les demandes de capacité déjà en attente passent avant
les nouvelles demandes. Cette option accepte 0 à 5 000 millisecondes ; 0, la
valeur par défaut, conserve la réponse `451` immédiate lorsque la capacité est
occupée. Le réglage dans le fichier de configuration prend effet au redémarrage.

Une attente expirée produit toujours `451 4.3.2` avant le transfert du corps et
réinitialise l’enveloppe. Aucun fichier de message n’est créé avant l’obtention
de la capacité. Les connexions en attente comptent dans les limites globales et
par IP ; `max_processing` continue de limiter ensemble réception du corps,
analyse et persistance. Une annulation libère la réservation de capacité.
L’ordre concerne les demandes encore en attente, pas les futures tentatives
d’un expéditeur après un refus.

Le journal `SMTP processing admission` conserve `waited_ms`, `limit_ms` et
`admitted`, sans enveloppe ni contenu. L’état administrateur expose le réglage.
Le banc accepte `--processing-wait-ms 3000` et l’inscrit dans le rapport et la
configuration privée. Omettre cette option permet encore de mesurer les anciens
binaires ; comparer explicitement 0 et la valeur choisie pour un candidat.

Cette option vise la longue attente avec réessais observée dans le relevé dev.8.
Son effet doit être mesuré à modèles, worker OCR, limites et complétude identiques.
Elle n’accélère pas les décodeurs et ne prouve pas une baisse du p95 d’analyse.
Les rafales dépassant sa durée maximale reçoivent encore des refus temporaires.

Le [comparatif Linux de dev.9](../research/smtp-capacity-wait-linux-20260910.json)
emploie le même binaire, les mêmes modèles, le même worker OCR et quatre clients.
Les deux lots de 128 messages donnent :

| Mesure | Attente désactivée | Attente maximale configurée à 3 s |
| --- | --- | --- |
| Messages entièrement analysés et livrés intacts | 128/128 | 128/128 |
| Refus temporaires avant DATA | 146 | 0 |
| Acceptation médiane | 0,56 s | 2,24 s |
| Acceptation p95 | 0,62 s | 2,33 s |
| Acceptation maximale, reprises comprises | 74,38 s | 2,38 s |
| Analyse p95 | 595 ms | 585 ms |
| Analyses complètes et livraisons par seconde | 1,72 | 1,77 |

L’attente répartit l’accès au traitement : elle supprime les attentes extrêmes
de ce lot, en augmentant les délais médian et p95 des autres messages. Il ne
faut donc pas la présenter comme une accélération générale. Le p95 d’analyse
reste au-dessus de 500 ms ; les dix millisecondes d’écart entre ces essais
successifs ne prouvent pas une accélération des décodeurs.

Avec les deux essais courts initiaux, les 272 messages sont entièrement analysés
et livrés sans changement de corps ni doublon. Une comparaison sur les originaux
identiques retrouve les mêmes scores, décisions, caractéristiques lexicales,
identifiants/poids de raisons et résumés OCR entre les deux réglages. Cela prouve
la stabilité de ces résultats sur la fixture, pas la qualité du classement sur
du courrier réel. Les données, limites de ressources, empreintes et ordre des
lots figurent dans le relevé. Les unités privées et copies de modèles ont été
retirées après conservation de l’audit ; la production reste inchangée.
## Rendu PDF du candidat 0.5.0-dev.10

Le [comparatif Linux](../research/vision-pdf-validation-20260910.json) conserve
huit paires d’appels au superviseur pour une image et huit pour un PDF scanné.
Le candidat remplace seulement le PNG produit par Poppler par un PPM RGB.
Les textes, QR codes, index de pages, statuts et erreurs sont identiques sur
les 32 réponses comparées. Le raster décodé est aussi comparé pixel par pixel.

Sur le PDF synthétique, la médiane passe de 1 236 à 981 ms et le p95 de 1 284 à
1 018 ms. La variation mesurée sur l’image, dont le traitement est inchangé,
illustre le bruit de mesure. Une première expérience remplaçant également les
PNG normalisés n’avait pas montré de gain sur les images ; elle n’est pas retenue.

Ces appels emploient un CPU et 900 Mio dans une unité temporaire Linux sans
réseau ni accès à l’état de production. Ils excluent SMTP, l’IPC Rust et les
autres moteurs. Ils ne prouvent ni le débit soutenu ni l’objectif de 500 ms.
Le protocole public de reproduction reste `scripts/vision_compare.py`, décrit
dans le guide OCR. `research/profile_tesseract.py` permet de distinguer sur une
image synthétique l’initialisation et la reconnaissance via l’API C documentée de
[Tesseract 5.5](https://github.com/tesseract-ocr/tesseract/blob/5.5.0/include/tesseract/capi.h).
Exécuter ce profilage dans une unité de test avec les mêmes plafonds, jamais
comme service de traitement des messages. Ses timings ne mesurent pas le worker.
## Profils OCR image et PDF du candidat 0.5.0-dev.11

Le banc `scripts/smtp_load_vision.py` accepte `--vision-fixture image` (défaut),
`pdf` ou `alternating`. Ce dernier alterne un message image et un message PDF
scanné et exige au moins deux messages. Les pièces restent synthétiques ; le
texte OCR et le QR attendus sont contrôlés comme pour le profil image.

`ocr_by_kind` sépare effectifs, complétude, vérification et latences par type.
L’attribution utilise l’empreinte de l’original conservée par le moteur, pas
l’ordre d’arrivée en base. Un PDF sans correspondance rend le test en échec.
Les compteurs restent enregistrés si une autre analyse échoue ; employer
`--require-complete` pour exiger toutes les analyses du profil.

Le premier raccordement Linux a livré quatre images et quatre PDF : l’OCR était
complet, mais les quatre inspections PDF étaient incomplètes. Le
[relevé](../research/pdf-structure-validation-20260910.json) conserve cet échec,
le correctif du générateur synthétique et les tests du contrôle JPEG/PDF.
Il ne présente pas cet essai comme une capacité validée du candidat corrigé.

Le [relevé corrigé sur Linux](../research/vision-pdf-linux-validation-20260910.json)
utilise le binaire dev.11 du commit `dc5a909`, dont les six jobs CI ont réussi.
Douze messages vérifient d’abord le raccordement du banc, puis 280 messages passent
par les modèles lexical et sémantique, l’antivirus, les signatures, les heuristiques,
l’inspection structurelle et l’OCR. Tous sont entièrement analysés et livrés
intacts. Les trois lots les plus longs donnent :

| Profil | Messages | Analyse p95 | Analyses complètes et livraisons/s | Réponses temporaires avant DATA |
| --- | --- | --- | --- | --- |
| Image | 64 | 590 ms | 1,75 | 0 |
| PDF scanné | 64 | 1 031 ms | 1,01 | 5 |
| Alternance image/PDF | 128 | 1 030 ms | 1,27 | 0 |

Une réponse temporaire supplémentaire concerne le petit lot PDF initial. Les
clients réessaient et les six réponses `451` ne provoquent aucune perte. Les
profils alternés contiennent une seule pièce jointe par message, image ou PDF.
Le test avec plusieurs types de pièces joints au même message reste à effectuer.

Le banc emploie quatre clients SMTP, un traitement simultané, une attente de
capacité de trois secondes et un worker OCR séquentiel limité à un CPU et 900 Mio.
L’unité SMTP est plafonnée à quatre CPU et 3 Gio sur un hôte partagé de 4 vCPU et
environ 8 Go. Son pic mémoire cgroup atteint 1,22 Gio ; celui du worker 135 Mio.
Les scanners externes à ces unités ne sont pas inclus dans ces pics.

Les 44 comparaisons d’images originales identiques retrouvent les mêmes décisions,
caractéristiques et résumés OCR sélectionnés. Cela ne mesure pas la capture ni
les faux positifs. L’objectif de p95 inférieur à 500 ms reste non atteint.
Le débit soutenu et le parallélisme OCR doivent être mesurés en conservant
la couverture des décodeurs et l’isolation des traitements. Les empreintes,
versions des moteurs et limites du banc sont conservées dans le relevé ; les
unités et copies de modèles temporaires ont été supprimées après l’audit.

## Mesurer le pool OCR (candidat 0.5.0-dev.13)

Le banc accepte `--vision-additional-socket /run/worker-2.sock` (répétable) et
`--vision-parallel 2`. Chaque socket doit joindre une instance indépendante du
worker du candidat. Le rapport conserve les nombres de sockets et de réservations
configurés ; il ne déduit pas le nombre de processus réels de ces seuls paramètres.

`--vision-fixture combined` ajoute une image et un PDF au même message. Ce profil
exige deux pièces sélectionnées, deux pages, deux QR codes et au moins 160 caractères
extraits, ainsi qu’une attribution à l’empreinte de l’original. Une page
ou un code manquant fait échouer le profil. Le profil `alternating` continue
d’envoyer un type de pièce par message, avec des latences séparées par type.

Comparer une et deux instances avec le même binaire, les mêmes modèles et budgets,
et un `--processing` cohérent avec les réservations OCR. Exiger `--require-complete`,
conserver tous les refus temporaires et erreurs, et contrôler les corps livrés.
Les tests de chevauchement de jobs et de sockets ne prouvent pas un gain de débit
du pipeline complet. Les mesures dev.11 ci-dessus ne qualifient pas le pool dev.13.

Le [relevé Linux de dev.13](../research/vision-pool-linux-validation-20260910.json)
compare maintenant une et deux instances avec le même binaire, les modèles
lexicaux/sémantiques, les deux scanners locaux et les inspections R&D. Sur le
serveur partagé de 4 vCPU et 7 757 Mio, les 200 messages synthétiques sont acceptés,
entièrement analysés et livrés intacts. Les deux contrôles initiaux de quatre
messages sont exclus des débits ci-dessous ; chaque case agrège deux essais de
16 messages avec des originaux identiques, dans un ordre alterné entre les modes.

| Pièces par message | Débit complet, 1 worker | Débit complet, 2 workers | Rapport | p95 d’analyse, 1 / 2 workers |
| --- | ---: | ---: | ---: | ---: |
| Une image avec texte et QR | 1,74 msg/s | 3,27 msg/s | × 1,88 | 620 / 659 ms |
| Un PDF scanné avec texte et QR | 1,00 msg/s | 1,95 msg/s | × 1,95 | 1 076 / 1 105 ms |
| Une image et un PDF | 0,69 msg/s | 1,34 msg/s | × 1,95 | 1 490 / 1 542 ms |

Le débit est le nombre d’analyses complètes divisé par la durée totale jusqu’à
livraison. Les quantiles sont recalculés à partir des analyses individuelles.
Les 15 réponses temporaires `451` surviennent avec un seul worker ; les réessais
aboutissent tous. Les 152 comparaisons entre répétitions des 48 originaux ne
montrent aucune différence de score, décision, action, caractéristiques ou
observations, après exclusion des durées et de l’empreinte de politique modifiée
par la concurrence OCR. Les budgets de décodage et de calcul sémantique sont
identiques entre les modes.

Deux workers augmentent la capacité sur ces cas sans réduire leur latence
d’analyse sous 500 ms. Le pic mémoire du groupe SMTP atteint environ 1,23 Gio,
et chacun des deux workers environ 137 Mio ; ces pics couvrent toute la suite
et excluent les scanners partagés. Les deux workers restent alloués pendant
la comparaison, même lorsque le second est inactif. Le réseau SMTP est privé,
sans DNS/authentification, réputation externe, LLM, TLS ou Proton. Le rapport
conserve les limites, les empreintes et le nettoyage des unités et copies de
modèles. Ces courts essais ne mesurent ni un débit soutenu représentatif ni
la qualité du classement ; la production demeure en 0.4.3.
