# Programme R&D des moteurs complémentaires

Source de la demande : seize techniques décrites dans le document fourni par
l’utilisateur. Cette liste conserve le périmètre entier ; un module existant,
un test synthétique réussi ou une observation ne prouvent pas une amélioration
de capture. Les commentaires commerciaux du document ne sont pas des mesures
de NoiseFence.

## Exigences et preuves attendues

| Technique | Base au début du programme | Travail / preuve de fin |
|---|---|---|
| Heuristiques FR/EN configurables | règles fixes dans `engine`, catalogue de poids | compilation bornée, MIME décodé, règles configurables, tests et rapport versionné |
| RBL/DNSBL | DQS IP/domaines, cache, états d’erreur | tests des codes, cache/délai ; pas de listes activées sans autorisation |
| Signatures de spam communautaires/locales | scanner de signatures, campagnes issues de retours | prouver l’isolation, la révocation et la distinction avec un malware |
| Corrélation IP/PTR/A/AAAA | `smtp_policy` | tests DNS, signaux corrélés plafonnés, observation |
| Apprentissage bayésien | Bernoulli NB et comparaison logistique | reproduction/export natif ; conserver les résultats défavorables du candidat |
| Listes de confiance manuelles et apprises | exceptions étroites de liens | identités authentifiées, portée destinataire, expiration, révocation et accélération effective mesurée |
| Historique expéditeur/destinataire | pas de confiance fondée sur les échanges | apprentissage humain avec diversité, protection contre l’empoisonnement et effet réel sur le résultat par destinataire |
| URLs trompeuses | HTML5, IDNA/PSL, OCR/QR, flux et réputation | régressions sans ouverture des liens ni double comptage |
| SPF/DKIM | `mail-auth`, original SMTP | tests d’authentification et d’en-têtes falsifiés |
| Domaine expéditeur capable de recevoir | MX, repli A/AAAA, Null MX | tests de routes et DNS indisponible ; sans tentative de livraison de vérification |
| HTML/PDF actifs | contrôles HTML partiels | inspection structurelle bornée, décodage des noms PDF, limitations explicites |
| Caractéristiques images/PDF | OCR/QR et limites de rendu | dimensions/types/nombres cohérents, formats invalides et limites |
| Teergrubing | limites de connexions uniquement | temporisation bornée et annulable, capacité distincte de DATA, tests SMTP |
| Greylisting | absent à la réception | état durable, 451 avant acceptation, reprises et expiration, IPv6 et isolation |
| Challenge/réponse ciblé | libération manuelle de quarantaine | mécanisme complet optionnel, token à usage unique, protection contre le backscatter et accès non autorisés |
| Analyse dynamique des macros | ClamAV, aucune exécution | adaptateur vers analyseur isolé, budget/état durable, tests de protocole et validation de l’isolation ; aucune exécution dans le processus SMTP |

## Livraison et validation

Les nouveaux mécanismes sont configurables et désactivés ou en observation par
défaut. Le greylisting et les actions de livraison ont leur propre activation
explicite. Les signaux expérimentaux ne changent pas silencieusement les modèles
ou les seuils existants. Un réglage doit faire partie de l’empreinte de politique
et une décision doit conserver la version utilisée.

Chaque mécanisme doit être raccordé au traitement réel et aux diagnostics, pas
seulement exposé dans une bibliothèque. Les corpus, métriques et commandes de
comparaison restent reproductibles. Les tests couvrent les limites de ressources,
les erreurs, les accès entre utilisateurs, les messages à plusieurs destinataires
et la reprise après redémarrage lorsque le mécanisme conserve un état.

Les objectifs de capture et de faux positifs restent ceux du protocole
[d’étiquetage](labeling-protocol.md). Ne pas réutiliser le test final pour choisir
les règles. Publier séparément les régressions synthétiques, les mesures de débit
et l’évaluation indépendante du classement.

## Audit initial du 10 septembre 2026

Le code de référence est `51b787f` (0.4.1). Les diagnostics SMTP récemment livrés
constituent un progrès vérifié pour la traçabilité du programme ; ils ne terminent
pas ses nouveaux moteurs. Le tableau conserve cet état initial ; les progrès
et preuves figurent ci-dessous. Ce document est un suivi de périmètre, pas un
certificat de validation ni une autorisation de basculer des MX.

## État du candidat 0.5.0-dev.1

Les seize techniques ont maintenant un chemin d’implémentation dans le produit
ou dans son outillage R&D. Les nouveaux modules sont raccordés au SMTP, à la
persistance et aux diagnostics, avec les limites détaillées dans le
[guide des moteurs](../docs/research-engines.md).

| Ensemble | Implémentation / preuves disponibles |
| --- | --- |
| Heuristiques FR/EN | `heuristics`, 25 régressions ; règles compilées, budgets, MIME décodé et contribution distincte des observations |
| RBL/DNSBL, signatures, liens et authentification | Contrôles existants conservés ; tests des codes fournisseur, erreurs, cache/quota, signatures officielles et consultatives, SPF/DKIM/ARC et en-têtes falsifiés dans la suite complète |
| IP/PTR et route de réception de l’expéditeur | `smtp_policy` conserve les vérifications DNS bornées, le repli A/AAAA et le traitement de Null MX ; aucune livraison de vérification |
| Bayésien | Modèle Bernoulli NB et export/prédiction natifs existants ; les rapports historiques restent conservés, sans nouvelle activation ni prétention de progrès mesuré |
| Confiance et historique | `sender_history`, 30 régressions ; identités authentifiées, corrections humaines, diversité, révocation, TTL et autorisations des copies cachées |
| HTML/PDF/Office/images | `content_inspection`, 45 régressions ; structures actives, décompression, fichiers invalides et couverture partielle |
| Temporisation et greylisting | `smtp_admission`, 22 régressions de module et 6 échanges SMTP ; redémarrage, budgets, annulation, mode Observation et capacité commune entre révisions |
| Vérification ciblée d’expéditeur | `challenge`, 25 régressions ; API réelle, origine/CSRF, jeton unique, état durable et conservation |
| Analyse dynamique | `sandbox`, 29 régressions ; `sandbox_pipeline`, 18 échanges et scénarios avec serveur simulé, chemin SMTP réel et diagnostics sous contrôle d’accès |

La suite centrale avec le moteur sémantique a passé 374 tests au premier contrôle,
puis les 18 scénarios de pipeline et les 25 tests de challenge ont été revérifiés
après leurs derniers ajouts. Le test nécessitant un vrai ClamAV est ignoré sur ce
poste. Les 28 tests frontend, le typage, la compilation et le rendu des diagnostics
dans le navigateur sont validés localement.

Une cible de [fuzzing](../docs/fuzzing.md) exerce les heuristiques et les décodeurs
avec des limites fixes. La campagne locale de 61 secondes a exécuté 77 653 entrées
avec instrumentation de couverture ; une reprise de 2 908 entrées a terminé sans
échec. Le pic RSS rapporté est de 99 Mio. Ce contrôle n’emploie pas AddressSanitizer
et ne remplace pas une longue campagne sur la cible Linux.

Le [relevé Apache](local-detectors-20260910.json) est un essai de développement :
il garde aussi l’échec initial lié aux séparateurs mbox, puis les résultats sur
des copies préparées. Aucun jeu récent réservé au test indépendant n’a été ouvert.

## Preuves encore manquantes avant activation générale

Le candidat 0.5.0-dev.2 ajoute la [fusion v2](fusion.md) : les observations locales,
y compris les propriétés des images et des PDF, disposent d’un chemin complet
vers l’entraînement, la prédiction native et la décision SMTP après promotion.
Les modèles restent liés à leurs versions et paramètres ; une observation
manquante ou incomplète ne devient pas une conclusion légitime. Les expériences
restent distinctes de la production stable, désormais en 0.4.3.

Le [rapport logiciel](fusion-local-validation-20260910.json) conserve les tests,
les empreintes des sources, le premier essai rejeté pour problème d’échelle et
sa correction. La parité finale couvre 2 000 prédictions v1 et 1 600 prédictions
v2 sans désaccord ; chaque audit de population conserve ses 400 messages, dont
les observations absentes ou invalides. Il ne mesure pas la qualité antispam.

## État du candidat 0.5.0-dev.3

Le challenge comporte maintenant le mécanisme de code affiché : génération locale
en Rust, saisie explicite, contrôle du code lié au lien, expiration et quotas
durables. Le code et la libération sont consommés dans la même transaction. Les
tests HTTP/SQLite couvrent les copies cachées, les autorisations actuelles, les
rejeux, les échecs de stockage et les tentatives entre plusieurs connexions.
Le script de la page livrée est testé et son rendu a été contrôlé dans un navigateur
avec une image synthétique issue du générateur Rust. La fonction reste facultative
et désactivée par défaut. Ni le lien ni le code ne prouvent l’existence physique
d’une personne ou la sûreté du message.

Le [relevé de validation](challenge-visual-validation-20260910.json) distingue
les tests du serveur, ceux du script et l’aperçu visuel. Le parcours, les quotas,
les réponses génériques et la migration sont décrits dans le
[guide du challenge](../docs/challenge.md).

## État du candidat 0.5.0-dev.4

Le candidat 0.5.0-dev.4 raccorde maintenant la confiance à une décision par
destinataire et à l’omission réelle du LLM facultatif, tout en maintenant les
contrôles obligatoires. La transaction d’acceptation peut persister deux variantes
sans mélanger les diagnostics ni les destinataires. Une révocation invalide la
preuve avant le commit. Le [guide](../docs/sender-history.md) décrit la configuration,
les conditions restrictives et les compteurs ; le
[relevé logiciel](sender-history-adaptive-validation-20260910.json) sépare les
tests et la mesure synthétique des performances encore à démontrer.

## État du candidat 0.5.0-dev.5

La preuve de confiance est maintenant limitée aux destinataires adaptés et aux
droits pertinents. Les corrections simultanées d’un autre destinataire, même sur
un ancien message partagé, ne forcent plus de réessai sans lien. Le débordement
des compteurs conserve une invalidation globale prudente ; les révocations et
changements d’autorisation restent vérifiés dans la transaction d’acceptation.

Le [relevé de validation](sender-history-scoped-validation-20260910.json) conserve
452 tests Rust réussis et la mesure de 256 preuves de révision avec quatre
lecteurs et 64 transactions de correction concurrentes. Cette mesure porte sur
SQLite et les preuves, pas sur le débit du traitement complet.

La CI du candidat précédent, `0.5.0-dev.4`, a échoué sur une assertion de temps
mural du test de sandbox ; les tests de recherche, du frontend et du déploiement
ont réussi. Le candidat suivant remplace cette assertion par une réponse réseau
retenue jusqu’à la vérification de l’expiration effective. Le délai réseau du
produit n’a pas été augmenté. La CI complète de `0.5.0-dev.5` a ensuite réussi
sur Linux AMD64 et ARM64, avec les contrôles Python, frontend, déploiement,
parité des modèles et livraison SMTP.

Le [relevé Linux](sender-history-linux-validation-20260910.json) ajoute un essai
ciblé de 23 tests avec l’exécutable optimisé du même commit. Il conserve les
256 preuves malgré les corrections sans lien, avec un p95 de vérification de
83 µs dans cette petite base synthétique. La machine possède 4 vCPU et environ
8 Go ; le processus de mesure était limité à deux CPU et 1 Gio, dans un réseau
privé. Les deux problèmes de préparation et leur résolution sont enregistrés.
Cette mesure ne termine pas la qualification de débit du traitement complet.
Le relevé lie les résultats à ce commit précis ; ils ne valident pas par avance
les changements de candidats suivants.

## Banc de capacité du candidat 0.5.0-dev.6

Le banc SMTP peut maintenant activer les deux moteurs locaux et envoyer des
structures HTML, PNG et PDF synthétiques. Il vérifie les observations attendues
sur les analyses complètes et conserve les états limités ou indisponibles dans
les compteurs. Le schéma v2 distingue `primary_complete` du nombre `complete`
incluant la recherche : une analyse principale réussie ne masque plus une
heuristique tronquée dans une mesure de capacité. Les limites du produit restent
identiques.

Le [guide de performance](../docs/performance.md) décrit les profils et le test
d’intégration ; le [relevé logiciel](capacity-probe-validation-20260910.json)
conserve les vérifications du candidat. Le [relevé Linux](capacity-linux-dev6-20260910.json)
ajoute 664 messages synthétiques livrés intacts sur 4 vCPU et 7 757 Mio de RAM,
en réseau privé, avec durabilité réelle. Les modèles lexicaux/sémantiques et les
scanners locaux sont activés dans trois profils distincts. Les 24 messages texte
R&D terminent tous l’analyse, avec un p95 de 338 ms ; ce petit lot ne constitue
pas une garantie de débit soutenu ni une comparaison statistique des moteurs.

La suite conserve deux limites : huit messages de 1 Mio dépassent le budget
heuristique ; les huit images OCR ont texte et QR décodés, mais l’inspection PNG
échoue sur le ratio de compression. Ce dernier cas, inattendu, fait échouer le
critère global du banc. Le candidat dev.7 corrige l’inspection PNG sans relever
les plafonds absolus, avec un rapport structurel révisé et conservation des
résultats OCR même lorsqu’une autre analyse échoue. Le relevé dev.6 demeure
inchangé.

Le [rejeu Linux de dev.7](png-linux-validation-20260910.json) valide 50 tests
natifs d’inspection et 16 livraisons synthétiques intactes et entièrement
analysées. Chacune des huit images OCR fournit le texte et le QR attendus, avec
une inspection PNG complète. Les six jobs CI du commit `28c4a28`, dont Rust
AMD64/ARM64 et la parité des modèles, ont réussi.

Le p95 du profil OCR reste à 708 ms, au-dessus de l’objectif initial de 500 ms.
Huit appels directs au worker inchangé, limités à un CPU, situent l’essentiel
du temps dans Tesseract ; ils excluent SMTP et le démarrage du superviseur/job.
Ce diagnostic conserve les durées brutes et ne démontre ni une capacité soutenue
ni une amélioration de classification. L’optimisation des attentes de processus
reste une piste de recherche ; aucun worker expérimental n’a été activé en
production.

## Travail encore nécessaire

Le candidat `0.5.0-dev.8` intègre la piste d’attente par notification Linux dans
le worker, avec maintien du repli, des délais et de l’arrêt des descendants.
Le [relevé](vision-process-validation-20260910.json) lie les tests et les 32 appels
comparatifs aux sources exactes. Onze tests de processus et cinq tests réels
OCR/QR/PDF passent sous Linux ; les sorties sont identiques sur les deux fixtures.
Les médianes mesurées avec le comparateur publié baissent d’environ 92 ms pour
l’image et 108 ms pour le PDF. Ces résultats locaux ne préjugent pas de la CI
complète du candidat, de la qualité de classement ou d’une activation générale.

Le [rejeu SMTP du même candidat](vision-smtp-validation-20260910.json) ajoute
136 messages entièrement analysés et livrés intacts avec les modèles et les
scanners locaux. L’OCR utilise une unité privée du candidat dont l’empreinte
est vérifiée dans chaque résultat. Le lot de 128 termine en 74,48 secondes,
avec un p95 d’analyse de 603 ms et 146 réponses temporaires avant DATA. Une
acceptation attend jusqu’à 74,36 secondes, reprises comprises. Ces valeurs
conservent l’écart à l’objectif de 500 ms et les limites de l’admission sous
rafale. Le binaire Linux est construit et vérifié. Après l’enregistrement initial
du relevé, les six jobs CI, dont ARM64, ont terminé avec succès ; leur résultat
final est conservé séparément de l’état encore partiel observé au premier relevé.

- Validation d’un vrai CAPEv2 et de sa VM Office isolée : instantané, restauration,
  absence d’accès au serveur de messagerie et au réseau de production, et politique
  de conservation côté analyseur. Les tests synthétiques ne l’attestent pas.
- Apport réel des nouveaux signaux sur un jeu récent indépendant, calibration,
  rappel, faux positifs, précision et intervalles de confiance. Le crédit de
  confiance et les poids expérimentaux ne constituent pas une liste blanche
  automatique validée ni un modèle promu.
- Mesures soutenues du traitement complet et du débit sur Linux 4 vCPU/8 Go,
  au-delà des premiers lots synthétiques, puis contrôle
  de la livraison Proton pour les nouvelles actions explicitement activées.
- Validation de chaque nouveau candidat sur Linux et choix d’activation des
  nouveaux modules. Les CI des candidats 0.5.0-dev.1, 0.5.0-dev.2, 0.5.0-dev.3, 0.5.0-dev.5, 0.5.0-dev.6 et 0.5.0-dev.7 ont réussi
  sur AMD64 et ARM64 ;
  elles ne valident pas par avance les modifications suivantes.

Ces éléments restent dans le périmètre du programme ; le succès des tests locaux
ne les transforme pas en conditions remplies.

## Candidat 0.5.0-dev.9 : admission sous charge

Le relevé OCR précédent expose une attente de 74 secondes liée aux reprises
après refus de capacité. Le candidat suivant ajoute une attente configurable
avant `354`, bornée à cinq secondes et désactivée par défaut. Les demandes encore
en attente conservent leur ordre d’accès au traitement ; une expiration produit
toujours un refus temporaire avant acceptation. Les limites de connexions, de
traitements et de stockage restent appliquées.

Le [relevé logiciel](smtp-capacity-wait-validation-20260910.json) conserve
465 tests Rust réussis, dont quatre contrôles de réservation/expiration et trois
tests SMTP réels de cette admission. Deux lots locaux de seize messages vérifient
le réglage du banc et les livraisons intactes. Ils n’emploient pas les modèles ou
l’OCR ; leur différence de réessais ne constitue pas la comparaison de performance
Linux attendue. Le prochain essai doit comparer les deux réglages avec le même
binaire, les mêmes modèles, le même worker OCR et toutes les analyses complètes.

La première CI de dev.9 échoue sur un autre test de sandbox utilisant un plafond
de 350 ms pour le réseau et les écritures SQLite ensemble. Le correctif de test
maintient la réponse HTTP incomplète ouverte jusqu’à l’observation de
`RequestTimeout`, confirme l’écriture de la réponse et conserve le délai réseau
de 100 ms. Les 29 tests de ce contrat passent ensuite localement. La nouvelle CI du
commit `aba71c2` termine avec succès dans ses six jobs, dont ARM64. Le code d’exécution est inchangé
par ce correctif de test.

Le [comparatif Linux](smtp-capacity-wait-linux-20260910.json) utilise ensuite
le même binaire dev.9 pour les deux réglages. Les 272 messages sont entièrement
analysés et livrés intacts ; les résultats de classement comparés sont identiques
pour chaque original. Dans les lots de 128, les refus temporaires passent de
146 à zéro, et l’attente maximale d’acceptation de 74,38 à 2,38 secondes. Le délai
médian augmente de 0,56 à 2,24 secondes : l’accès au traitement est réparti entre
les clients. Le p95 d’analyse reste supérieur à 500 ms. La CI complète
du correctif réussit ensuite, y compris ARM64 ; le relevé conserve séparément
l’observation intermédiaire et la vérification finale.
## Candidat 0.5.0-dev.10 : coût du rendu PDF

Le profilage synthétique distingue environ 127 ms d’initialisation Tesseract et
183 ms de reconnaissance, hors démarrage des processus et du worker. Il ne
justifie pas de partager un décodeur entre messages. Le candidat conserve
l’isolation existante et évite la compression PNG du raster Poppler intermédiaire.
Le [relevé](vision-pdf-validation-20260910.json) conserve la première expérience
non retenue sur les images et la comparaison finale : 32 sorties OCR/QR complètes
identiques, médiane PDF de 1 236 à 981 ms. La mesure n’inclut pas le SMTP et reste
au-dessus de 500 ms. Les validations de corpus récent indépendant, de sandbox Office
réelle et de qualification du traitement complet restent ouvertes.

La CI du commit documentaire précédent `b30f675` expose une course du test de
nettoyage des descendants : Linux renvoie `ESRCH` quand le processus disparaît
entre l’ouverture et la lecture de son fichier `/proc`. Le test reconnaît désormais
cette disparition, comme `ENOENT`, sans masquer les autres erreurs ni changer
les contrôles de groupe de processus et de délai. Les onze tests passent dans
l’unité Linux isolée après correction ; le worker est identique à celui du
comparatif PDF. Le relevé conserve l’échec initial et les vérifications séparées.
## Candidat 0.5.0-dev.11 : inspection PDF et mesure SMTP

La CI de dev.10 (`7a9430e`) a terminé ses six jobs avec succès, dont ARM64.
Le raccordement du nouveau profil PDF au SMTP révèle ensuite deux causes de
couverture incomplète : une génération xref hors plage dans la fixture produite
par Pillow et l’absence de prise en charge structurelle des images JPEG intégrées.
L’OCR réussi ne masque pas ces limites dans le relevé du banc.

Le candidat suivant corrige la fixture et ajoute l’inspection des image-XObjects
DCT : dimensions, précision, composantes, cadrage et fin de flux. Il conserve la
distinction entre noms PDF actifs et données JPEG opaques. La révision 3 invalide
les anciennes liaisons de modèle côté Rust et Python. Les profils SMTP image/PDF
séparent les mesures par empreinte de message ; une analyse incomplète reste
enregistrée et fait échouer un profil exigeant la complétude.

Le [relevé logiciel](pdf-structure-validation-20260910.json) conserve le premier
échec Linux, les tests Rust/Python et l’analyse locale du vrai moteur sur un PDF
généré valide et deux variantes malformées. Les validations Linux réalisées
ensuite sont enregistrées séparément de ces premiers résultats.

La première CI de dev.11 et son build de mesure échouent sur une assertion du
banc qui attend encore la révision 2 du rapport structurel. Le correctif conserve
une vérification exacte, désormais sur la révision 3. Le test SMTP local valide
ensuite huit analyses complètes et deux volontairement limitées, avec dix corps
livrés intacts. Les échecs initiaux sont conservés dans le relevé ; ils ne valent
pas validation Linux du banc corrigé.

La CI corrigée du commit `dc5a909` termine ses six jobs avec succès, dont ARM64.
Le [relevé Linux](vision-pdf-linux-validation-20260910.json) vérifie les empreintes
de l’artefact et de ses sources avant les essais SMTP. Douze messages vérifient
le raccordement sans modèles, puis 280 messages sont entièrement analysés et
livrés intacts avec modèles, antivirus, signatures et worker OCR du candidat.
Les profils alternent des messages avec une image ou un PDF ; ils ne vérifient
pas encore les deux types de pièces joints au même message.

Les lots de 64 images, 64 PDF et 128 messages alternés atteignent respectivement
des p95 d’analyse de 590, 1 031 et 1 030 ms. Les six réponses temporaires avant DATA
sont suivies d’une livraison réussie. Les 44 comparaisons d’images originales
identiques conservent les mêmes décisions et caractéristiques sélectionnées.
Ces résultats synthétiques, avec un seul traitement simultané et un worker OCR
limité à un CPU, ne démontrent ni le débit soutenu ni la qualité de classement.
L’audit est conservé, les unités temporaires et copies de modèles supprimées.
Les validations du corpus récent, de la sandbox Office réelle et des nouvelles
actions chez Proton restent ouvertes, ainsi que l’objectif d’analyse sous 500 ms.

## Candidat 0.5.0-dev.12 : cohérence avec le relais stable

L’audit des diagnostics en production a révélé un rejet local des noms MX absolus
présents dans les avis d’échec en file. La version stable 0.4.3 corrige ce défaut,
avec validation Linux, TLS et persistance. Le report dans la R&D conserve le nom
absolu pour le DNS et retire un seul point pour les contrôles de boucle et le nom
TLS. Le [relevé local](mx-root-rnd-validation-20260910.json) conserve les quinze
tests de routes, traces SMTP et droits des diagnostics réussis, ainsi que Clippy.
La CI du commit `f7e9ae3` termine ses six jobs avec succès, dont ARM64. Les mesures
PDF effectuées avec dev.11 restent liées à leur propre binaire et à leurs paramètres.

## Candidat 0.5.0-dev.13 : répartir l’OCR entre instances isolées

Les mesures précédentes identifient le coût du worker OCR séquentiel. Le candidat
ajoute un pool de deux à quatre instances indépendantes, chacune avec utilisateur
dynamique et espaces de noms séparés. Le répartiteur Rust réserve une instance
libre dans la limite globale, restitue les réservations après annulation et
conserve les erreurs d’échange. Le traitement de chaque worker reste séquentiel
et les limites des décodeurs sont conservées. La lecture d’une requête partage
désormais une seule seconde entre l’en-tête et tous les fragments du corps.

Le [relevé](vision-pool-validation-20260910.json) conserve les 476 tests Rust du
runtime et les neuf tests ciblés, dont un contrôle supplémentaire d’annulation,
ainsi que 79 tests Python réussis et quatre contrôles spécifiques à Linux omis
localement. L’essai Linux observe des jobs simultanés sur deux workers réels,
des utilisateurs et espaces de noms distincts, et des refus d’accès entre
instances. Les deux requêtes combinant image et PDF sont complètes et leurs
quatre pages sont vérifiées. Les unités et fichiers du banc ont été retirés.

Le profil SMTP `combined` exige les deux pièces dans chaque message, en complément
du profil alterné. L’artefact Linux inclut les templates et le test du pool pour
permettre un essai avec le binaire correspondant. Les six jobs de la CI du commit
`0b2b712`, dont AMD64/ARM64 et les assertions renforcées sur les deux requêtes de
chauffe du worker, ont réussi.

Le [relevé Linux suivant](vision-pool-linux-validation-20260910.json) ajoute
200 messages SMTP synthétiques complets et livrés intacts avec les modèles
lexicaux/sémantiques et les scanners locaux. À limites de décodage identiques,
deux workers et deux traitements SMTP simultanés donnent un débit de 1,88 à
1,95 fois celui d’un worker sur les trois types de pièces. Les 152 comparaisons
entre répétitions des 48 originaux ne montrent aucun changement des décisions
ou des observations, hors durées et empreinte de concurrence. Les bases SQLite
sont intactes ; les 15 refus temporaires du mode séquentiel aboutissent après
réessai. Le contrôle dans les services réels confirme le refus de création de
sockets IPv4 et l’isolation des fichiers et sockets entre workers.

Les fichiers, unités et cinq copies de modèles du banc ont été retirés après
vérification de l’archive d’audit. La production reste en 0.4.3, avec configuration
et modèles inchangés. Le p95 d’analyse reste supérieur à 500 ms ; ces courts lots
sur serveur partagé ne remplissent pas la qualification de débit soutenu,
l’évaluation indépendante du classement, l’exécution Office isolée ni les essais
Proton des nouvelles actions. L’exécution complète d’une mise à niveau avec le
pool déjà installé reste également à vérifier.

## Candidat 0.5.0-dev.14 : restaurer les services après un échec

La revue de l’installateur a identifié deux défauts : l’unité du serveur SMTP
restait celle du candidat lors d’un retour arrière, et la présence du fichier
du worker historique pouvait provoquer son démarrage alors que seul le pool
était utilisé. L’installateur restaure maintenant les définitions du serveur et
des workers, conserve l’état inactif du worker historique et garde le SMTP arrêté
si un worker nécessaire à la restauration ne redémarre pas. Les barrières de
compatibilité SQLite et de configuration demeurent obligatoires.

Le scénario `tests/systemd_install.py` est raccordé au job Linux AMD64 avec le
binaire natif. Il couvre une installation neuve, une mise à niveau et quatre
échecs contrôlés, avec deux workers réels et un message synthétique conservé
dans la file. Il refuse un serveur déjà équipé de NoiseFence. Les deux bundles
utilisent le même binaire et des définitions systemd différentes : ce périmètre
teste les transitions de déploiement, sans prouver la compatibilité entre deux
versions de l’application. Les résultats sont ceux du job du commit testé ;
la CI dev.13 et les mesures précédentes ne valident pas ce nouveau scénario.
