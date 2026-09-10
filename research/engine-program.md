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
restent distinctes de la production 0.4.2.

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
