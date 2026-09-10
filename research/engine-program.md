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

L’historique de confiance demeure consultatif : son effet sur la décision par
destinataire et l’accélération demandée ne sont pas encore implémentés. Le
challenge vérifie la possession d’une boîte par un jeton ; il ne reproduit pas
encore le mécanisme de code affiché du document et ne prouve pas l’existence
physique d’une personne. Ces écarts restent dans le périmètre d’implémentation.

- Validation d’un vrai CAPEv2 et de sa VM Office isolée : instantané, restauration,
  absence d’accès au serveur de messagerie et au réseau de production, et politique
  de conservation côté analyseur. Les tests synthétiques ne l’attestent pas.
- Apport réel des nouveaux signaux sur un jeu récent indépendant, calibration,
  rappel, faux positifs, précision et intervalles de confiance. Le crédit de
  confiance et les poids expérimentaux ne constituent pas une liste blanche
  automatique validée ni un modèle promu.
- Mesures du traitement complet et du débit sur Linux 4 vCPU/8 Go, puis contrôle
  de la livraison Proton pour les nouvelles actions explicitement activées.
- Validation de chaque nouveau candidat sur Linux et choix d’activation des
  nouveaux modules. La CI du candidat 0.5.0-dev.1 a réussi sur AMD64 et ARM64 ;
  elle ne valide pas par avance les modifications suivantes.

Ces éléments restent dans le périmètre du programme ; le succès des tests locaux
ne les transforme pas en conditions remplies.
