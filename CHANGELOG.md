# Changelog

Les versions suivent Semantic Versioning. Le projet reste en 0.x : un changement
incompatible demande une version mineure et une migration documentée.

## [Unreleased]

### 0.5.0-dev.9 — Attente bornée de capacité SMTP

- Ajouter `smtp.processing_wait_ms` (0 à 5 000 ms), une attente optionnelle dans
  l’ordre des demandes de capacité avant la réponse 354. Conserver la limite de
  traitements simultanés, l’expiration avec réponse 451 et la persistance avant
  acceptation. La valeur par défaut 0 conserve le refus temporaire immédiat.
- Tracer la durée et l’issue de cette admission, exposer son réglage dans l’état
  administrateur et permettre sa mesure avec le banc SMTP/OCR. Les résultats
  de débit et de latence de dev.8 ne valident pas par avance ce changement.
- Comparer le réglage sur Linux avec modèles et OCR : 272 analyses et livraisons
  intactes. Sur les lots de 128, les refus temporaires passent de 146 à zéro et
  l’acceptation maximale de 74,38 à 2,38 secondes ; le délai médian augmente avec
  la répartition des tours. Conserver le p95 d’analyse encore supérieur à 500 ms.

### 0.5.0-dev.8 — Attente efficace des processus OCR

- Attendre la fin des décodeurs et du job OCR par notification `pidfd` sur Linux,
  avec repli borné lorsque ce mécanisme est indisponible. Conserver les délais,
  plafonds de sortie et arrêts du groupe de processus, avec des tests réels des
  expirations, erreurs et descripteurs.
- Fournir un outil de comparaison sur image/PDF synthétiques, en alternant les
  versions et en exigeant l’égalité des sorties OCR/QR complètes. Refuser d’écraser
  une mesure existante et conserver un rapport en cas d’échec.
- Publier 11 tests Linux de processus, cinq tests réels OCR/QR/PDF et 32 appels
  comparatifs. Dans ce relevé, les médianes passent de 644 à 553 ms pour l’image
  et de 1 369 à 1 261 ms pour le PDF ; ces petits lots ne prouvent ni la qualité
  de classement ni une capacité soutenue. La production reste distincte.
- Vérifier 136 analyses et livraisons SMTP synthétiques avec le worker du candidat,
  les modèles et les scanners locaux. Le lot de 128 atteint un p95 d’analyse de
  603 ms ; conserver les réessais avant DATA et l’attente maximale de 74 secondes,
  ainsi que les empreintes du worker et les limites de cette mesure isolée.

### 0.5.0-dev.7 — Inspection PNG et diagnostics du banc OCR

- Inspecter les lignes PNG avec un tampon fixe de 8 Kio, en contrôlant leur taille
  exacte et les plafonds absolus. Les bannières ordinaires très compressées ne
  provoquent plus une analyse incomplète due au seul ratio de compression.
- Conserver les contrôles de flux, sommes de contrôle, filtres de lignes et
  budgets partagés, ainsi que les limites de ratio PDF/Office. Versionner les
  nouvelles observations structurelles pour refuser les anciens modèles liés
  à une sémantique différente.
- Conserver les mesures OCR et QR lorsqu’un autre contrôle du banc échoue,
  sans masquer cet échec ni convertir l’analyse en succès.
- Publier le premier relevé Linux du candidat dev.6 : 664 messages synthétiques
  livrés intacts, avec les analyses limitées et l’échec PNG/OCR documentés.
- Vérifier le correctif dev.7 sur Linux : 50 tests d’inspection, 16 messages
  entièrement analysés et livrés intacts, huit OCR/QR vérifiés et six jobs CI
  réussis. Conserver le p95 OCR de 708 ms, encore supérieur à l’objectif initial.

### 0.5.0-dev.6 — Mesures SMTP des moteurs de recherche

- Étendre le banc de charge aux heuristiques FR/EN et à l’inspection HTML/PNG/PDF,
  avec pièces jointes synthétiques, observations attendues et intégrité du corps.
- Compter séparément les scans principaux réussis et les analyses incluant tous
  les modules demandés. Conserver les limites rencontrées et proposer une option
  qui exige des analyses complètes, sans augmenter les budgets du produit.
- Appliquer cette distinction à la mesure d’analyse seule, avec les statuts OCR
  et des moteurs locaux, sans enregistrer le contenu des messages.
- Vérifier ce contrat par de vraies sessions SMTP en CI et inclure le démon ainsi
  que les scripts et fixtures publics dans l’artefact Linux de mesure.
- Corriger les arguments du générateur utilisé par le banc OCR/QR et publier le
  relevé Linux de l’historique adaptatif du candidat précédent.

### 0.5.0-dev.5 — Révocations limitées aux destinataires concernés

- Revérifier la confiance adaptative avec des compteurs propres aux destinataires
  et à leurs droits. Les corrections sans accès à une autre livraison ne forcent
  plus son réessai, y compris pour un ancien message partagé avec copies cachées.
- Couvrir les changements de droits et de comptes, les modifications de preuves,
  la reprise et la maintenance. Borner les compteurs et conserver une invalidation
  globale en cas de débordement, ainsi que la compatibilité de retour au candidat
  précédent.
- Remplacer une assertion de durée instable sur Linux par un serveur simulé qui
  reste silencieux jusqu’à la constatation du délai d’expiration. Le délai réseau
  du produit reste identique.
- Préparer les exécutables Linux de mesure avec une empreinte de l’ensemble des
  sources Rust, y compris les sous-modules. Les résultats locaux restent des
  preuves logicielles, sans activation de la R&D en production.

### 0.5.0-dev.4 — Historique adaptatif par destinataire

- Raccorder la confiance apprise ou configurée à un seuil explicite par
  destinataire, après authentification et contrôles obligatoires. Conserver le
  score du modèle ; ne pas appliquer cette politique aux modèles de fusion.
- Éviter les appels LLM facultatifs des relations éligibles et isoler leur
  décision lorsque d’autres destinataires nécessitent l’analyse normale.
- Persister au plus deux variantes dans une transaction durable, avec corps
  identique, en-têtes/ARC propres, diagnostics privés et reprise indépendante.
- Revérifier les corrections, droits et échéances avant acceptation ; appliquer
  les changements de listes manuelles au rechargement sans multiplier les limites
  de concurrence. Un échec d’acceptation annule les deux variantes.
- Montrer dans la console le seuil appliqué et l’éventuelle omission du LLM.
  Les tests et mesures synthétiques vérifient le mécanisme, sans démontrer une
  amélioration de capture ni activer ces réglages en production.

### 0.5.0-dev.3 — Confirmation avec code affiché

- Ajouter un code visuel généré localement en Rust au parcours de confirmation
  des expéditeurs : le lien seul ne libère plus un message en quarantaine.
- Lier le code au jeton et au nonce, borner sa durée et conserver les quotas de
  vérification et de renouvellement dans SQLite. Consommer code, lien et
  libération dans la même transaction, avec reprise après échec de stockage.
- Fournir une page française sans dépendance externe, avec clic explicite,
  contrôle d’origine, CSP, alternative manuelle et tests du script réellement
  livré. Ce mécanisme facultatif ne prouve ni l’humanité ni la sûreté du message.

### 0.5.0-dev.2 — Fusion des nouveaux signaux

- Raccorder les observations des heuristiques et de l’inspection HTML/PDF/Office
  à un protocole appris v2 de 327 caractéristiques, avec catalogue de règles,
  versions et paramètres liés au modèle ; conserver le protocole v1.
- Étendre l’export natif, l’apprentissage, les comparaisons par familles et la
  prédiction de population. Conserver les observations absentes ou incomplètes
  dans les compteurs et refuser les configurations incompatibles.
- Vérifier l’effet des coefficients v2 sur la décision enregistrée et le marquage
  SMTP dans un test local, ainsi que la parité Rust/Python. Les essais synthétiques
  ne prouvent pas une amélioration de capture et n’activent pas un modèle réel.

### 0.5.0-dev.1 — Moteurs complémentaires

- Ajouter des heuristiques FR/EN compilées, l’inspection bornée HTML/PDF/images/Office
  et leurs diagnostics versionnés, sans contribution automatique des observations.
- Ajouter l’historique de confiance authentifiée par destinataire, les corrections
  humaines, l’expiration et la révocation ; aucun contournement des contrôles malware.
- Ajouter le greylisting durable et la temporisation bornée, avec domination du mode
  global Observation et capacité partagée entre les révisions de configuration.
- Ajouter une vérification ciblée des expéditeurs pour la quarantaine et un connecteur
  CAPEv2 facultatif avec file durable, récupération après interruption et conservation
  bornée. Les résultats dynamiques ne libèrent jamais automatiquement les messages.
- Afficher les observations, limitations et résultats différés dans la console sous
  contrôle des droits ; conserver les preuves privées hors des diagnostics publics.
- Fournir l’export local de développement et une cible de fuzzing des nouveaux
  décodeurs. Documenter les mesures historiques et l’absence de validation d’une VM
  réelle ou d’amélioration démontrée du taux de capture.

## [0.4.2] - 2026-09-10

- Masquer les adresses pouvant être réaffichées dans les réponses SMTP distantes,
  y compris les alias, les copies cachées et les représentations encodées usuelles.
  Le masquage intervient avant troncature et s’applique aussi à la consultation des
  anciens journaux et erreurs dans la console.
- Conserver les codes SMTP, codes étendus, étapes, durées et motifs utiles au
  diagnostic. Les textes importés dépassant le budget d’inspection sont omis.
- Couvrir les réponses distantes, les journaux structurés et l’API authentifiée
  avec des régressions sur les droits par destinataire et la confidentialité.

## [0.4.1] - 2026-09-09

- Historique SMTP sortant par destinataire : serveurs essayés, IP, TLS vérifié,
  réponses positives et négatives, codes étendus, durée et prochaine tentative.
  Les erreurs réseau et de protocole conservent leur contexte ; une déconnexion
  après le `250` final ne provoque pas de nouvelle livraison.
- Diagnostics dans la console : règles déclenchées, effets consultatifs ou
  numériques, contributions du modèle, authentification, durée et réglages
  réellement appliqués à l’analyse. Aucun seuil historique n’est inventé.
- Traces bornées enregistrées avec le résultat de livraison et accessibles
  uniquement aux destinataires autorisés. Migration additive du schéma 2,
  suppression avec les métadonnées, aucun corps ni argument SMTP sortant journalisé.
- Journaux structurés enrichis pour relier analyse, acceptation durable et relais.
  Les modèles, seuils et comportements de filtrage existants sont conservés.

## [0.4.0] - 2026-09-09

Release finale du cycle 0.4, regroupant les versions de développement jusqu’à
0.4.0-dev.4. Elle conserve les comportements de filtrage de ce dernier candidat.

### Fonctionnalités

- Passerelle SMTP Rust concurrente, STARTTLS, file durable et suivi des livraisons
  par destinataire. Domaines, alias et réception de toutes les adresses d’un domaine.
- Analyse locale, authentification email, détection de publicités/newsletters,
  confirmations croisées et connecteurs facultatifs : OCR/QR/PDF, ClamAV,
  Spamhaus DQS, CRDF et VirusTotal. Modèles appris chargés séparément.
- Actions configurables par catégorie : transmettre, tagger ou mettre en
  quarantaine. Libération, suppression et expiration par destinataire.
- Console française adaptée aux mobiles : messages, raisons, corrections,
  quarantaine, compte personnel, domaines, passerelles, filtres et comptes.
  Autorisations vérifiées côté serveur ; réglages versionnés et brouillons conservés.

### Distribution et installation

- Mise à jour des outils de recherche vers PyTorch 2.13.0 et Transformers 5.10.1
  pour leurs correctifs de sécurité ; versions consignées dans les nouveaux exports.
  Les modèles déployés et les résultats historiques ne sont pas modifiés.
- Archives Linux x86-64 et ARM64 : binaire avec moteur sémantique disponible,
  frontend statique, services systemd, exemples, documentation et licences.
  Debian 12+ ou Linux avec glibc 2.36+, Python 3.11+ et systemd.
- Sommes SHA-256 et métadonnées de construction liant chaque archive au commit.
  La publication est conditionnée aux tests Rust, frontend, Python, SMTP et workers Linux.
- [Guide de première installation](https://github.com/crdffrance/NoiseFence/blob/v0.4.0/docs/getting-started.md),
  [contributions](https://github.com/crdffrance/NoiseFence/blob/v0.4.0/CONTRIBUTING.md)
  et [signalement privé de sécurité](https://github.com/crdffrance/NoiseFence/blob/v0.4.0/SECURITY.md).
  Licence GPL-3.0-only. Aucune clé, configuration de production, corpus privé ou modèle entraîné inclus.

### Mise à niveau et limites

- Depuis 0.4.0-dev.4 : aucune nouvelle migration ni modification de politique.
  Depuis 0.3 : sauvegarder configuration et données à l’arrêt avant la migration
  vers le schéma de stockage 2. Les anciens binaires sont incompatibles avec ce schéma ;
  suivre la [procédure de restauration](https://github.com/crdffrance/NoiseFence/blob/v0.4.0/docs/actions.md#migration-de-stockage).
- Observation par défaut. Le marquage nécessite les validations Proton/ARC
  correspondantes ; une release ne modifie ni les MX ni le mode de filtrage.
- Capture ≥ 95 %, faux positifs ≤ 0,1 % et analyse p95 < 500 ms sont des objectifs
  à démontrer sur des données récentes représentatives. Cette publication n’est
  ni une certification de conformité SMTP, ni une garantie de livraison chez Proton.
  SMTPUTF8 reste désactivé ; les analyses incomplètes sont signalées.

## 0.4.0-dev.4 — Réglages adaptés aux petits écrans

- Limite la largeur intrinsèque des sélecteurs dans les formulaires : les options longues ne font plus déborder la politique de filtrage sur téléphone.
- Validation de la politique à 320 pixels et de la navigation clavier des rubriques.
- La version 0.4.0-dev.3 a été publiée pour validation mais n’a pas été installée en production ; la refonte est livrée avec cette correction.

## 0.4.0-dev.3 — Console administrateur et utilisateur

- Navigation séparant messagerie, administration et espace personnel ; accès direct à la quarantaine et menu mobile.
- Tableau de messages distinguant classement et livraison, compteurs interactifs, recherche effaçable, actualisation périodique en arrière-plan et cartes adaptées aux téléphones.
- Détail donnant priorité aux actions et aux principaux indices, avec contrôles techniques repliables.
- Confirmation intégrée de quarantaine : destinataire explicite, annulation clavier, restitution du focus et erreurs dans la fenêtre.
- Écran Mon compte : périmètre autorisé et changement du mot de passe avec confirmation.
- Administration des filtres en cinq rubriques préservant le brouillon ; recherche des comptes par nom, accès et rôle.
- Tests de présentation pour décisions canoniques, antivirus, livraisons multiples et recherche des comptes. Moteur, API, stockage et politique de production inchangés.

## [0.4.0-dev.2] - 2026-09-09

- Normaliser les anciens réglages lors de leur chargement pour examen : les
  actions et poids affichés correspondent aux valeurs que le serveur applique,
  y compris lors du retour à la politique historique sans actions explicites.
- Afficher ce rétablissement dans le récapitulatif et couvrir la compatibilité
  des anciennes révisions par des tests du frontend exécutés dans la CI.
- Conserver le tag dev.1 comme étape de développement ; il n’a pas été installé.

## [0.4.0-dev.1] - 2026-09-09

- Séparer les actions des classements : transmission sans préfixe, marquage ou
  quarantaine, configurables pour spam, PUB et malware confirmé. Conserver
  l’observation par défaut et les validations Proton/ARC pour le marquage.
- Ajouter une quarantaine durable par destinataire, avec libération, suppression,
  expiration de 1 à 30 jours, historique, compteurs et contrôles de session/ACL.
  Le corps reste conservé jusqu’à résolution de toutes les copies ; une libération
  dispose d’un nouveau délai de réessai SMTP.
- Personnaliser huit contributions heuristiques bornées dans la console, avec
  restauration des valeurs par défaut, sans modifier les caractéristiques apprises
  ni supprimer la priorité antivirus et la confirmation du spam.
- Migrer la base au schéma 2. Les versions 0.3 refusent ce schéma pour protéger
  les corps en quarantaine. L’installateur bloque un retour automatique incompatible ;
  sauvegarder avant migration et consulter [la procédure](docs/actions.md).

## [0.3.0-dev.22] - 2026-09-09

- Publier les corrections de cohérence de dev.21 avec le libellé exact
  « indice de suspicion » : le score historique comprend aussi les signaux
  consultatifs actifs.
- Réessayer au maximum trois fois le téléchargement de l’image de construction
  verrouillée par digest, puis échouer si elle reste indisponible. Les tests et
  vérifications d’intégrité restent obligatoires.
- Conserver le tag dev.21 ; sa publication a été interrompue après l’erreur
  HTTP 502 du registre Docker. Aucun binaire dev.21 n’a été installé en production.

## [0.3.0-dev.21] - 2026-09-09

- Donner la priorité aux malwares reconnus par l’antivirus principal, même avec
  un score textuel faible ou une détection de publicité. Conserver l’alerte si
  un autre contrôle échoue, en transmettant toujours sans préfixe dans ce cas.
- Utiliser la même décision pour la catégorie, les en-têtes, les compteurs et
  la console. Identifier la source antivirus sans inventer un score à 100.
- Unifier l’interprétation des avis LLM et des codes ZEN ; conserver PBL/BCL
  sans le poids attribué aux listes de réputation malveillante.
- Conserver les raisons lors d’une nouvelle application de la confirmation,
  et tester les désaccords entre moteurs, les pannes et la persistance des alertes.
- Ajouter la source de décision `antivirus` : les nouvelles analyses nécessitent
  dev.21 ou plus récent pour être lues ; voir la politique de compatibilité dans
  [la documentation](docs/filter-policy.md).

## [0.3.0-dev.20] - 2026-09-09

- Ajouter une option de confirmation du score historique : conserver en
  « À vérifier » les suspicions sans contrôle supplémentaire suffisamment fort,
  avec score et caractéristiques intacts, sans préfixe ni reclassement en légitime.
- Administrer cette option et rechercher les analyses complètes à vérifier,
  en conservant les autorisations par destinataire et la distinction des pannes.
- Préciser les consignes LLM contre les faux positifs fondés sur la brièveté,
  un fournisseur gratuit, un transfert ou une notification de service.
- Tester la conservation des décisions corroborées, l’absence de confiance
  dans les en-têtes fournis, les erreurs des fournisseurs et les droits de console.

## [0.3.0-dev.19] - 2026-09-09

- Verrouiller la dépendance transitive de compilation `sharp` sur 0.35.4 pour
  corriger [GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c).
  Conserver les contrôles d’audit ; ne pas rétrograder les outils Cloudflare.
- Publier la catégorie PUB de dev.18 avec cette correction. Le tag dev.18 reste
  conservé ; sa publication a été interrompue après l’échec de l’audit frontend.

## [0.3.0-dev.18] - 2026-09-09

- Distinguer les publicités et newsletters légitimes dans une catégorie PUB,
  sans modifier le score antispam ; conserver la priorité au spam et exclure
  les messages transactionnels, de service et les conversations identifiables.
- Ajouter les réglages PUB, le filtre et le compteur d’historique, les raisons
  et les corrections explicites PUB/Spam/Légitime avec les mêmes contrôles d’accès.
- Préparer le préfixe [PUB] avec corps inchangé, déduplication des préfixes et
  scellement ARC ; exiger une validation Proton propre à [PUB] avant marquage.
- Exporter les labels PUB sans polluer l’apprentissage binaire ; conserver
  l’ambiguïté des anciens votes et des corrections de sous-types contradictoires.

## [0.3.0-dev.17] - 2026-09-08

- Borner et annuler le faux serveur HTTP des tests de réputation : une échéance
  expirée avant connexion ne laisse plus les contrôles Linux attendre indéfiniment.
- Séparer les délais des tests de quota, de réponse excessive et d’expiration
  pour vérifier chaque erreur même sur un runner chargé. Aucun changement du
  comportement de filtrage par rapport à la version 0.3.0-dev.16.

## [0.3.0-dev.16] - 2026-09-08

- Ajouter les protections consultatives contre l’usurpation, les liens trompeurs
  et les campagnes répétées confirmées dans le domaine destinataire.
- Regrouper les indices HTML, texte et OCR/QR ; utiliser une base locale d’URLs
  exactes, avec import atomique, expiration et unités systemd facultatives.
- Consulter les rapports CRDF Threat Center et VirusTotal avec cache, délais,
  quotas persistants et états d’erreur distincts. Ne soumettre aucun message,
  pièce jointe ou lien complet aux fournisseurs.
- Administrer les noms protégés, exceptions et clés API dans la console, sans
  exposer les secrets dans les réponses, les révisions ou les journaux.
- Conserver le score calibré et les décisions de livraison ; exporter les
  observations pour une validation indépendante avant contribution au classement.

## [0.3.0-dev.15] - 2026-09-08

- Conserver le modèle lexical chargé et son empreinte avec le moteur multilingue
  résident pendant les changements de configuration. Un fichier remplacé sur
  disque n’est activé qu’au redémarrage, après validation de leurs liens.
- Maintenir les domaines désactivés dans le sélecteur de l’historique, sous réserve
  des accès du compte, pour consulter les messages déjà reçus.

## [0.3.0-dev.14] - 2026-09-08

- Administrer les domaines, leurs alias, la réception de toutes les adresses et
  les passerelles de livraison depuis la console française, avec TLS vérifié.
- Appliquer une configuration validée et versionnée sans redémarrage, à la
  prochaine transaction SMTP ; préserver les routes des messages déjà en file.
  Réutiliser les moteurs lourds et leurs limites de concurrence ; isoler et borner
  les recherches SQLite pour préserver les écritures de la file.
- Configurer les détecteurs installés, leur contribution au score et le mode
  observation/marquage. Conserver les exigences de calibration et de validation
  Proton/ARC. Les secrets et ressources restent dans la configuration serveur.
- Donner aux administrateurs une visibilité globale et aux utilisateurs des
  droits par adresse ou domaine (`*@domaine`). Réutiliser les mêmes autorisations
  pour l’historique, les statistiques, les corrections et les exports d’apprentissage.
- Créer, modifier et désactiver les comptes, réinitialiser leurs mots de passe,
  révoquer leurs sessions et protéger le dernier administrateur.
- Afficher la file, les métriques et le journal ; relancer les livraisons temporaires,
  charger une ancienne révision pour examen et restaurer la configuration initiale.
  Ajouter `console-reset` pour la récupération locale, service arrêté.

## [0.3.0-dev.13] - 2026-09-08

- Alimenter les workers de relais dès qu’une livraison se termine ou qu’un
  message est persisté, sans attendre le prochain tick de reprise.
- Regrouper les écritures DATA par blocs de 64 Kio, conserver les contrôles SMTP
  et la confirmation après synchronisation durable du corps et de SQLite.
- Configurer la concurrence DATA/analyse avec `smtp.max_processing` (1–64),
  indépendamment des connexions et du relais ; répondre temporairement avant
  DATA lorsque cette capacité est occupée.
- Attendre brièvement le moteur sémantique dans son budget total, préchauffer
  ses kernels au démarrage et analyser en parallèle avec les scanners locaux.
- Fournir un banc SMTP synthétique isolé : débit, latences, reprises, intégrité,
  corps inchangés, analyses complètes et mémoire. Vérifier petits et gros mails
  dans la CI. Les chiffres SMTP seul ne mesurent pas le filtrage complet.

## [0.3.0-dev.12] - 2026-09-08

- Lire localement le texte français/anglais, les QR codes et codes-barres des
  images jointes, intégrées et des PDF avec Tesseract, ZBar et Poppler isolés.
- Borner temps, mémoire, pixels, pages, octets et sorties ; rendre l'analyse
  incomplète en cas de panne ou de limite, sans bloquer la livraison.
- Afficher les résultats dans la console, intégrer les domaines décodés à la
  réputation configurée et conserver des observations sans texte ni codes bruts.
- Ajouter `vision-inspect` pour lire explicitement un `.eml` local sans DNS,
  LLM, stockage ou livraison. Les nouvelles règles restent consultatives par
  défaut ; aucune performance de capture ou de faux positifs n'est présumée.

## [0.3.0-dev.11] - 2026-09-07

- Évaluer hors ligne chaque ligne d'un export de population avec
  `fusion-population-predict`, sans transformer les observations manquantes ou
  incompatibles en messages légitimes. Vérifier les compteurs, les identités,
  le modèle et les octets exacts du jeu ; publier atomiquement sans écrasement.
- Comparer les cinq candidats figés sur toute la population, avec annotations
  humaines et arbitrages documentés, détection des campagnes déjà utilisées,
  comptage des inconnus et bornes conservatrices. Distinguer mesures par message
  et stabilité par campagne ; empêcher une réévaluation accidentelle du même jeu.
- Tester la chaîne complète d'évaluation sur des cas synthétiques incluant les
  pannes, conflits et données anciennes. Ces mesures ne valident aucun modèle
  pour le trafic réel et n'activent aucun nouveau classement en production.

## [0.3.0-dev.10] - 2026-09-07

- Unifier la décision persistée entre le SMTP, la console, les recherches et les
  statistiques. Distinguer indésirable, légitime et indéterminé ; conserver le
  score historique pour les comparaisons.
- Intégrer la fusion native facultative en observation, puis en décision avec
  modèle lié aux détecteurs et dossier de validation récent. Refuser le marquage
  pour profils inconnus, contrôles incomplets et validation expirée. Le contrôle
  de compatibilité Proton reste indépendant et obligatoire.
- Exporter la population retenue sur un intervalle, y compris les messages
  incomplets, non annotés, contradictoires ou dépourvus d'observations SMTP.
  Conserver une empreinte des octets originaux même lorsque MIME est limité,
  distincte de l'empreinte de campagne. Aucun corps n'est exporté.
- Corriger la saturation LLM : elle rend aussi la décision historique
  indéterminée, sans préfixe ni dépense. Ajouter des tests SMTP, d'accès et de
  cohérence des exports. Aucun nouveau modèle de recherche n'est activé.

## [0.3.0-dev.9] - 2026-09-07

- Ajouter le contrat natif de fusion de 218 observations typées, l'export privé
  `fusion-export` et les prédictions hors ligne `fusion-predict`. Vérifier la
  cohérence des contrôles, les versions des détecteurs et les profils disponibles.
- Apprendre une régression logistique régularisée, calibrer ses probabilités et
  sélectionner un seuil commun sur des lots distincts. Détecter les campagnes
  partagées avec les modèles de contenu ou entre les lots de fusion.
- Figer cinq ablations avant le test, publier mesures, incertitude et couverture,
  et comparer les décisions Python/Rust dans la CI. Les modèles produits restent
  des candidats de recherche ; le score du service et les MX restent inchangés.
- Inclure les modules Rust imbriqués et les protocoles embarqués dans l'empreinte
  des sources des archives, avec la liste des entrées et un schéma explicite.
- Porter le plafond mémoire de FreshClam à 2 Gio : la validation des nouvelles
  bases dépassait 768 Mio et provoquait des redémarrages répétés par manque de
  mémoire. Conserver la vérification des bases et les autres limites du service.

## [0.3.0-dev.8] - 2026-09-07

- Conserver les résultats typés SPF, DKIM, DMARC, ARC, réputation et autres
  moteurs, avec états individuels et résultats partiels malgré un délai dépassé.
  Distinguer réception SMTP, enveloppe fournie et analyse locale ; laisser les
  données anciennes inconnues.
- Identifier les octets des modèles chargés et les réglages de détection.
  Conserver les limites d’attestation des signatures ClamAV et du modèle cloud.
- Préserver les catégories et rôles DQS, distinguer les domaines légitimes
  compromis des domaines malveillants, rejeter les erreurs fournisseur comme
  signaux indisponibles et respecter le TTL positif.
- Ajouter ces observations à l’API et à l’export privé de corrections, avec les
  droits et la rétention existants. Les diagnostics fournis manuellement ne
  deviennent pas des observations SMTP d’apprentissage.
- Versionner le protocole d’étiquetage et l’expérience d’augmentation du contenu.
  Aucun nouveau modèle de contenu ou de fusion n’est activé par cette version.

## [0.3.0-dev.7] - 2026-09-07

- Ajouter un module Rust de cohérence HELO/IP, PTR confirmé et domaine
  d'enveloppe, inspiré des techniques de policyd-weight. Respecter IPv6,
  les enveloppes vides, Null MX et le repli A/AAAA sans MX. Les serveurs
  sortants ne sont pas obligés de correspondre aux MX entrants.
- Borner les recherches DNS, les délais, la concurrence et le cache. Une
  indisponibilité abandonne les contributions partielles et conserve la
  livraison sans préfixe ; aucun rejet SMTP fondé sur ces signaux.
- Observer les poids candidats avant activation explicite de leur contribution
  plafonnée. Afficher les raisons et statuts dans la console, les conserver
  avec les métadonnées et les mesurer avec le banc du pipeline complet.
- Étendre DQS aux domaines HELO et MAIL FROM, prioritaires sur les liens du
  corps, sans dupliquer les contributions ni activer de nouvelle liste.
- Fournir `smtp-check` pour les essais DNS seuls, sans email ni appel payant.
  Tester les réponses DNS réelles sur serveur local et les cas limites.

## [0.3.0-dev.6] - 2026-09-07

- Accepter toutes les adresses valides d'un domaine avec l'option explicite
  `accept_all_recipients`, sans liste de boîtes obligatoire. Transmettre chaque
  adresse à elle-même en conservant la partie locale et les routes configurées.
- Préserver la priorité des alias explicites et les droits de console par
  destination ; refuser les domaines externes, les chaînes et boucles d'alias.
  Tester le relais SMTP de destinataires non déclarés après redémarrage et
  l'isolation des copies cachées.
- Banc de mesure du traitement complet avec modèle chargé une fois, chauffe
  séparée, statuts des connecteurs et p50/p95 par cas. Aucun envoi SMTP, aucun
  contenu ou vecteur enregistré ; appels LLM payants uniquement sur demande
  explicite et avec le budget configuré. Les échecs restent dans les mesures.

## [0.3.0-dev.5] - 2026-09-07

- Router les alias explicites entre domaines configurés vers une boîte canonique
  autorisée, avec la route et les droits de cette boîte. Permettre un domaine
  réservé aux alias sans route propre ; refuser les chaînes, boucles, collisions
  et destinations absentes de la liste autorisée.
- Comparer les domaines sans distinction de casse et conserver exactement la
  partie locale et l'adresse canonique utilisée pour les autorisations.
- Documenter les essais depuis un fournisseur externe via une adresse pilote,
  sans bascule des MX principaux. Vérifier le contenu mis en file, les copies
  cachées et la suppression du corps après résolution de tous les destinataires.

## [0.3.0-dev.4] - 2026-09-07

- Distinguer l'extraction locale des vérifications externes : une panne de DNS,
  scanner ou LLM n'exclut plus des corrections dont les caractéristiques locales
  sont complètes. Conserver le repli sans préfixe et exclure les anciens résultats
  incomplets dont l'extraction ne peut pas être attestée.
- Placer les snapshots d'apprentissage périodique dans le répertoire temporaire
  privé de systemd ; vérifier leur suppression après sortie normale et SIGKILL.
  Publier les poids et métriques agrégées, sans prédictions individuelles.
- Créer les répertoires du service au démarrage, préserver le candidat précédent
  lorsqu'il manque des corrections et enregistrer un statut d'entraînement agrégé.
  Utiliser une même release pour l'export et l'entraînement pendant les mises à jour.

## [0.3.0-dev.3] - 2026-09-07

- Export privé et atomique des corrections de schéma 3, avec empreinte de campagne,
  vecteur sémantique et protocole exact de l’encodeur. Exclure les désaccords,
  droits révoqués, lignes expirées et caractéristiques incompatibles.
- Entraîner des candidats lexicaux/hybrides à partir des caractéristiques retenues,
  sans corps ni accès réseau. Séparer apprentissage, développement, calibration
  et test par campagne ; publier ensemble les poids, la combinaison liée et le
  rapport. Les corrections seules ne rendent jamais un candidat éligible.
- Adapter le service d’entraînement au schéma actif, limiter ses ressources et
  préserver le précédent candidat lors d’un échec. Aucune activation automatique.

## [0.3.0-dev.2] - 2026-09-07

- Tester les archives Linux avec le profil optimisé effectivement distribué.
  Le profil debug de la dépendance `gemm-f16` échouait à compiler sur Linux ARM64
  et a empêché la publication des archives de `0.3.0-dev.1`.
- Ajouter le contrôle ARM64 du moteur multilingue avant la création d'une release.
  Aucun changement des poids, des scores ni de la configuration de filtrage.

## [0.3.0-dev.1] - 2026-09-07

- R&D reproductible sur Apache, Enron-Spam brut et Nazario 2015–2025 : sources
  épinglées, regroupement des doublons proches et partitions indépendantes pour
  apprentissage, sélection, calibration et test. Nazario 2025 reste hors apprentissage.
- Modèles logistiques TF-IDF et avec rapports de vraisemblance bayésiens, comparaison
  de régularisations et export de poids JSON pour une inférence native Rust.
- Schéma de caractéristiques 3 : mots, bigrammes, groupes de caractères et structure,
  avec exclusion du contenu HTML non visible et des anciens marqueurs antispam.
  Conservation du support des anciens modèles et versionnement des caractéristiques.
- Commandes `features-export` et `analyze` pour les essais sans livraison SMTP.
  Aucun candidat de recherche n'est automatiquement activé en production.
- Comparaison facultative d'un encodeur multilingue local figé, avec fichiers
  épinglés, tête logistique et sélection sur le développement uniquement.
- Vérification de réputation sur les liens des corps MIME décodés : les liens
  Base64 et quoted-printable ne disparaissent plus, et les anciens en-têtes de
  filtres ne fournissent plus de domaines à interroger.
- Mesures natives du modèle sur macOS ARM64 et Debian x86-64 de 4 vCPU / 8 Go.
- Encodeur multilingue optionnel exécuté en Rust avec Candle, empreintes vérifiées,
  combinaison liée au modèle lexical et concordance Python/Rust contrôlée.
  Inférence hors des threads réseau, concurrence et délais bornés, score de repli
  calibré et statut visible dans la console. Aucun modèle activé automatiquement.

## [0.2.0-dev.2] - 2026-09-06

- Accepter le champ `tool_calls: []` effectivement renvoyé par Scaleway lorsqu'aucun
  outil n'est appelé ; continuer à refuser les appels réels et les anciens
  `function_call`. Test de régression HTTPS et contrôle des cas interdits.
- Conserver le rapport d'analyse des essais Proton incomplets pour leur diagnostic.
- Configurations Nginx HTTPS, renouvellement Certbot via webroot et services pour
  ClamAV amont 1.4.6, afin d'éviter la version Debian 13 encore vulnérable.
- Supervision périodique des services, scanners, signatures, file, disque, certificat
  et budget LLM. L'analyse reste consultative jusqu'aux validations de livraison.
- Normaliser les permissions de l'archive installée pour permettre son exécution
  par le compte de service après une extraction dans un répertoire privé.

## [0.2.0-dev.1] - 2026-09-06

- Préversion de développement `0.2.0-dev.1` : connecteurs ClamAV officiels et
  signatures complémentaires sur sockets Unix distinctes, limites et verdicts
  visibles dans la console. Profil Sanesecurity LOW, sources et clé épinglées,
  services systemd et test réel EICAR fournis. Pas de quarantaine implémentée.
- Client Scaleway facultatif : HTTPS vérifié, extrait MIME borné, JSON fermé,
  budget SQLite réservé avant appel, tarification explicite et aucune relance
  automatique. Échanges testés localement ; validation cloud encore nécessaire.
- Candidat Bernoulli Bayes et comparaison reproductible avec la régression
  logistique. Contrôles d'activation conservés ; objectifs de qualité non atteints.
- Plan de données récentes, comparaison des technologies, calibration et validation
  du pipeline complet. Aucun de ces nouveaux connecteurs n'est activé par défaut.
- Déploiement des certificats SMTP Let’s Encrypt par hook Certbot : validation du nom,
  de la chaîne et de la clé, permissions restreintes, bascule atomique et retour arrière
  si le redémarrage échoue. Tests du renouvellement ajoutés à la CI.

## [0.1.0] - 2026-09-06

Première version open source de **NoiseFence**, sous GPL-3.0-only.

- Réception SMTP en Rust avec STARTTLS, SIZE, 8BITMIME et PIPELINING.
- File durable SQLite/WAL et spool sur disque, reprise par destinataire et notifications d’échec.
- Analyse locale MIME, règles, régression logistique, SPF/DKIM/DMARC/ARC et connecteur Spamhaus DQS optionnel.
- Console française avec comptes locaux, sessions sécurisées, historique, corrections et droits par destinataire.
- Services systemd, configurations d’exemple et archives Linux x86-64/ARM64.
- Mode observation par défaut ; le marquage exige la validation préalable du relais Proton.

Limites connues : compatibilité réelle Proton non validée ; rappel du candidat historique
60,94 %, sous l’objectif de 95 % ; le taux ≤ 0,1 % de faux positifs n’est pas démontré.
Le modèle candidat ne passe pas le contrôle d’activation. SMTPUTF8 reste désactivé.

[Unreleased]: https://github.com/crdffrance/NoiseFence/compare/v0.3.0-dev.7...HEAD
[0.3.0-dev.7]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.3.0-dev.7
[0.3.0-dev.6]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.3.0-dev.6
[0.3.0-dev.5]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.3.0-dev.5
[0.3.0-dev.4]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.3.0-dev.4
[0.3.0-dev.3]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.3.0-dev.3
[0.3.0-dev.2]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.3.0-dev.2
[0.3.0-dev.1]: https://github.com/crdffrance/NoiseFence/tree/v0.3.0-dev.1
[0.2.0-dev.2]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.2.0-dev.2
[0.2.0-dev.1]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.2.0-dev.1
[0.1.0]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.1.0
