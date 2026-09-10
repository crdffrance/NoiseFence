# Changelog

Les versions suivent Semantic Versioning. Le projet reste en 0.x : un changement
incompatible demande une version mineure et une migration documentée.

## [Unreleased]

## [0.4.4] - 2026-09-10

- Suivre les redirections HTTP et HTML des liens du texte et de l’OCR/QR avec
  un réglage administrateur explicite. Vérifier chaque saut DNS/IP et le
  certificat TLS, exclure les adresses internes et borner temps, volume et
  concurrence. Ne pas exécuter JavaScript ni soumettre de formulaires.
- Comparer les URLs visitées à la base locale de phishing et consulter les
  domaines découverts via les connecteurs configurés, avec priorité aux dernières
  destinations et indication des quotas et omissions.
- Afficher les parcours et leurs interruptions dans les diagnostics, sans
  conserver chemins, paramètres ou pages. Conserver les observations
  consultatives, les modèles et les actions de livraison existants.
- Reporter cette capacité de 0.5.0-dev.15 sur la branche stable 0.4.3, sans
  migration de stockage. Les configurations existantes gardent le suivi désactivé
  jusqu’à son activation depuis la console.

## [0.4.3] - 2026-09-10

- Accepter le point final des noms MX pour le relais SMTP, notamment les avis
  d’échec déjà en file. Conserver la résolution DNS absolue, le nom TLS canonique,
  la vérification des certificats et les contrôles contre les boucles.
- Documenter les tentatives arrêtées avant toute réponse SMTP et couvrir les
  routes avec ou sans port, les noms invalides et la livraison locale des avis.

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
