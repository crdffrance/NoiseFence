# Changelog

Les versions suivent Semantic Versioning. Les versions 0.x restent expérimentales.

## [Unreleased]

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
