# Changelog

Les versions suivent Semantic Versioning. Les versions 0.x restent expérimentales.

## [Unreleased]

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

[Unreleased]: https://github.com/crdffrance/NoiseFence/compare/v0.3.0-dev.2...HEAD
[0.3.0-dev.2]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.3.0-dev.2
[0.3.0-dev.1]: https://github.com/crdffrance/NoiseFence/tree/v0.3.0-dev.1
[0.2.0-dev.2]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.2.0-dev.2
[0.2.0-dev.1]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.2.0-dev.1
[0.1.0]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.1.0
