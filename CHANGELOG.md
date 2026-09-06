# Changelog

Les versions suivent Semantic Versioning. Les versions 0.x restent expérimentales.

## [Unreleased]

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

[Unreleased]: https://github.com/crdffrance/NoiseFence/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/crdffrance/NoiseFence/releases/tag/v0.1.0
