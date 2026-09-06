# Exploitation Linux

## Installation

Compiler sur la cible Linux avec `cargo build --release --locked`. La compilation effectuée sur macOS ne produit pas un binaire Linux. La CI fournie définit les contrôles Linux mais n’a pas été exécutée sur un serveur distant dans cette session.

Les archives locales `release/noisefence-0.1.0-linux-amd64.tar.gz` et
`release/noisefence-0.1.0-linux-arm64.tar.gz` sont construites dans des conteneurs Linux
Bookworm avec Rust 1.98. Choisir l’architecture correspondant à `uname -m`
(`x86_64` → amd64, `aarch64` → arm64). Elles nécessitent glibc 2.36 ou plus récente,
par exemple Debian 12 ou Ubuntu 24.04. Elles ne conviennent pas à Alpine/musl.
Après extraction, vérifier `sha256sum -c SHA256SUMS`. Le binaire est `noisefence` et
le dossier `web` contient uniquement la console publique. Installer ces deux éléments
aux emplacements ci-dessous. `build.json` enregistre l’image et l’empreinte des sources.

Compiler la console avec `npm ci` puis `npm run build` dans `web`. Le répertoire public à distribuer est **`web/dist/client`**. Ne servir ni `web/dist/server`, ni les sources, ni les fichiers de configuration.

Créer un compte système `noisefence`. Installer le binaire sous `/opt/noisefence/noisefence`, les fichiers statiques sous `/opt/noisefence/web`, la configuration sous `/etc/noisefence/config.toml`, et les données sous `/var/lib/noisefence` (propriétaire `noisefence`, mode 0700). Les secrets et clés doivent être lisibles par ce compte sans être accessibles aux autres utilisateurs.

Installer `deploy/noisefence.service` et configurer un proxy HTTPS avec le modèle `deploy/Caddyfile`. Renseigner des certificats SMTP valides pour le hostname de la passerelle ; le certificat HTTPS du proxy n’est pas automatiquement celui du SMTP. Prévoir le renouvellement et le redémarrage du service pour charger les nouveaux certificats.

Le port API 8080 reste lié à loopback. Exposer SMTP/25 et HTTPS/443, plus le port requis par la méthode choisie d’obtention des certificats. Les contrôles d’origine et cookies sécurisés restent actifs en production.

Créer les comptes et leurs adresses via la CLI avant de donner accès à la console. La table des destinataires doit rester synchronisée avec les adresses Proton actives : pas de sondage opportuniste `RCPT TO` chez Proton, pas de catch-all implicite. Les alias sont des correspondances explicites vers une adresse canonique locale au domaine. Le rôle administrateur donne accès aux mesures globales, pas aux messages d’autres utilisateurs sans attribution d’adresse.

## Réputation et DNS

Configurer `filter.spamhaus_key_env = "SPAMHAUS_DQS_KEY"` uniquement avec un accès DQS autorisé. Placer la clé dans `/etc/noisefence/secrets.env`, mode 0600, jamais dans le dépôt ou l’interface. Les requêtes contiennent des IP et noms de domaine, pas de corps ni de pièces jointes. Les réponses d’erreur, refus ou limitations du fournisseur ne deviennent pas des signaux de spam.

Le résolveur système est utilisé par Hickory. Le cache DQS est borné à 10 000 entrées et 60 secondes. Les vérifications d’un message partagent un délai réseau de cinq secondes. Une analyse partielle n’ajoute pas de préfixe.

## Suivi et disponibilité

- `journalctl -u noisefence` expose des événements JSON avec identifiant de file, score, durée et résultat ; aucun corps ou mot de passe n’est journalisé.
- `GET /healthz` indique que l’API répond. Ce n’est pas une preuve de disponibilité de Proton.
- `GET /api/v1/metrics`, avec session administrateur, expose file, âge du plus ancien message, échecs, analyses incomplètes et espace libre.
- `noisefence queue` permet l’inspection opérateur ; `retry UUID` avance seulement la prochaine tentative des destinataires encore en attente.

Définir des alertes sur espace libre inférieur à la réserve, âge de file supérieur à 30 minutes, erreurs Proton récurrentes, échecs non notifiés, taux d’analyses incomplètes et absence d’événements. Le fichier systemd redémarre le service après erreur, avec limitation des redémarrages.

Les délais de nouvelle tentative sont environ 30 minutes, 1 heure, 2 heures, puis 4 heures avec une petite variation. Après cinq jours, générer un avis d’échec. Le client SMTP peut attendre jusqu’aux délais protocolaires pendant une livraison ; un arrêt propre accorde 30 secondes aux sessions actives avant interruption et reprise au redémarrage.

Une seule instance du daemon peut posséder le spool, via un verrou système. La CLI peut être utilisée parallèlement. Ne jamais partager le même répertoire de données entre deux serveurs ou sur NFS. Un arrêt du serveur unique provoque normalement les nouvelles tentatives des expéditeurs ; il n’existe pas de haute disponibilité dans cette version.

Le seuil de réserve disque arrête l’acceptation par erreur temporaire avant saturation. Il ne remplace pas le dimensionnement : prévoir le volume de plusieurs jours de messages et la taille moyenne réelle. Le budget mémoire systemd de 2 Go doit être confronté à un test sur la cible de référence 4 vCPU / 8 Go avant montée en charge.

## Sauvegarde et restauration

Pour une sauvegarde cohérente initiale, arrêter le service, copier le répertoire de données complet et la configuration/les clés avec leurs permissions, puis redémarrer. Ne pas sauvegarder le seul fichier SQLite pendant que son WAL évolue ; les corps en attente et la base doivent appartenir au même instant cohérent.

Au démarrage, les livraisons interrompues repassent en attente. Les fichiers de réception non acceptés et les orphelins sont nettoyés. Si un message référencé par la base a perdu son corps, le serveur refuse de démarrer : restaurer la sauvegarde cohérente et diagnostiquer le stockage. Les fichiers marqués livrés ne doivent pas être réinjectés aveuglément, sous peine de doublons.

## Entraînement périodique

Créer `/var/lib/noisefence/models` avant d’installer le timer fourni. Il exporte les annotations actuelles et entraîne un candidat ; il échoue explicitement quand un sous-ensemble ne contient pas les deux classes. Son activation est volontairement indépendante de la réception SMTP.

Comparer le candidat sur un corpus récent conservé pour la validation. Un modèle qui respecte son évaluation textuelle nécessite encore la validation du pipeline complet. `model-activate` vérifie le hachage du modèle et le rapport, puis remplace atomiquement le modèle actif. Redémarrer le service pour charger la nouvelle version. Conserver la version précédente pour un retour arrière.
