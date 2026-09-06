# Exploitation Linux

## Installation

Compiler sur la cible Linux avec `cargo build --release --locked`. La compilation effectuée sur macOS ne produit pas un binaire Linux. La CI vérifie le code Rust et la console sur Linux ; consulter [GitHub Actions](https://github.com/crdffrance/NoiseFence/actions) pour le résultat correspondant au commit déployé.

Les archives locales `release/noisefence-0.1.0-linux-amd64.tar.gz` et
`release/noisefence-0.1.0-linux-arm64.tar.gz` sont construites dans des conteneurs Linux
Bookworm avec Rust 1.98. Choisir l’architecture correspondant à `uname -m`
(`x86_64` → amd64, `aarch64` → arm64). Elles nécessitent glibc 2.36 ou plus récente,
par exemple Debian 12 ou Ubuntu 24.04. Elles ne conviennent pas à Alpine/musl.
Après extraction, vérifier `sha256sum -c SHA256SUMS`. Le binaire est `noisefence` et
le dossier `web` contient uniquement la console publique. Installer ces deux éléments
aux emplacements ci-dessous. `build.json` enregistre l’image et l’empreinte des sources.

Pour une installation versionnée, exécuter `sudo sh deploy/install.sh /chemin/vers/la/release /chemin/vers/config.local.toml`.
L’installateur conserve les versions dans `/opt/noisefence/releases/VERSION`, remplace
le lien `current` et préserve une configuration existante. Il refuse d’écraser une
autre construction de la même version. Pour revenir en arrière, restaurer le lien
`current` vers la version précédente puis redémarrer `noisefence.service`.

Une première installation peut écouter seulement sur loopback, avec SMTP sur 2525 et
l’API sur 18080, en observation et sans destinataire activé. Dans ce cas, consulter la
console avec un tunnel `ssh -L 18080:127.0.0.1:18080 UTILISATEUR@SERVEUR`, puis ouvrir
`http://127.0.0.1:18080`. Créer ensuite le compte via `user-add` et saisir son mot de passe
sur le serveur. Le passage à SMTP public/25 exige DNS, certificats, destinataires réels
et validation Proton ; il ne résulte pas automatiquement de l’installation du binaire.

Compiler la console avec `npm ci` puis `npm run build` dans `web`. Le répertoire public à distribuer est **`web/dist/client`**. Ne servir ni `web/dist/server`, ni les sources, ni les fichiers de configuration.

Créer un compte système `noisefence`. Installer le binaire sous `/opt/noisefence/noisefence`, les fichiers statiques sous `/opt/noisefence/web`, la configuration sous `/etc/noisefence/config.toml`, et les données sous `/var/lib/noisefence` (propriétaire `noisefence`, mode 0700). Les secrets et clés doivent être lisibles par ce compte sans être accessibles aux autres utilisateurs.

Installer `deploy/noisefence.service` et configurer un proxy HTTPS avec le modèle `deploy/Caddyfile`. Renseigner des certificats SMTP valides pour le hostname de la passerelle ; le certificat HTTPS du proxy n’est pas automatiquement celui du SMTP. Prévoir le renouvellement et le redémarrage du service pour charger les nouveaux certificats.

### Certificat SMTP Let’s Encrypt

Le hook `deploy/certbot-deploy.py` nécessite Python 3.11+, OpenSSL et systemd.
Le nom A du serveur doit pointer vers son IP, le reverse doit être cohérent, et le
port TCP/80 doit être accessible pour le challenge HTTP-01. Ne publier un AAAA que
si IPv6 fonctionne. Le mode Certbot standalone utilise temporairement le port 80 ;
il faut le conserver disponible pour les renouvellements. Si un serveur HTTP est
installé ensuite, adapter la méthode ACME à son webroot ou au DNS.

Sur Debian, installer Certbot puis obtenir le certificat du hostname réellement
configuré dans NoiseFence. Remplacer les valeurs d’exemple :

```sh
sudo apt-get install --no-install-recommends certbot
sudo certbot certonly --standalone --preferred-challenges http \
  --non-interactive --agree-tos --email admin@example.org \
  --cert-name mx.example.org -d mx.example.org --key-type rsa --rsa-key-size 2048
```

Configurer `smtp.tls_cert = "/etc/noisefence/tls/current/fullchain.pem"` et
`smtp.tls_key = "/etc/noisefence/tls/current/key.pem"`. Le hook ne change ni
l’adresse d’écoute SMTP, ni les destinataires, ni le mode de filtrage.

```sh
sudo install -d -m 0755 /usr/local/libexec /etc/letsencrypt/renewal-hooks/deploy
sudo install -m 0755 deploy/certbot-deploy.py /usr/local/libexec/noisefence-certbot-deploy
sudo ln -sfn /usr/local/libexec/noisefence-certbot-deploy \
  /etc/letsencrypt/renewal-hooks/deploy/noisefence
sudo env RENEWED_LINEAGE=/etc/letsencrypt/live/mx.example.org \
  /usr/local/libexec/noisefence-certbot-deploy
sudo systemctl enable --now certbot.timer
```

Seul le certificat dont le nom Certbot correspond au hostname NoiseFence est traité.
Avant activation, le hook vérifie la chaîne de confiance, le nom DNS, la validité
pour au moins 24 heures et la correspondance de la clé privée. Il prépare un
répertoire de version en `root:noisefence`, fichiers 0640 et répertoires 0750,
puis remplace atomiquement le lien `current`. Il redémarre le service s’il est actif
pour charger le nouveau certificat. Si la commande de redémarrage échoue, il restaure
le lien précédent et tente de redémarrer l’ancienne version. Les anciennes versions
du certificat sont conservées dans `tls/versions` pour le retour arrière.

Vérifier l’émission future avec `sudo certbot renew --cert-name mx.example.org --dry-run`.
Cette simulation ne déploie pas son certificat de test et n’exécute pas les hooks
de déploiement par défaut. Contrôler aussi `systemctl list-timers certbot.timer`,
`journalctl -u certbot.service` et l’expiration du certificat effectivement présenté
par SMTP. Ajouter une alerte si celui-ci expire dans moins de 14 jours.

Sur le port réellement configuré, valider STARTTLS et le nom du certificat :

```sh
openssl s_client -starttls smtp -connect 127.0.0.1:2525 \
  -servername mx.example.org -verify_hostname mx.example.org \
  -verify_return_error -brief </dev/null
```

Utiliser `mx.example.org:25` pour vérifier une écoute publique déjà activée. Le
certificat SMTP ne met pas la console web en HTTPS et ne valide pas le relais Proton.
Référence : [guide Certbot](https://eff-certbot.readthedocs.io/en/stable/using.html).

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
