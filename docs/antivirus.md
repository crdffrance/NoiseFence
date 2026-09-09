# Antivirus et signatures complémentaires

Ces connecteurs sont facultatifs et désactivés sans configuration. Dans cette
version de développement, ils enregistrent les détections et leurs raisons ; ils
ne retiennent ni ne suppriment les messages. Depuis dev.21, le statut `malware`
du scanner principal reçoit une [priorité explicite de classement](filter-policy.md),
avec un score décisionnel nul (`null`, pas zéro). Les signatures complémentaires
restent consultatives, sans quarantaine ni rejet antivirus.
Toute politique de rétention ou de modification des messages doit être validée
séparément, notamment avec le relais Proton.

Deux processus sont prévus : ClamAV avec les bases officielles, puis un scanner
consultatif avec les bases Sanesecurity. Leurs scans tournent en parallèle. Cette
séparation évite qu'une première correspondance de spam interrompe la recherche de
malware dans une pièce jointe. Les sockets doivent être différentes et accessibles
uniquement aux comptes de service. Aucun port ClamD TCP n'est nécessaire.

## Bases officielles sous Debian

Installer des paquets ClamAV encore maintenus pour la distribution cible et vérifier
les avis de sécurité. Au 6 septembre 2026, Debian 13 propose encore 1.4.3 et son
[suivi de sécurité](https://security-tracker.debian.org/tracker/source-package/clamav)
signale des vulnérabilités corrigées dans 1.4.6. Ne pas déployer cette ancienne
version sur les messages entrants. Le conteneur historique Bookworm teste le
protocole ; ce n'est pas la version retenue pour le serveur.

Le déploiement utilise le [paquet officiel Cisco Talos 1.4.6](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.4.6),
installé sous `/usr/local`. Pour AMD64, le paquet `clamav-1.4.6.linux.x86_64.deb`
a pour SHA256 `d3ee9e401974855a1edc1761b1425417d126de618d5f0c91cd51209f69f6fcc2`.
Vérifier l'empreinte publiée par le fournisseur avant `dpkg -i`, puis exécuter
`ldconfig`. Ce paquet ne crée ni compte, ni configuration, ni services systemd.

Créer un compte système `clamav`, les répertoires `/etc/clamav`, `/var/lib/clamav`
et `/var/log/clamav`, puis installer `deploy/clamd.conf` et `deploy/freshclam.conf`.
Installer `deploy/clamav-upstream.service` comme `clamav-daemon.service` et
`deploy/freshclam-upstream.service` comme `clamav-freshclam.service`. Ajouter
`noisefence` au groupe `clamav`. Démarrer FreshClam, attendre la validation des
bases, puis démarrer le scanner. Le scanner complémentaire doit également utiliser
`/usr/local/sbin/clamd` dans son unité systemd. Les outils de rechargement se trouvent
dans `/usr/local/bin`. Ne pas installer en parallèle les anciens démons Debian.

Le paquet amont doit être suivi pour ses mises à jour de sécurité ; FreshClam met
à jour les signatures, pas les exécutables. Si Debian fournit ensuite une version
corrigée, la variante suivante utilise ses chemins et unités natifs :

```sh
sudo apt-get install --no-install-recommends clamav clamav-daemon clamav-freshclam clamdscan
sudo cp -an /etc/clamav/clamd.conf /etc/clamav/clamd.conf.before-noisefence
sudo install -m 0644 deploy/clamd.conf /etc/clamav/clamd.conf
sudo install -d /etc/systemd/system/clamav-daemon.service.d /etc/systemd/system/clamav-daemon.socket.d
sudo install -m 0644 deploy/clamav-daemon.override.conf /etc/systemd/system/clamav-daemon.service.d/noisefence.conf
sudo install -m 0644 deploy/clamav-daemon.socket.override.conf /etc/systemd/system/clamav-daemon.socket.d/noisefence.conf
sudo usermod -aG clamav noisefence
sudo systemctl daemon-reload
sudo systemctl enable --now clamav-freshclam.service
```

Attendre le téléchargement et la validation des bases dans le journal FreshClam,
puis redémarrer `clamav-daemon.socket` et `clamav-daemon.service`. Vérifier les
permissions du socket, puis activer la section `[antivirus]` du modèle TOML.
Redémarrer NoiseFence pour charger ses groupes supplémentaires. Conserver une copie
de sa configuration précédente pour retirer le connecteur en cas d'incident.

Les limites fournies couvrent un message de 25 Mio, 100 Mio après décompression,
16 niveaux, 500 fichiers et 2 secondes de travail ClamAV. Le client attend au plus
3 secondes. Les dépassements, archives chiffrées et erreurs restent distincts d'un
résultat sain. Un scan incomplet empêche l'ajout du préfixe antispam. Les plafonds
systemd doivent être confrontés à la charge réelle et aux pics de mise à jour.

## Bases complémentaires

`deploy/fetch-unofficial-sigs.py` télécharge les sources de la version 8.0.0 et
la clé publique Sanesecurity, puis vérifie les empreintes de
`deploy/unofficial-sigs.sources.json`. Il n'exécute et n'installe rien. Une rotation
de clé ou un changement de sources exige une révision de ce manifeste.

```sh
python3 deploy/fetch-unofficial-sigs.py /tmp/noisefence-unofficial-sigs
sudo apt-get install --no-install-recommends gnupg rsync curl socat dnsutils
sudo install -d /etc/clamav-unofficial-sigs /usr/local/share/doc/clamav-unofficial-sigs
sudo install -m 0755 /tmp/noisefence-unofficial-sigs/clamav-unofficial-sigs.sh /usr/local/sbin/clamav-unofficial-sigs
sudo install -m 0644 /tmp/noisefence-unofficial-sigs/config/master.conf /etc/clamav-unofficial-sigs/master.conf
sudo install -m 0644 /tmp/noisefence-unofficial-sigs/config/os/os.debian.conf /etc/clamav-unofficial-sigs/os.conf
sudo install -m 0644 /tmp/noisefence-unofficial-sigs/LICENSE /usr/local/share/doc/clamav-unofficial-sigs/LICENSE
sudo install -m 0644 deploy/unofficial-sigs.user.conf /etc/clamav-unofficial-sigs/user.conf
sudo install -d -o clamav -g clamav /var/lib/noisefence-signatures /var/lib/clamav-unofficial-sigs /var/log/clamav-unofficial-sigs
sudo install -d -o clamav -g clamav -m 0700 /var/lib/clamav-unofficial-sigs/gpg-key
sudo install -m 0600 -o clamav -g clamav /tmp/noisefence-unofficial-sigs/sanesecurity-publickey.gpg /var/lib/clamav-unofficial-sigs/gpg-key/publickey.gpg
sudo install -m 0644 deploy/noisefence-signatures.conf /etc/clamav/noisefence-signatures.conf
sudo install -m 0644 deploy/noisefence-signature-scanner.service deploy/noisefence-signatures.service deploy/noisefence-signatures.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start noisefence-signatures.service
```

Vérifier dans le journal que les bases ont été téléchargées, vérifiées par GPG et
chargées sans erreur. Au premier lancement, l'absence de scanner à recharger est
normale : démarrer ensuite `noisefence-signature-scanner.service`, puis activer son
démarrage automatique et `noisefence-signatures.timer`. Activer enfin `[signatures]`
dans NoiseFence et vérifier les deux résultats indépendants. Ne pas démarrer le
scanner avec un répertoire de bases vide ni cumuler le timer avec un cron amont.

Le profil utilise Sanesecurity LOW et sa liste de corrections, désactive YARA, les
mises à niveau automatiques du programme et les fournisseurs nécessitant un compte
distinct. Les signatures restent consultatives, quelle que soit leur étiquette.
Pour ajouter un fournisseur, vérifier sa licence, sa méthode d'authentification et
son effet sur les faux positifs avant de modifier le profil.

## Contrôles d'exploitation

Surveiller `clamav-freshclam.service`, les deux scanners et
`noisefence-signatures.service` : dernier succès, version des bases effectivement
chargées, erreurs GPG, mémoire, latence et analyses incomplètes. Alerter si les bases
quotidiennes officielles ou les mises à jour complémentaires ont plus de 48 heures.
Interroger `VERSION` sur chaque socket pour relever la version du moteur ; le
journal du programme de mise à jour fournit les versions des bases complémentaires.
Un processus actif avec des bases anciennes ne prouve pas une protection à jour.

Le service FreshClam dispose d'un plafond de 2 Gio : il charge les nouvelles bases
pour les vérifier avant leur installation. Le 7 septembre 2026, l'ancien plafond
de 768 Mio a provoqué des arrêts `oom-kill` répétés pendant cette vérification.
Prévoir ce pic en plus des scanners et de NoiseFence, puis surveiller la mémoire
réellement disponible sur l'hôte. Ne pas désactiver la validation des bases pour
réduire ce besoin. Pour une installation existante, un drop-in systemd
`clamav-freshclam.service.d/30-database-memory.conf` peut contenir :

```ini
[Service]
MemoryMax=2G
```

Après installation du drop-in, exécuter `systemctl daemon-reload` puis
`systemctl restart clamav-freshclam.service`. Vérifier un cycle de mise à jour
réussi et la version chargée par ClamD ; l'état `active` seul ne suffit pas.

`deploy/health-check.py` et les unités `noisefence-health.service`/`.timer`
contrôlent toutes les cinq minutes services, sockets, date de la base quotidienne,
dernier contrôle Sanesecurity, file, disque, certificat et budget LLM. Le rapport
est enregistré dans `/var/lib/noisefence/operational-health.json` et dans le journal
systemd. Un incident fait échouer l'unité ; raccorder ce statut à la supervision
de l'opérateur pour les notifications. Aucun email d'alerte n'est envoyé par ce script.

Le harnais `tests/clamav/Dockerfile` exécute un véritable scan EICAR dans une pièce
jointe MIME et un scan sain sans envoyer d'email. Il utilise des volumes distincts
pour les bases et les artefacts Rust. `NOISEFENCE_TEST_UNOFFICIAL=1` teste également
le téléchargement des sources et des signatures ; respecter les limitations des
fournisseurs si un téléchargement échoue.

Références : [protocole ClamD](https://docs.clamav.net/manual/Usage/ClamdProtocol.html),
[versions de clamav-unofficial-sigs](https://github.com/extremeshok/clamav-unofficial-sigs/releases).
