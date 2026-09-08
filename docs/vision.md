# OCR, QR codes et codes-barres

NoiseFence peut lire localement les images MIME jointes ou intégrées (`cid:`), les
images `data:image/...;base64` et les pages des PDF, y compris les PDF scannés.
Tesseract lit le français et l'anglais ; ZBar décode les QR codes et ses formats
de codes-barres, dont EAN et Code 128. Les images PNG, JPEG, GIF, WebP, TIFF et BMP
sont prises en charge. Les images distantes ne sont jamais téléchargées, les liens
ne sont pas ouverts et les documents ne sont jamais exécutés.

## Installation Debian / Ubuntu

Après installation du binaire et du frontend de la même version :

```sh
sudo sh /opt/noisefence/current/deploy/install-vision.sh
```

Ajouter à `/etc/noisefence/config.toml` :

```toml
[vision]
socket = "/run/noisefence-vision/worker.sock"
timeout_ms = 3000
max_parallel = 1
max_parts = 6
max_part_bytes = 4194304
max_total_bytes = 8388608
max_pixels = 8000000
max_pages = 4
max_text_chars = 16000
max_codes = 16
contribute_to_score = false
# Optionnel : empreinte affichée par vision-worker.py --capabilities.
# backend_sha256 = "..."
```

Puis `sudo -u noisefence /opt/noisefence/noisefence --config
/etc/noisefence/config.toml check-config` et `sudo systemctl restart noisefence`.
Le service reçoit seulement les pièces sélectionnées par une socket Unix locale
accessible au groupe `noisefence`. Chaque demande a son processus, sans réseau,
accès aux secrets ou accès à la file SMTP ; mémoire, CPU, pixels, pages, fichiers,
sorties et durée sont bornés. Les fichiers temporaires disparaissent après la
demande. Le renouvellement des paquets de sécurité peut changer l'empreinte du
backend ; mettre à jour un éventuel verrou après vérification des tests.

## Consulter la lecture

Dans le détail d'un message, la console affiche le résultat OCR, le nombre de
caractères, de pages et de codes, les domaines de liens comptés et les raisons.
Les corrections « Spam » / « Légitime » restent disponibles.

Pour voir les textes et les valeurs exactes des codes d'un fichier local :

```sh
sudo -u noisefence /opt/noisefence/noisefence \
  --config /etc/noisefence/config.toml vision-inspect /chemin/message.eml
```

Cette commande affiche du JSON, sans livraison, base de données, DNS ni LLM.
Elle lit le fichier explicitement fourni ; sa sortie peut contenir des secrets
présents dans les QR codes. L'historique SMTP conserve seulement les compteurs,
indicateurs, erreurs techniques et versions, jamais ce texte ni les codes bruts.

## Effet sur la décision et limites

Les domaines des liens récupérés rejoignent les contrôles de réputation DQS,
quand une clé autorisée est configurée, dans la limite commune de douze domaines.
Les identités SMTP restent prioritaires, puis les liens visuels précèdent les
autres liens du corps pour éviter leur éviction par un pied de page volumineux.
Le texte récupéré reçoit aussi un logit
lexical local distinct, consultatif : il ne remplace pas les caractéristiques
textuelles du modèle existant et n'est jamais ajouté aux appels LLM.

Un QR code, un lien ou du texte dans une image ne suffisent pas à marquer un mail.
La règle facultative `contribute_to_score` ajoute au plus 0,75 au logit quand le
contenu visuel combine urgence, demande d'identifiants et lien. Elle reste
désactivée par défaut en attendant une calibration indépendante. Les nouvelles
observations sont conservées pour les analyses ; elles ne sont pas des entrées
du modèle de fusion actuel à 218 caractéristiques. Le changement de politique
invalide la liaison d'un ancien modèle de fusion, qui doit être revalidé.

Une panne, saturation, limite ou pièce illisible rend l'analyse incomplète :
le message est transmis sans préfixe et l'incident est visible. Cela inclut les
documents trop volumineux, chiffrés, les SVG et les pages ou frames excédentaires.
Les images de mauvaise qualité et certains QR codes peuvent rester illisibles
même quand les décodeurs terminent normalement. Ce n'est pas une garantie de
capture ; les taux de faux positifs et de capture restent à mesurer sur des
messages récents indépendants. La cible p95 de 500 ms des messages textuels
ne constitue pas une mesure OCR ; le traitement visuel a son budget distinct.

## Mise à jour et supervision

L'installateur principal redémarre le worker déjà installé pour suivre la nouvelle
version. Lors d'une première activation, installer le worker avant d'ajouter la
section `[vision]`. Contrôler `systemctl status noisefence-vision.socket
noisefence-vision.service`, les états OCR dans la console et les limites mémoire.
Pour revenir en arrière, restaurer ensemble binaire, worker et configuration.

Tests réels locaux, sans email ni réseau, sur images synthétiques et PDF :

```sh
sudo apt-get install --no-install-recommends qrencode fonts-dejavu-core
/usr/bin/python3 tests/vision_worker.py
sudo /usr/bin/python3 tests/systemd_vision.py
```
