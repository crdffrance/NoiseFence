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

Depuis `0.5.0-dev.8`, le worker utilise les notifications Linux de fin de processus
(`pidfd` et `poll`) pour attendre les décodeurs et le job. Les systèmes qui ne les
fournissent pas conservent l’attente bornée de Python. Le temps déjà écoulé reste
déduit du délai lors d’un repli ; les sorties restent sur fichiers et le superviseur
arrête le groupe de processus après chaque job. Les algorithmes OCR/QR, langues,
résolution et plafonds d’analyse restent ceux de la configuration existante.
La [documentation Python](https://docs.python.org/3/library/subprocess.html#subprocess.Popen.wait)
décrit les pauses de sondage de l’attente POSIX avec délai ;
[`pidfd_open`](https://docs.python.org/3/library/os.html#os.pidfd_open) permet
d’attendre un processus Linux par descripteur.

L'installateur principal redémarre le worker déjà installé pour suivre la nouvelle
version. Lors d'une première activation, installer le worker avant d'ajouter la
section `[vision]`. Contrôler `systemctl status noisefence-vision.socket
noisefence-vision.service`, les états OCR dans la console et les limites mémoire.
Pour revenir en arrière, restaurer ensemble binaire, worker et configuration.
L’empreinte du code du worker fait partie de `backend_sha256`. Lorsqu’une empreinte
est explicitement configurée, appliquer la nouvelle empreinte validée avec le
worker correspondant ; une incompatibilité reste une analyse indisponible.

Tests réels locaux, sans email ni réseau, sur images synthétiques et PDF :

```sh
sudo apt-get install --no-install-recommends qrencode fonts-dejavu-core
/usr/bin/python3 tests/vision_worker.py
/usr/bin/python3 -m unittest discover -s tests_python -p test_vision_process.py -v
sudo /usr/bin/python3 tests/systemd_vision.py
```

## Comparer deux versions du worker

Le [relevé dev.8](../research/vision-process-validation-20260910.json) conserve
les observations brutes, les empreintes et les limites de l’essai. Sur huit
paires par fixture, les sorties complètes sont identiques ; les médianes sont
de 644/553 ms pour l’image et de 1 369/1 261 ms pour le PDF, ancien/nouveau worker.
Le p95 image du candidat reste à 581 ms. Ce sont des appels au superviseur/job
sur deux fixtures publiques, avec un seul CPU et 900 Mio de mémoire ; SMTP,
l’IPC Rust et les autres moteurs sont hors de cette mesure.

Préparer une copie vérifiée d’une ancienne version, puis lancer le comparateur
dans une unité privée limitée en ressources, avec les dépendances OCR installées :

```sh
python3 scripts/vision_compare.py --baseline-worker /chemin/worker-verifie.py \
  --candidate-worker deploy/vision-worker.py --output-dir var/vision-comparison \
  --pairs 8
```

Les deux fichiers de worker sont du code exécuté : utiliser des versions du dépôt
vérifiées. Le programme génère lui-même les fixtures et n’accepte pas de courrier
à analyser. Il alterne les versions, conserve les empreintes du protocole, du
texte, des codes et des erreurs, et exige le QR attendu. Les empreintes des sources
des deux workers sont enregistrées séparément. Une sortie différente ou
incomplète fait échouer la commande et laisse `run_finished=false` dans le rapport.
Un répertoire de sortie existant est refusé. Le comparateur conserve uniquement
les empreintes des sorties OCR dans le JSON ; les fixtures restent publiques et
synthétiques. Il appartient à l’opérateur d’imposer les limites de l’unité de test.
