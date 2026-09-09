# Première installation

Ce guide installe la release 0.4.0 sur un serveur Linux dédié. Les archives incluent
le binaire Rust, la console statique et les services systemd ; Node et Rust ne sont
pas nécessaires sur le serveur. Aucun compte, secret ou modèle entraîné n’est fourni.

## Prérequis

- Debian 12 ou plus récent, ou distribution avec glibc 2.36+, systemd et Python 3.11+.
  Les archives ne ciblent pas Alpine/musl. Architectures x86-64 et ARM64.
- Droits `sudo`, certificats TLS valides et nom DNS du serveur. Pour recevoir du
  courrier public : port 25 entrant/sortant et enregistrements A/PTR cohérents.
- Domaine et boîtes existantes chez le fournisseur de destination. Les routes
  explicites de NoiseFence ne créent pas de boîtes Proton.
- Espace pour la file, les quarantaines et les sauvegardes. Commencer avec la
  concurrence de l’exemple et mesurer avant de l’augmenter ; voir [performances](performance.md).

## Télécharger et vérifier

Sur le serveur, dans un répertoire de travail vide :

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends ca-certificates curl python3 openssl
nf_version=0.4.0
case "$(uname -m)" in
  x86_64) nf_arch=amd64 ;;
  aarch64) nf_arch=arm64 ;;
  *) echo 'Architecture non prise en charge'; exit 1 ;;
esac
nf_archive="noisefence-${nf_version}-linux-${nf_arch}.tar.gz"
nf_url="https://github.com/crdffrance/NoiseFence/releases/download/v${nf_version}"
curl --fail --location --proto '=https' --proto-redir '=https' --remote-name "$nf_url/$nf_archive"
curl --fail --location --proto '=https' --proto-redir '=https' --remote-name "$nf_url/$nf_archive.sha256"
sha256sum --check "$nf_archive.sha256"
tar -xzf "$nf_archive"
cd "noisefence-${nf_version}-linux-${nf_arch}"
sha256sum --check --quiet SHA256SUMS
./noisefence --version
```

Les deux vérifications doivent réussir. `build.json` identifie la version, le commit,
l’architecture et le schéma de stockage. Les sources correspondantes sont disponibles
depuis le tag GitHub ; les licences sont incluses dans l’archive.

## Préparer le serveur et la configuration

Créer une copie privée de `config/production.example.toml` en dehors de l’archive,
par exemple `../config.local.toml` avec `umask 077`. Adapter au minimum :

| Réglage | Valeur à fournir |
| --- | --- |
| `hostname` | Le nom DNS de la passerelle correspondant au certificat SMTP |
| `smtp.tls_cert`, `smtp.tls_key` | Chaîne et clé TLS lisibles par le compte système `noisefence` |
| `web.public_origin` | L’URL HTTPS exacte de la console |
| `domains` | Les domaines, boîtes ou alias autorisés et leurs routes explicites |
| `relay.postmaster` | Une adresse postmaster existante et configurée |

Conserver `filter.mode = "observe"` pendant la validation initiale. Garder l’API
liée à loopback et `secure_cookies = true` derrière le proxy HTTPS. Une liste de
destinataires vide refuse le courrier : remplir `recipients`, ou activer
`accept_all_recipients = true` pour un domaine dont la réception est prévue chez Proton.
Déclarer aussi `postmaster@domaine` ou son alias.

Pour un premier essai isolé, utiliser SMTP sur loopback/2525 sans changer les MX.
La [procédure d’exploitation](operations.md) décrit les chemins, les permissions,
la réception par domaine, le proxy et le renouvellement TLS. Les exemples
`deploy/nginx.conf` et `deploy/Caddyfile` doivent être adaptés à votre domaine.
Ne pas servir le dossier de configuration ou le répertoire de données avec le proxy.

## Installer et créer l’administrateur

L’installateur crée le compte système `noisefence`, installe la release, contrôle la
configuration et démarre le service. Les certificats doivent être prêts à ce stade.
Sur une installation existante, la configuration en place est conservée.

```sh
sudo sh deploy/install.sh "$PWD" "$(realpath ../config.local.toml)"
sudo -u noisefence /opt/noisefence/noisefence \
  --config /etc/noisefence/config.toml user-add administrateur --admin
sudo systemctl is-active noisefence
sudo journalctl -u noisefence -n 30 --no-pager
curl --fail http://127.0.0.1:8080/healthz
```

Le mot de passe de 12 caractères minimum est saisi deux fois dans le terminal.
Il n’existe pas de mot de passe par défaut. Une fois le proxy et son certificat
configurés, ouvrir l’URL HTTPS choisie et se connecter. Créer ensuite les comptes
utilisateurs et leurs accès depuis [l’administration](console.md).

## Vérifier le traitement

Analyser d’abord un message de test local sans livraison :

```sh
sudo -u noisefence /opt/noisefence/noisefence \
  --config /etc/noisefence/config.toml analyze /chemin/lisible/message.eml
```

Cette commande utilise les connecteurs activés mais ne crée pas d’entrée dans
l’historique de livraison. Pour voir les décisions dans la console, faire passer
un message par SMTP vers un destinataire de test configuré. Suivre les
[essais Proton et le domaine pilote](proton-validation.md), puis contrôler la file
et le dossier d’arrivée côté Proton. Une acceptation SMTP ne prouve pas un placement
en réception. L’activation du marquage Spam/PUB nécessite les rapports correspondants.

Activer progressivement les [actions](actions.md), [OCR/QR](vision.md),
[antivirus](antivirus.md) et [connecteurs de réputation](protection.md) selon les
besoins. Les services externes demandent des accès autorisés et restent optionnels.
Un manque de preuve de classement ou une panne de fournisseur doit rester visible
dans l’analyse. Les objectifs de capture et de faux positifs ne sont pas des
performances acquises de cette distribution.

## Mettre à niveau

Lire le changelog et conserver la version précédente. Arrêter les services qui
écrivent la file ou les modèles avant de sauvegarder `/var/lib/noisefence` et
`/etc/noisefence`. Vérifier la nouvelle archive, puis utiliser son installateur.
Depuis 0.4.0-dev.4, la release 0.4.0 conserve le schéma 2 et les réglages.
Depuis 0.3, appliquer la [migration et ses limites de retour arrière](actions.md#migration-de-stockage).
Une publication GitHub ne met pas automatiquement à jour un serveur.
