# NoiseFence

Passerelle SMTP en Rust, avec moteur antispam local et console française. Elle reçoit les messages des destinataires autorisés, les analyse, les enregistre durablement et les transmet aux MX Proton configurés. En mode `tag`, les messages suspects reçoivent `[SPAM]` dans l’objet. Le score ne provoque ni rejet ni quarantaine.

**Version de développement 0.3.0-dev.15 — expérimentale, en observation par défaut.** Les versions publiées sont disponibles dans les [releases](https://github.com/crdffrance/NoiseFence/releases). La compatibilité réelle avec Proton et les objectifs de capture restent à démontrer. Voir les mesures du [candidat Rust appris](research/model-card-20260906.md), la [comparaison multilingue](research/semantic-card-20260907.md) et les [validations précédentes](docs/validation-results.md).

Cette branche ajoute les connecteurs facultatifs [ClamAV et signatures complémentaires](docs/antivirus.md), la comparaison de modèles Bayes et logistique, et un [client Scaleway avec budget local](docs/scaleway.md). Ils restent désactivés par défaut. Le [plan d'entraînement et de validation](docs/detection-roadmap.md) distingue ce qui est implémenté de ce qui reste à mesurer.

Logiciel open source sous [GPL-3.0-only](LICENSE), développé par CRDF Labs et les contributeurs NoiseFence. Dépôt : [crdffrance/NoiseFence](https://github.com/crdffrance/NoiseFence).

La [lecture OCR, QR codes et codes-barres](docs/vision.md) traite aussi les images
jointes ou intégrées et les PDF scannés, en français et en anglais, dans un worker
local isolé. Les résultats sont visibles dans la console ; `vision-inspect` permet
de lire les textes et les codes exacts d'un fichier `.eml` local.

La [console d’administration](docs/console.md) permet de gérer les domaines,
passerelles, filtres, comptes et livraisons. Les administrateurs voient tous les
messages de l’organisation ; les utilisateurs voient uniquement leurs accès.
Les réglages sont validés, versionnés et appliqués sans redémarrage.

## Démarrage local

Environnement validé : Rust 1.98, Node 24, Unix. Depuis la racine du projet :

```sh
cargo build --locked
cd web
npm ci
npm run build
cd ..
cargo run -- --config config/development.toml init
cargo run -- --config config/development.toml user-add alice --addresses alice@example.test
cargo run -- --config config/development.toml serve
```

Le mot de passe est saisi de manière interactive, sans argument de ligne de commande. La configuration de développement écoute uniquement sur `127.0.0.1:2525` (SMTP) et `127.0.0.1:18080` (API). Elle route les messages vers un serveur SMTP de test sur `127.0.0.1:2526` ; si ce serveur est absent, les messages restent en file.

Pour développer la console, lancer `npm run dev` dans `web` puis ouvrir l’URL locale affichée. Le proxy de développement transmet `/api` vers Rust. Pour consulter directement la version compilée sur le port 18080, utiliser une copie de la configuration avec `web.public_origin = "http://127.0.0.1:18080"`. L’origine doit correspondre exactement à l’URL du navigateur.

Le compte `alice` ne voit que les messages livrés à `alice@example.test`, y compris ceux reçus via l’alias `billing@example.test`. Créer un compte distinct pour Bob si nécessaire. Aucun compte ni mot de passe par défaut n’est intégré. Pour administrer tous les domaines, créer un compte avec `user-add administrateur --admin`.

Pour accepter `*@example.org` sans déclarer chaque boîte dans la passerelle,
activer `accept_all_recipients = true` dans ce domaine : chaque adresse est relayée
vers elle-même chez Proton. Les alias explicites restent prioritaires et les
droits de console peuvent être attribués par adresse ou par domaine. Voir la
[configuration de réception par domaine](docs/operations.md)
dans le guide d'exploitation.

## Architecture

| Module | Responsabilité |
|---|---|
| `smtp` | Machine à états SMTP, STARTTLS, réception en flux, limites et destinataires |
| `store` | Spool sur disque, SQLite WAL, transactions, reprise et droits par adresse |
| `relay` | SMTP sortant, validation TLS, tentatives par destinataire et notifications d’échec |
| `engine` | MIME, signaux, SPF/DKIM/DMARC/ARC, réputation, classification et marquage |
| `corpus` | Import, déduplication, entraînement, mesures et activation contrôlée des modèles |
| `antivirus` | Scans ClamD bornés sur deux sockets : antivirus officiel et signatures consultatives |
| `llm` | Extraits textuels facultatifs vers Scaleway, schéma JSON et budget durable |
| `api` / `web` | Comptes, historique, corrections et console statique |

Le service confirme `250` après synchronisation du fichier, de son répertoire et de la transaction SQLite. Les destinataires ont des états indépendants. Une réponse finale `250` de Proton marque la livraison réussie, même si la connexion échoue ensuite pendant QUIT. Si la réponse finale est perdue, SMTP peut produire un doublon : le service ne promet pas de livraison « exactement une fois ».

Les corps sont supprimés après résolution de tous les destinataires. Une livraison en échec définitif produit une notification à l’expéditeur d’enveloppe ; aucun retour n’est produit pour une enveloppe vide ou pour l’échec d’une notification. Le corps original n’est pas joint aux notifications. Une enveloppe usurpée peut néanmoins provoquer un retour vers un tiers : c’est une conséquence du stockage/relais SMTP, à mesurer pendant les essais.

Les métadonnées, caractéristiques et retours utilisateurs expirent après 30 jours. Les exports de corpus et sauvegardes sont des fichiers distincts dont l’exploitant doit gérer la conservation. Les caractéristiques hachées ne constituent pas une garantie d’anonymisation.

## Commandes utiles

```sh
noisefence --config /etc/noisefence/config.toml check-config
noisefence --config /etc/noisefence/config.toml queue
noisefence --config /etc/noisefence/config.toml retry MESSAGE_UUID
noisefence --config /etc/noisefence/config.toml user-disable alice
noisefence --config /etc/noisefence/config.toml user-reset-password alice
noisefence --config config/development.toml scan message.eml
```

`scan` effectue uniquement l'extraction et la classification locales, sans solliciter ClamAV, les signatures, le LLM ou l'authentification DNS. Les connecteurs configurés sont exécutés pendant une réception SMTP ou une préparation d’essai Proton. Un redémarrage charge les changements de configuration et de modèle.

La commande `analyze` exécute les connecteurs configurés une fois, sans mettre le
message en file ni l'envoyer. Une [adresse pilote](docs/proton-validation.md#adresse-pilote-sans-bascule-du-domaine-principal)
permet aussi de tester des envois réels et de voir les analyses dans la console
sans changer les MX du domaine principal. Le [protocole de recherche](research/README.md) décrit
les corpus, les caractéristiques natives Rust, l'entraînement des candidats et la
validation séparée. Les modèles de recherche ne sont pas activés automatiquement.

## Entraînement et mesure

```sh
python3 scripts/fetch_corpus.py corpus/apache
noisefence corpus-import --ham corpus/apache/ham --spam corpus/apache/spam --output corpus/apache.jsonl
mkdir -p models
noisefence train corpus/apache.jsonl --output models/candidate.json
noisefence train corpus/apache.jsonl --algorithm bernoulli-nb --output models/bayes.json
noisefence model-activate models/candidate.json --report models/candidate.json.report.json --destination models/active.json
```

L’import ignore les pièces jointes et les anciens en-têtes antispam. Le modèle est une régression logistique L2 sur mots/bigrammes et caractéristiques de structure hachés, avec pondération IDF ajustée uniquement sur l’entraînement. Les doublons normalisés sont regroupés avant une séparation déterministe 80/10/10. Cette séparation ne garantit pas que toutes les variantes d’une campagne ont été reconnues comme apparentées.

L'option Bernoulli Bayes constitue un candidat de comparaison sur présence des mêmes
caractéristiques, avec lissage de Laplace. Elle utilise un format de modèle distinct,
refusé par les anciens binaires. Sur le test historique, son rappel de 0,52 % est
inférieur aux 60,94 % de la régression logistique : aucun des deux n'est activé.

Le seuil est calibré sur les messages légitimes du jeu de validation, puis exprimé à l’indice de suspicion demandé (95 par défaut). Cet indice n’est pas une probabilité de spam calibrée. Le jeu de test n’intervient pas dans l’ajustement du seuil. Le rapport contient rappel, précision, faux positifs et intervalles de Wilson à 95 %. `model-activate` refuse les rapports qui ne satisfont pas les objectifs, notamment la borne supérieure des faux positifs. Le petit jeu public ne suffit généralement pas à établir un taux inférieur à 0,1 % avec confiance.

Le rapport du modèle textuel ne mesure pas toute la chaîne avec DNS, règles et comportement de Proton. Les corpus Apache datant principalement de 2002–2005 ne prouvent pas une efficacité sur le trafic actuel. Garder le mode observation, collecter des annotations représentatives, puis évaluer le pipeline complet sur des données récentes indépendantes avant de revendiquer 95 % de capture et 0,1 % de faux positifs.

Les utilisateurs corrigent leurs propres messages. Les retours contradictoires entre destinataires sont exclus de l’export. Les services `deploy/noisefence-train.*` préparent un candidat hebdomadaire ; ils ne l’activent pas. Un manque d’exemples des deux classes fait échouer l’entraînement explicitement. Le [pipeline de corrections du schéma 3](docs/feedback-training.md) conserve les vecteurs et leur protocole, puis prépare un candidat lexical ou hybride lié à son modèle lexical. Les corrections seules ne constituent pas une évaluation représentative.

## Validation et déploiement

Les [observations de chaque contrôle](docs/decision-evidence.md) distinguent les
résultats, erreurs et contrôles non exécutés, conservent les catégories de
réputation et identifient les modèles chargés. La [fusion native facultative](research/fusion.md) combine ces observations et
partage sa décision entre SMTP et console. Son activation demande des preuves
de qualité et de latence ; les objectifs restent à démontrer.

Voir [les essais Proton](docs/proton-validation.md), [l’installation Linux](docs/operations.md) et [le périmètre de sécurité](docs/security.md).

Les mesures et limites effectivement vérifiées figurent dans [le rapport de validation](docs/validation-results.md).
Le [banc de mesure du traitement complet](docs/performance.md) permet de comparer
les durées du modèle et des connecteurs sur des cas contrôlés, sans livraison SMTP.

```sh
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cd web
npx tsc --noEmit
npm run lint
npm run build
npm audit --audit-level=high
```

Les tests SMTP utilisent exclusivement des sockets loopback et des destinataires `.test`. Le fuzzing est fourni dans `fuzz`; une campagne guidée avec instrumentation peut être lancée via `cargo +nightly fuzz run message` et `cargo +nightly fuzz run smtp`. Les tests ne certifient pas la conformité exhaustive à tous les RFC ni la résistance à une charge de production.

Les [contrôles de cohérence SMTP/DNS](docs/smtp-policy.md) ajoutent HELO, PTR
confirmé et domaine d’enveloppe, avec poids plafonnés et observation initiale.
La commande `smtp-check` permet de les essayer sans envoyer d’email.
