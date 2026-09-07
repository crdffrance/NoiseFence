# NoiseFence : expériences de détection

Le modèle est appris sur des emails étiquetés ; ajouter une règle pour chaque
exemple reçu ne remplace pas cet apprentissage. Le cas privé fourni pendant la
R&D est une régression connue, exclue des jeux d'entraînement et des métriques
de test indépendant. Il reste privé et ne doit pas être publié avec le code.

## Protocole

1. Archiver les sources, dates, licences et empreintes des corpus publics. Ne
   jamais visiter leurs liens, charger leurs images ou exécuter leurs pièces jointes.
2. Extraire le texte visible, les mots et caractères, ainsi que la structure MIME
   et les relations entre identités et liens. Exclure les scores des anciens
   filtres, dossiers, chemins de corpus, destinataires et dates de transport.
3. Regrouper les doublons et variantes proches avant toute partition. Retirer les
   conflits d'étiquettes ; conserver un audit des exclusions. Isoler les campagnes
   récentes et les sources externes pour mesurer la généralisation.
4. Séparer entraînement, sélection des hyperparamètres, calibration du seuil et
   test final. Les résultats du test ne sélectionnent ni le modèle ni le seuil.
5. Comparer la logistique régularisée, Bayes et les modèles linéaires avec rapports
   de vraisemblance bayésiens ; comparer mots, caractères et structure par ablation.
   Étudier un encodeur local multilingue si ces modèles restent insuffisants.
6. Exporter des poids versionnés utilisables en Rust, puis vérifier l'égalité des
   prédictions entre entraînement et exécution. Mesurer mémoire et latence réelles.
7. Évaluer séparément la décision complète : authentification, réputation,
   signatures, modèle local, sélection LLM et combinaison. Ne pas présenter une
   évaluation du texte seul comme une validation de toute la passerelle.

Publier rappel, précision, faux positifs, intervalles de Wilson, PR-AUC, effectifs
et résultats par source. La cible demeure rappel ≥ 95 % et faux positifs ≤ 0,1 %
sur des emails récents représentatifs ; une petite série sans erreur ne prouve
pas cette cible. L'activation reste conditionnée à une validation indépendante.

## Sources initiales

- [Apache SpamAssassin](https://spamassassin.apache.org/old/publiccorpus/) :
  démarrage historique, pas une preuve de performances sur 2026.
- [Nazario](https://monkey.org/~jose/phishing/), années 2015 à 2025 : phishing
  réel, classé manuellement par Jose Nazario ; CC BY 4.0 selon son
  [README](https://monkey.org/~jose/phishing/README.txt). Une seule boîte source,
  erreurs de classement possibles. Les dates d'archives ne garantissent pas les
  dates déclarées dans chaque email. Année 2025 réservée au test externe initial.
- [Enron-Spam](https://www2.aueb.gr/users/ion/data/enron-spam/) : échanges et spam
  historiques, à distinguer des courriels professionnels récents.
- [E-PhishGen, AISec 2025](https://arxiv.org/abs/2509.01791) : souligne les limites
  de généralisation des benchmarks historiques ; corpus généré à distinguer des
  emails réels, et licence à vérifier avant toute redistribution ou incorporation.

Les données et modèles de travail restent dans `corpus/`, `models/` et `reports/`,
exclus de Git. Publier le code, les manifestes et les mesures ; ne pas publier les
emails privés. Les téléchargements de recherche ne modifient pas la production.

## Reproduire l'expérience linéaire

Les empreintes des téléchargements Nazario et Enron sont dans `sources.lock.json`.
L'extraction est exécutée par le même code Rust que l'inférence. Python est utilisé
pour l'optimisation et les statistiques, pas comme service de production.

```sh
python3 -m pip install -r research/requirements.txt
python3 scripts/fetch_corpus.py corpus/apache
python3 scripts/research_fetch.py corpus/research/nazario
python3 scripts/research_fetch.py corpus/research/enron --enron
python3 research/prepare_corpus.py corpus
cargo build --release --locked
```

Pour chaque schéma (1 puis 3), exporter les caractéristiques et regrouper les
campagnes avant l'entraînement. Utiliser 16 384 dimensions pour le schéma 1 et
262 144 pour le schéma 3. Chaque sortie d'entraînement doit être un dossier neuf.

```sh
target/release/noisefence features-export \
  --manifest corpus/research/prepared/manifest.jsonl --root corpus \
  --output corpus/research/features-v3.raw.jsonl --feature-version 3
python3 research/group_campaigns.py corpus/research/features-v3.raw.jsonl \
  corpus/research/features-v3.grouped.jsonl
OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 python3 research/train_linear.py \
  corpus/research/features-v3.grouped.jsonl models/research-mixed-v3-dev \
  --dimension 262144 --feature-version 3 --development-only
```

Après les deux sélections de développement, figer le choix avant d'ouvrir les
métriques de calibration et de test :

```sh
python3 research/finalize_linear.py models/research-mixed-final \
  models/research-mixed-v1-dev models/research-mixed-v3-dev
```

`selection-frozen.json` enregistre le choix avant l'évaluation finale. Les poids
ne sont pas un pickle exécutable. La transformation IDF est ajustée exclusivement
sur l'entraînement. Le score exporté est un indice dont le seuil est 95/100,
pas une probabilité calibrée de spam. Les observations locales déjà apprises par
le schéma 3 ne sont pas ajoutées une seconde fois comme poids manuels.

Le regroupement utilise un texte canonique et une distance SimHash ≤ 3, avec
une seule représentation par groupe. Toute composante touchant le test externe
est exclue de l'apprentissage. Cette méthode n'assure pas de trouver toutes les
campagnes : elle réduit les fuites, sans constituer une preuve d'indépendance parfaite.

## Analyser un email sans l'envoyer

```sh
noisefence --config config/local.toml analyze message.eml \
  --source-ip IP_DE_L_EMETTEUR --helo HOTE_EMETTEUR \
  --mail-from EXPEDITEUR_DE_TEST --output reports/analysis.json
```

Cette commande utilise les connecteurs configurés, peut faire des requêtes DNS
et Scaleway, et consomme le budget LLM partagé si ce connecteur est sollicité.
Elle n'enregistre aucun message dans la file et ne le livre à aucun destinataire.
Utiliser une configuration de recherche privée pour les modèles candidats.

## Comparer un encodeur multilingue local

L'expérience optionnelle utilise [multilingual-e5-small](https://huggingface.co/intfloat/multilingual-e5-small),
publié sous licence MIT. La révision et les empreintes des fichiers sont épinglées
dans `encoder.lock.json`. Seuls poids Safetensors, tokenizer et configuration sont
chargés ; aucun code provenant du dépôt du modèle n'est exécuté. Le modèle
préentraîné reste figé. Une tête logistique est apprise sur les emails, puis
comparée au modèle lexical et à leur combinaison sur le développement uniquement.
Un encodeur préentraîné ne constitue pas un moteur SMTP développé de zéro :
c'est une dépendance optionnelle étudiée, distincte du moteur Rust natif.

```sh
python3 -m venv var/research-venv
var/research-venv/bin/python -m pip install -r research/semantic-requirements.txt
python3 research/fetch_encoder.py models/encoders/multilingual-e5-small
python3 research/prepare_semantic.py corpus/research/features-v3.grouped.jsonl \
  corpus/research/prepared/manifest.jsonl corpus/research/semantic
cargo build --release --locked --example research_text
target/release/examples/research_text corpus/research/semantic/manifest.jsonl \
  corpus corpus/research/semantic/texts.jsonl
HF_HUB_OFFLINE=1 TOKENIZERS_PARALLELISM=false var/research-venv/bin/python \
  research/encode_local.py corpus/research/semantic/texts.jsonl \
  models/research-e5-dev-256 --encoder models/encoders/multilingual-e5-small \
  --device cpu --max-tokens 256
var/research-venv/bin/python research/train_semantic.py \
  models/research-e5-dev-256 corpus/research/semantic/rows.jsonl \
  models/research-mixed-final/predictions.jsonl models/research-e5-comparison
```

Sur un Mac compatible, `--device mps` utilise le GPU local. Le texte est extrait
par le même module Rust que le modèle lexical. Aucun email n'est transmis au
fournisseur du modèle. Les séquences sont limitées à 256 tokens dans l'expérience
initiale : une fin de message longue peut être perdue. Les jeux de test déjà
observés ne sont pas réutilisés pour choisir la combinaison. Un résultat de
développement ne valide ni l'inférence Rust de cet encodeur, ni ses performances
en production, ni une cible multilingue. Un recouvrement inconnu avec les données
de préentraînement reste possible.

Pour mesurer la combinaison sélectionnée sur les références historiques déjà
examinées, figer d'abord le choix. Ces mesures doivent être signalées comme des
références de R&D réutilisées, et non comme une nouvelle validation indépendante.

```sh
var/research-venv/bin/python research/freeze_semantic.py \
  models/research-e5-comparison models/research-mixed-v3-dev/raw-model.json \
  models/research-e5-dev-256
python3 research/prepare_semantic.py corpus/research/features-v3.grouped.jsonl \
  corpus/research/prepared/manifest.jsonl corpus/research/semantic-evaluation \
  --evaluation-only
target/release/examples/research_text corpus/research/semantic-evaluation/manifest.jsonl \
  corpus corpus/research/semantic-evaluation/texts.jsonl
HF_HUB_OFFLINE=1 TOKENIZERS_PARALLELISM=false var/research-venv/bin/python \
  research/encode_local.py corpus/research/semantic-evaluation/texts.jsonl \
  models/research-e5-evaluation-256 --encoder models/encoders/multilingual-e5-small \
  --device cpu --max-tokens 256
var/research-venv/bin/python research/finalize_semantic.py \
  models/research-e5-comparison models/research-e5-evaluation-256 \
  corpus/research/semantic-evaluation/rows.jsonl \
  models/research-mixed-final/predictions.jsonl models/research-e5-reference
```

Le seuil est ajusté uniquement sur les légitimes de calibration. Le fichier
`combination.json` décrit une référence Python ; il n'est pas un modèle compatible
avec la commande d'activation Rust. Les scripts n'activent rien en production.

## Exécuter la combinaison en Rust

Le portage optionnel utilise Candle sur CPU et des fichiers locaux épinglés.
Exporter le manifeste lié au modèle lexical calibré, puis compiler :

```sh
var/research-venv/bin/python research/export_native_hybrid.py \
  models/research-e5-reference/combination.json \
  models/research-mixed-v3-dev/raw-model.json \
  models/research-mixed-final/model.json \
  models/research-e5-reference/native-combination.json
cargo build --release --locked --features semantic
```

Dans une copie privée de la configuration de recherche, conserver le modèle
lexical calibré dans `filter.model` et ajouter :

```toml
[filter.semantic]
encoder_dir = "models/encoders/multilingual-e5-small"
combination = "models/research-e5-reference/native-combination.json"
max_parallel = 1
timeout_ms = 500
```

Les chemins sont relatifs au répertoire courant. Pour un service, utiliser des
chemins absolus et définir `RAYON_NUM_THREADS=4`, `CANDLE_NUM_THREADS=4`,
`TOKENIZERS_PARALLELISM=false` dans son environnement. La configuration et les
fichiers doivent correspondre à la même expérience ; les empreintes, révision,
schéma et seuil sont vérifiés. Sans l'option de compilation, une configuration
sémantique provoque une erreur explicite au démarrage.

L'inférence SMTP utilise un travailleur bloquant borné. Le délai n'interrompt pas
le calcul CPU déjà lancé : son créneau reste réservé jusqu'à sa fin. En cas
d'occupation ou d'échec, le score lexical calibré est conservé et le message est
traité comme une analyse incomplète, sans préfixe. `scan` reste une commande
synchrone hors ligne ; `analyze` utilise le chemin asynchrone sans livraison.

Pour mesurer les deux modèles avec les mêmes extractions que l'inférence :

```sh
RAYON_NUM_THREADS=4 CANDLE_NUM_THREADS=4 TOKENIZERS_PARALLELISM=false \
  target/release/noisefence model-benchmark message.eml \
  --model models/research-mixed-final/model.json \
  --semantic-combination models/research-e5-reference/native-combination.json \
  --encoder models/encoders/multilingual-e5-small --iterations 100
```

Le modèle n'est pas chargé pendant les itérations chronométrées. Les mesures
excluent DNS, scanners, LLM et file. [Résultats natifs](native-hybrid-validation-20260907.json).
Les vecteurs de l'encodeur restent des caractéristiques sensibles soumises à la
conservation de 30 jours ; ils ne sont pas envoyés dans la réponse de la console.
L'export du manifeste et les tests locaux ne constituent pas une approbation de
la qualité ni une activation en production.

Pour mesurer également DNS, scanners et LLM, utiliser le
[banc du traitement complet](../docs/performance.md). Le
[rapport de latence du 7 septembre 2026](pipeline-latency-20260907.json)
compare trois profils sur quatre messages synthétiques. Il documente aussi
les appels LLM évités et les limites de ces mesures, sans en déduire la qualité
sur le trafic réel.
