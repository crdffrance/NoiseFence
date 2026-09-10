# Entraîner le composant textuel avec un export Enron

L'import accepte une archive ZIP contenant uniquement `enron_spam_data.csv`, avec
les colonnes `Message ID`, `Subject`, `Message`, `Spam/Ham`, `Date`. Il prépare un
candidat local compatible avec les caractéristiques Rust de schéma 3. Il ne
change pas le modèle actif, le moteur sémantique, les règles ni les actions SMTP.

Utiliser Python 3.11 ou 3.12 avec `research/requirements.txt`. Les corpus, poids et
prédictions restent privés dans les répertoires ignorés par Git. La réception d'un
fichier ne suffit pas à établir ses droits de redistribution. Aucun téléchargement,
visite de lien, chargement d'image distante ou envoi d'email n'est nécessaire.

## Import et recouvrements

```sh
umask 077
python research/import_enron_csv.py enron_spam_data.zip corpus/private/enron-import
cargo build --release --locked --bin noisefence --example corpus_keys
target/release/noisefence features-export \
  --manifest corpus/private/enron-import/manifest.jsonl --root corpus/private/enron-import \
  --output corpus/private/enron-import/features.raw.jsonl --feature-version 3
target/release/examples/corpus_keys corpus/private/enron-import/manifest.jsonl \
  corpus/private/enron-import corpus/private/enron-import/token-keys.jsonl
target/release/examples/corpus_keys corpus/research/prepared/manifest.jsonl \
  corpus corpus/private/historical.token-keys.jsonl
python research/merge_corpus.py corpus/private/enron-import/features.raw.jsonl \
  corpus/research/features-v3.grouped.jsonl corpus/private/enron-merged \
  --reference corpus/research/features-v3.raw.jsonl \
  --token-keys corpus/private/historical.token-keys.jsonl \
  --token-keys corpus/private/enron-import/token-keys.jsonl
```

Ajouter un argument `--reference` pour chaque autre corpus déjà utilisé ou réservé,
y compris les diagnostics privés. L'expérience du 10 septembre inclut les
diagnostics Zenodo, les exemples fournis précédemment et les lots synthétiques
français d'entraînement, de calibration et de test.

Seuls l'objet et le corps alimentent le MIME reconstruit. Les dates, identifiants,
labels et chemins ne deviennent pas des caractéristiques. Les en-têtes de
transport absents ne sont pas inventés. L'import retire les NUL, normalise les
fins de ligne et déplie l'objet ; il conserve les accents. Un doublon portant des
labels contradictoires est entièrement exclu, sans choisir la première étiquette.

Le regroupement utilise l'identité SHA, le texte canonique et SimHash, complétés
par des clés de mots insensibles à l'espacement de la ponctuation. Cette dernière
étape est nécessaire lorsque le CSV reformate un ancien email. Toute composante
reliée à une référence est exclue des ajouts, même par une chaîne de similarités.
Les groupes aux labels contradictoires sont écartés ; un seul représentant est
retenu dans chaque autre groupe. Les nouvelles clés servent uniquement à la
déduplication, jamais au score. Cette heuristique ne garantit pas de reconnaître
toutes les variantes d'une campagne.

Les lignes et partitions du corpus historique sont conservées à l'identique.
Les campagnes nouvelles suivent le hachage 60 % entraînement, 10 % développement,
10 % calibration, 20 % test. Les anciens tests restent des références déjà
consultées ; ils ne deviennent pas de nouveaux tests indépendants.

## Ajuster puis vérifier

Figer le protocole, les empreintes et la grille avant l'ajustement. L'expérience
compare TF-IDF logistique et logistique avec ratios bayésiens, chacune avec
`C=0.1,1,10,100`. L'IDF et les coefficients utilisent uniquement l'entraînement.
Le développement sélectionne le candidat au budget empirique de faux positifs
de 0,1 %. Le seuil final utilise les légitimes de calibration uniquement.

```sh
OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 PYTHONWARNINGS=error \
python research/train_linear.py corpus/private/enron-merged/features.jsonl \
  models/enron-development --dimension 262144 --feature-version 3 --development-only
python research/finalize_linear.py models/enron-candidate models/enron-development
python research/compare_lexical.py models/enron-candidate models/current-lexical/model.json
python research/verify_rust.py models/enron-candidate --binary target/release/noisefence \
  --corpus corpus --manifest corpus/private/combined.manifest.jsonl
```

Pour la vérification Rust, construire le manifeste combiné avec les chemins des
deux imports, relatifs à `--corpus`. Ne pas modifier les manifests historiques.
`comparison.json` compare les deux modèles textuels sur les mêmes messages et
avec leur seuil figé. Le rapport de test ne doit pas servir à régler un nouveau
seuil ou sélectionner une autre variante. Conserver les intervalles de confiance
et les résultats par source, y compris lorsque le candidat régresse.

Le candidat reste `eligible: false`. Les échanges Enron de 1999–2005 ne démontrent
pas la qualité sur le trafic actuel en français. Les labels binaires ne permettent
pas d'apprendre séparément le consentement aux publicités ou le phishing. La
comparaison ne mesure pas les autres contrôles de la passerelle. Une combinaison
E5 est liée au SHA exact de son modèle lexical : remplacer uniquement ce dernier
invaliderait cette liaison. Toute activation demande une qualification du modèle
complet sur des emails récents indépendants et représentatifs.

Le [bilan du 10 septembre 2026](enron-training-20260910.md) décrit l’entraînement
effectué sur l’archive fournie et les régressions qui empêchent son activation.
