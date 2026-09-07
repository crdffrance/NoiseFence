# Comparer un apport de données sans masquer les régressions

`adapt_content.py` compare des modèles lexicaux et sémantiques sur des partitions
d’entraînement et de développement déjà figées. Il produit un candidat privé et
un rapport. Il ne lit pas de jeu de calibration/test, ne change aucun modèle actif
et ne publie aucun poids. Les droits d’usage des corpus restent applicables aux
artefacts produits.

## Entrées

Installer les versions de `research/requirements.txt` dans un environnement local.
Le calcul ne demande ni accès réseau ni appel LLM.

Le fichier de caractéristiques JSONL utilise le schéma 3 de `features-export`,
après regroupement des campagnes. Chaque ligne conserve `fingerprint`, `group`,
`raw_sha256`, `spam`, `features`, `feature_version` et ajoute :

- `partition` : `train` ou `development`, cohérente avec le hachage du groupe ;
- `stratum` : nom du sous-ensemble d’évaluation, par exemple `historical` et
  `french_synthetic`.

Toutes les campagnes externes, de calibration et de test doivent être absentes du
fichier. Le programme les refuse même si leur partition déclarée est falsifiée.
Chaque groupe doit avoir un seul représentant. Vérifier les doublons et variantes
proches entre **toutes** les sources et partitions avant de préparer le fichier ;
le contrôle d’identité du lecteur ne remplace pas cet audit de similarité.

Le répertoire d’embeddings contient `embeddings.npy` (float32, vecteurs normalisés),
`ids.json` (empreintes brutes dans l’ordre des vecteurs) et `protocol.json`. Ce
dernier reprend exactement `semantic-protocol.json` et ajoute `complete: true`,
`embeddings_sha256` et `ids_sha256`. Les identités doivent correspondre exactement
au fichier de caractéristiques. Ne pas charger un cache de test dans cet outil.

Les noms des sources, labels et partitions servent à l’organisation de l’expérience
et à la pondération de l’entraînement ; ils ne sont pas des caractéristiques du
détecteur. Chaque strate doit comporter les deux classes en entraînement et en
développement.

Exemple de grille, à fixer avant les essais :

```json
{
  "augmentation_strata": ["french_synthetic"],
  "sample_weights": [1, 5, 20],
  "lexical_C": [10, 100],
  "semantic_C": [1, 10],
  "semantic_weights": [0, 0.1, 0.5, 1, 2, 4],
  "lexical_families": ["tfidf_logistic", "nb_logistic"],
  "target_fpr": 0.001
}
```

```sh
OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 \
python3 research/adapt_content.py \
  corpus/private/train-development.features.jsonl \
  corpus/private/train-development.embeddings \
  corpus/private/grid.json \
  models/reference/model.json models/reference/native-combination.json \
  models/private-content-candidate
```

Le dossier de sortie doit être nouveau. Les fichiers et répertoires créés sont
privés (`umask 077`). Les caractéristiques, poids et prédictions restent dans les
emplacements ignorés par Git.

## Choix et limites

L’IDF apprend sur les messages uniques d’entraînement uniquement. La pondération
de l’apport s’applique à la fonction d’apprentissage et aux fréquences bayésiennes,
sans dupliquer les messages ni modifier les effectifs d’évaluation. Un échec de
convergence interrompt l’expérience.

Chaque combinaison utilise un seul seuil de développement : le plus restrictif
des seuils nécessaires pour respecter le budget empirique de faux positifs dans
chaque strate. Le choix maximise le plus faible rappel parmi les strates, puis le
rappel moyen et la PR-AUC moyenne. Cela empêche une grande source de masquer les
erreurs d’une petite source ; cela ne prouve pas la généralisation sur de futurs
messages. Les intervalles et effectifs restent indispensables.

Le modèle sémantique seul figure comme ablation. Le candidat exporté respecte le
contrat natif actuel : logit lexical + contribution sémantique. Les contributions
SMTP, authentification, réputation, signatures et LLM nécessitent une expérience
de combinaison distincte avec leur contexte de réception fiable.

Les sorties comprennent `specification.json`, `development.json`, les prédictions
de développement, `raw-model.json` et `raw-head.json`. Le seuil n’est pas calibré
dans ces poids bruts. Ne pas les installer directement en production. Figer la
sélection, calibrer le seuil sur un lot réservé, puis mesurer une seule fois le
test indépendant et vérifier les prédictions Rust avant toute activation. Un
score obtenu en déplaçant le biais pour correspondre au seuil 95 reste un indice
de suspicion, pas une probabilité calibrée.

Le [protocole de validation](labeling-protocol.md) précise les exigences pour les
données récentes, les probabilités, les régressions, la latence et Proton.
