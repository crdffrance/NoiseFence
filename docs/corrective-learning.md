# Apprendre des erreurs sans masquer les régressions

Le score historique peut être élevé sur des messages légitimes dont le style
diffère du corpus d’entraînement. Ajouter des règles ou remonter un seuil peut
réduire simultanément les faux positifs et la capture. `research/adapt_feedback.py`
permet de tester une correction des poids, avec des mesures explicites de ce
compromis. Il ne modifie ni configuration, ni message, ni décision active.

## Calcul

Le modèle lexical schéma 3, son IDF et son biais constituent la référence figée.
La tête sémantique reste identique lorsqu’elle est fournie ; son empreinte doit
correspondre exactement à celle du modèle. La correction apprend une régression
logistique régularisée dans l’espace couvert par les caractéristiques des
messages corrigés. La perte équilibre les deux classes et ajoute un corpus
de rappel. L’interception, l’extraction et le seuil 95 restent fixes.

Les coefficients correctifs sont ajoutés aux poids lexicaux existants. Le moteur
Rust charge le même format JSON et effectue le même produit scalaire : aucune
nouvelle inférence d’encodeur, requête externe ou recherche de voisin ne s’ajoute
au traitement SMTP. Cela ne valide pas à lui seul les performances du candidat.

Le paramètre `--regularization` vaut 1 par défaut et `--replay-weight` vaut 1.
La perte humaine est une somme équilibrée ; le poids total du rappel correspond
au nombre de campagnes humaines, multiplié par `replay-weight`. Fixer ces
paramètres avant l’évaluation. Les modifier après examen des résultats transforme
les lots concernés en données de développement ; une nouvelle validation reste
nécessaire.

## Entrées et confidentialité

Utiliser [l’export des corrections](feedback-training.md) sur le serveur. Les
droits des annotateurs, la rétention, les conflits et la complétude des
caractéristiques sont vérifiés par l’exporteur. Le programme n’ouvre aucune boîte,
pièce jointe ou URL. Les vecteurs et les poids appris avec eux restent privés.

```sh
noisefence --config /etc/noisefence/config.toml export-learning \
  /run/noisefence-learning/feedback.jsonl --require-semantic

OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 /opt/noisefence-learning/bin/python \
  research/adapt_feedback.py /run/noisefence-learning/feedback.jsonl \
  replay.jsonl.gz reference/model.json candidat-correctif \
  --semantic-head reference/native-combination.json
```

Le corpus de rappel JSONL, éventuellement gzip, possède une ligne par campagne :

```json
{
  "schema": "noisefence-content-replay-1",
  "feature_version": 3,
  "id": "<SHA-256 du message brut>",
  "fingerprint": "<SHA-256 du texte canonique>",
  "group": "<SHA-256 de la campagne>",
  "simhash": "<16 caractères hexadécimaux>",
  "spam": false,
  "partition": "train",
  "stratum": "historical",
  "external_test": false,
  "features": [[123, 1.0]]
}
```

`partition` accepte `train` et `control`. Le hachage de groupe doit correspondre
aux partitions figées de `train_linear.py` ; les groupes de test ou externes
ne peuvent pas être déclarés d’entraînement. Un contrôle utilise un groupe de
test ou externe. `stratum` accepte `historical`, `french_synthetic`, `external`.
Les deux classes sont nécessaires dans l’entraînement et dans le contrôle.
L’exemple ci-dessus illustre le format ; il ne constitue pas une entrée valide
avec ses empreintes remplacées par des libellés.

Les vecteurs doivent provenir de l’extraction Rust, rester normalisés et respecter
les bornes du schéma. Un doublon de campagne est refusé. Un rappel proche d’un
membre des corrections humaines est exclu, même si ce membre appartient à une
campagne supprimée pour conflit. Les limites portent sur 256 campagnes humaines,
20 000 lignes de rappel, 1 Gio décompressé et 40 millions de valeurs. Préparer
et dédupliquer les sources avant la sélection ; la distance SimHash ne prouve
pas l’indépendance de toutes les variantes.

## Mesure et refus d’activation

Chaque campagne humaine est d’abord prédite par un correcteur entraîné sans
cette campagne. La validation temporelle utilise les 30 % de campagnes les plus
récentes : aucun membre d’une campagne ni annotation d’entraînement ne peut
dépasser la date de coupure. Les campagnes traversant cette coupure et les
annotations tardives sont comptées parmi les exclusions. Un manque de classes
antérieures donne un résultat indisponible, jamais un succès.

Le candidat final apprend ensuite toutes les campagnes retenues. Les contrôles
de rappel restent exclus du calcul des poids. Ils comparent le lexical seul,
par strate ; la comparaison des corrections utilise également la tête sémantique
figée lorsqu’elle est disponible. Ces contrôles ne rejouent pas le pipeline
SMTP, les appels LLM ni les fournisseurs conditionnés par le score.

`report.json` contient les effectifs, rappel, précision, faux positifs et leurs
intervalles de Wilson, les exclusions, les paramètres et les empreintes d’entrée.
Les comptes de messages doivent accompagner les taux ; une correction signalée
par l’utilisateur ne représente pas un tirage uniforme du trafic.

La porte de développement refuse une perte de capture ou davantage de faux
positifs sur un contrôle, ainsi que l’absence de progrès hors campagne ou de
contrôle temporel. Même en l’absence de ces régressions, le résultat reste
`needs_independent_validation`, `may_activate: false`, `eligible: false`.
Un seuil atteint sur quelques corrections ne démontre pas 0,1 % de faux positifs
sur le trafic réel. Les corpus déjà examinés servent de références de régression.

Le dossier privé contient les poids JSON, la tête liée à leur nouvelle empreinte
et le rapport, y compris pour un candidat rejeté. Il est créé atomiquement et ne
peut pas remplacer un dossier existant. Aucun détail par message n’est écrit.
Supprimer l’export de travail après les vérifications ; conserver les données
sources uniquement selon la durée de rétention autorisée.

## Vérification

`tests_python/test_feedback_adaptation.py` couvre la direction de la correction,
le rappel, la séparation des campagnes, les annotations tardives, les entrées
invalides, le refus des régressions et la conservation des paramètres figés.
La CI compare aussi les prédictions au programme Rust `feedback_probe`, avec des
données synthétiques. Aucun email ou poids privé n’est distribué avec le projet.
