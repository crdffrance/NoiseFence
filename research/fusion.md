# Fusion apprise des observations

NoiseFence peut entraîner puis évaluer hors ligne une décision commune à partir
des observations des détecteurs. Cette chaîne produit des modèles de recherche
JSON exécutables nativement en Rust. Elle ne remplace pas encore le score du
service et ne déclenche aucune activation. Un candidat nécessite ensuite un test
récent représentatif, l'audit de ses données, la mesure du traitement complet et
la validation de livraison chez Proton.

## Entrées communes

Le [protocole versionné](fusion-protocol.json) fixe 218 caractéristiques et leurs
bornes. Son empreinte porte sur les octets exacts du fichier ; Rust embarque ces
mêmes octets. L'extraction utilise exclusivement les observations typées de
`noisefence-evidence-1` : logits locaux bornés, authentification et alignements,
catégories et rôles DQS, cohérence SMTP, catégories des scanners et avis LLM.
Chaque contrôle conserve son état, y compris absence, indisponibilité et
saturation. Les valeurs déclarées par le LLM sont des caractéristiques, pas des
étiquettes ni des probabilités déjà calibrées.

Le score historique, les poids manuels, le score qui sélectionne les appels LLM,
les labels, les textes d'explication, les identités et les durées sont exclus du
vecteur. Le score historique reste disponible uniquement pour la comparaison de
référence. Les codes DQS d'erreur sont refusés ; les catégories de domaines
légitimes compromis ne deviennent pas des caractéristiques d'identité suspecte.

Les artefacts identifient les modèles réellement chargés, la version applicative,
le verrou de dépendances, le protocole sémantique, les paramètres des contrôles
et le prompt. Un export mélangeant plusieurs configurations est refusé. Une
prédiction exige le même ensemble d'artefacts ; un changement de configuration
ou de version doit faire l'objet d'une nouvelle expérience. Les empreintes
exactes des définitions chargées par ClamD et la révision cloud du LLM restent
inconnues lorsqu'elles ne sont pas attestées par les fournisseurs.

## Préparer un jeu privé

Après annotation autorisée dans la console, exporter les données :

```sh
noisefence --config /etc/noisefence/config.toml export-learning /chemin/prive/learning.jsonl
noisefence fusion-export /chemin/prive/learning.jsonl --output /chemin/prive/vectors.jsonl
```

La seconde commande est entièrement hors ligne et ne charge pas la configuration
du serveur. Elle conserve seulement le contexte provenant de la réception SMTP.
Les analyses avec une enveloppe fournie manuellement et les anciens messages sans
observations sont omis avec des compteurs explicites. Un export sans observation
SMTP exploitable échoue. Les contrôles incomplets restent présents : on ne doit
pas améliorer artificiellement les résultats en les retirant.

Les fichiers sont créés atomiquement avec des droits `0600`, sans écraser un
export existant. Ils restent sensibles même sans corps et doivent suivre la
conservation de 30 jours. Les corrections seules ne représentent pas le trafic :
annoter aussi un échantillon défini à l'avance de messages correctement classés.
Conserver la méthode de tirage et l'autorisation d'usage dans le manifeste.

Préparer `annotations.jsonl`, une ligne par observation exportée :

```json
{"id":"<64 caractères hexadécimaux>","campaign":"<empreinte de campagne>","label":"legit","split":"train","language":"fr","kind":"invoice"}
```

Les labels suivent le [protocole d'étiquetage](labeling-protocol.md) : `legit`,
`spam`, `phishing`, `uncertain`. Conserver `unwanted_binary` si un ancien retour
« Spam » n'a pas été revu en sous-classe. Une annotation certaine doit rester
cohérente avec le retour humain exporté. Les labels incertains sont exclus de
l'ajustement et des métriques avec leur nombre publié.

Attribuer les campagnes à cinq lots **avant** l'expérience : `train`,
`development`, `calibration`, `threshold`, `test`. Le contrôle regroupe
transitivement les empreintes identiques, les campagnes déclarées et les SimHash
à distance au plus trois. Tout groupe traversant deux lots ou l'historique des
modèles de base fait échouer l'expérience. Les labels binaires contradictoires
échouent également. Un représentant déterministe par campagne est conservé :
les métriques portent sur ces représentants, pas sur un taux pondéré par le
volume de copies. Ce regroupement reste une heuristique à compléter par l'audit.

Préparer `base-history.json` avec les empreintes des campagnes déjà utilisées
pour les modèles lexicaux et sémantiques concernés. Inclure aussi les lots de
développement, calibration, seuil et tests déjà consultés pour choisir ces
modèles. Il s'agit de choisir un lot de fusion distinct, pas de réutiliser les
prédictions d'entraînement des mêmes moteurs :

```json
{
  "schema": "noisefence-base-history-1",
  "lexical_model_sha256": "<empreinte du modèle chargé>",
  "semantic_model_sha256": null,
  "complete_for": ["fit", "development", "calibration", "threshold", "previous_tests"],
  "rows": [{"fingerprint":"<empreinte>","simhash":"<16 caractères hexadécimaux>","campaign":"<empreinte>"}]
}
```

Utiliser `null` pour un modèle absent. Un modèle chargé interdit un historique
vide. L'exhaustivité de cet historique doit être vérifiée ; le logiciel peut
détecter un chevauchement déclaré, pas prouver l'absence d'une campagne omise ni
auditer le préentraînement fondamental d'un encodeur tiers.

Le manifeste `experiment.json` lie les fichiers par SHA-256 :

```json
{
  "schema": "noisefence-fusion-experiment-1",
  "version": "fusion-research-20260907",
  "purpose": "research",
  "protocol_sha256": "<SHA-256 des octets de fusion-protocol.json>",
  "vectors": {"path":"vectors.jsonl","sha256":"<empreinte>"},
  "annotations": {"path":"annotations.jsonl","sha256":"<empreinte>"},
  "base_history": {"path":"base-history.json","sha256":"<empreinte>"},
  "sampling": {
    "kind": "representative",
    "description": "<méthode réelle de tirage et périmètre>",
    "authorization": "<référence à l'autorisation d'usage>",
    "start_at": 1788739200,
    "end_at": 1788825599
  }
}
```

Les chemins sont relatifs au manifeste, ou absolus. Les dates Unix bornent les
dates de réception fiables exportées. Utiliser `corrections` ou `synthetic` pour
ces sources respectives ; une déclaration `representative` reste à auditer.
Les exports sont bornés à 50 000 observations et 512 Mio. Chaque lot doit garder
les deux classes après regroupement.

## Entraînement, calibration, seuil et test

Installer les dépendances verrouillées dans un environnement Python isolé :

```sh
python3 -m venv /chemin/prive/fusion-venv
/chemin/prive/fusion-venv/bin/pip install -r research/requirements.txt
/chemin/prive/fusion-venv/bin/python research/train_fusion.py fit experiment.json /chemin/prive/candidate
```

L'entraîneur ajuste une normalisation sur `train`, puis une régression logistique
L2 pour `C ∈ {0,1 ; 1 ; 10}`. Il choisit C sur `development`, sous la contrainte
de faux positifs de 0,1 %, sans classe de priorité fondée sur la langue. Il replie
la normalisation dans les poids et le biais pour l'inférence Rust.

Une calibration sigmoïde monotone est ajustée sur `calibration`. La proportion
d'indésirables de ce lot est enregistrée : la probabilité résultante concerne ce
mélange et les disponibilités observées. Le seuil de logit est ensuite choisi sur
`threshold`, avec un seul seuil pour tous les messages. Les ex æquo restent
indivisibles, et une marge numérique sépare les groupes retenus. La contrainte
de sélection est empirique ; le test final publie aussi l'incertitude statistique.

Les cinq variantes sont figées avant le test : contenu, contenu + identité,
ajout de réputation, ajout des scanners, ensemble avec LLM. Ces ablations
retirent des familles de caractéristiques sur les mêmes observations ; elles ne
simulent pas le coût ni les effets d'un nouveau routage des connecteurs. En
particulier, l'avis LLM dépend encore de la politique d'appel historique.

Le modèle conserve les profils de disponibilité présents à la fois en
entraînement et en calibration. Un profil inconnu ne peut pas déclencher le
préfixe. Une analyse incomplète, un contrôle requis indisponible ou une chaîne ARC
impossible à prolonger l'empêchent aussi, même avec un logit élevé. Ces cas restent
dans le dénominateur du rappel. Les principales contributions sont exprimées en
logit ; elles expliquent l'équation, pas une causalité ni une preuve de spam.

Évaluer ensuite le test, sans réajustement :

```sh
/chemin/prive/fusion-venv/bin/python research/train_fusion.py evaluate experiment.json /chemin/prive/candidate
noisefence fusion-predict /chemin/prive/learning.jsonl \
  --model /chemin/prive/candidate/full.json --output /chemin/prive/native-predictions.jsonl
```

`fit.json` lie le manifeste et les modèles par empreintes. `test.json` contient
TP/FP/FN/TN, rappel, précision, taux de faux positifs, intervalles de Wilson à 95 %,
résultats par langue, type, label et disponibilité, Brier, log-loss et diagramme
de fiabilité sous forme de classes numériques. Les empreintes sont revérifiées
avant évaluation ; un test déjà consommé dans ce dossier ne peut pas être relancé.
Il reste consommé si l'opérateur copie ou déplace le dossier.

Le critère documentaire exige au moins 10 000 légitimes et 2 000 indésirables
représentatifs, un rappel observé d'au moins 95 % et une borne supérieure du taux
de faux positifs compatible avec 0,1 %. Aucun résultat de cette chaîne ne suffit
à autoriser seul la production. Les corpus historiques, les corrections et les
exemples synthétiques servent au développement et aux diagnostics distincts.

## Vérification logicielle

```sh
cargo build --locked --bin noisefence --example fusion_fixture
python3 research/verify_fusion.py var/fusion-parity
```

Ce contrôle construit 400 observations synthétiques, apprend les cinq variantes,
compare 2 000 prédictions Python/Rust et vérifie la règle sans préfixe pour les
analyses incomplètes. Aucun email ni appel de détecteur n'est produit. La CI
exécute ce contrôle avec les autres tests ; sa réussite n'est pas une mesure de
qualité antispam.

Références : [calibration des probabilités](https://scikit-learn.org/stable/modules/calibration.html),
[choix du seuil sur un lot distinct](https://scikit-learn.org/stable/modules/classification_threshold.html).
