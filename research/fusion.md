# Fusion apprise des observations

NoiseFence peut entraîner puis évaluer hors ligne une décision commune à partir
des observations des détecteurs. Cette chaîne produit des modèles de recherche
JSON exécutables nativement en Rust. Le service peut comparer cette fusion en
observation, puis utiliser sa décision après validation explicite. Un candidat nécessite un test
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
fait varier toutes les familles de contrôles, compare 2 000 prédictions
Python/Rust et vérifie la règle sans préfixe pour les analyses limitées, erreurs
de réputation et saturations LLM. Aucun email ni appel de détecteur n'est produit. La CI
exécute ce contrôle avec les autres tests ; sa réussite n'est pas une mesure de
qualité antispam.

## Décision du service et de la console

Sans table `[fusion]`, le comportement historique est conservé, avec une décision
persistée explicite : `legitimate`, `unwanted` ou `undetermined`. SMTP, liste,
recherche et statistiques utilisent la même décision, y compris lorsque le seuil
de configuration change ensuite. Les anciennes lignes restent interprétées avec
leur indice historique et le seuil configuré ; une analyse incomplète n'est pas
comptée comme indésirable. L'indice historique `scan.score` reste disponible pour
la comparaison et la sélection des appels LLM. Les en-têtes internes
`X-NoiseFence-Decision` et `X-NoiseFence-Decision-Source` reprennent le résultat
et sa source ; ceux reçus de l’expéditeur sont supprimés et les nouveaux champs
sont inclus dans le scellement ARC. Une indisponibilité ou saturation
LLM rend la décision indéterminée ; les sauts volontaires ou budgétaires restent
des états distincts.

Pour observer un candidat réellement entraîné sur les mêmes détecteurs :

```toml
[fusion]
model = "/var/lib/noisefence/models/fusion.json"
mode = "observe"
```

Le démarrage vérifie les octets du modèle et l'égalité exacte de ses artefacts
avec les détecteurs chargés. `check-config` vérifie la structure de configuration ;
le chargement complet des artefacts est effectué au démarrage du service. Une
modification de version, de dépendances, de détecteur ou de politique impose une
nouvelle expérience. La table `[fusion]` est exclue de l'empreinte de la politique
des détecteurs : elle ne change pas leurs observations ni la sélection LLM et
évite une dépendance circulaire entre le fichier candidat et ses entrées.

En observation, `scan.fusion` conserve le résultat, les principales contributions
et les disponibilités sans changer la décision active. `scan.decision` est le
résultat utilisé pour la livraison. La console distingue cette comparaison de
recherche du classement actif. Les probabilités n'ont de sens que pour la
population et les profils de calibration ; les contributions ne sont pas des
preuves. Un diagnostic `scan` ou `analyze` ne devient jamais une réception SMTP.

`mode = "decision"` nécessite aussi `validation_report`, un dossier JSON de revue
administrateur, borné à 32 Kio, selon `noisefence-fusion-promotion-1`. Il contient :

- Les SHA-256 des octets du modèle, du manifeste figé, du rapport de test, de
  couverture de la population et de latence du traitement complet.
- `reviewed_at`, `observation_start`, `observation_end` en secondes Unix et une
  référence de revue `review_reference`. Revue de moins de 30 jours, observations
  de moins de 90 jours ; `sampling = "representative_smtp"`.
- `tp`, `fp`, `fn_count`, `tn` sur le test récent indépendant, comprenant les cas
  sans préfixe faute d'analyse exploitable. Au moins 10 000 légitimes et 2 000
  indésirables ; rappel ≥ 95 % et borne supérieure Wilson à 95 % des faux
  positifs ≤ 0,1 %. Aucun message laissé hors bilan (`unaccounted_messages = 0`).
- `pipeline_p95_ms < 500` et `pipeline_samples >= 1000`, mesurés pour des messages
  ≤ 1 Mio, caches chauds, sur la machine de référence et avec les contrôles actifs.

Les noms exacts et types sont définis dans `src/fusion/runtime.rs` (`Validation`).
Ces références et nombres sont une **attestation de revue**, pas une preuve
automatiquement vérifiée par les seuls hashes : auditer et conserver les rapports
sources, le périmètre, l'indépendance, les exclusions et les mesures. Ne jamais
copier les nombres fabriqués des tests logiciels pour activer un modèle réel.
Un rapport de `train_fusion.py` sur les seuls représentants de campagne ou sur les
seules corrections n'atteste pas à lui seul de la couverture du trafic SMTP.

Au démarrage et pour chaque décision, le service revérifie les conditions et
l'âge de cette attestation. Un profil non validé, une panne, une analyse incomplète
ou une attestation expirée produit une décision indéterminée, sans score fusion
exploitable ni préfixe. Le seuil porte sur le logit brut figé ; ni l'arrondi de la
console ni `filter.threshold` ne remplacent ce seuil. L'observation des détecteurs
reste distincte d'une indisponibilité de la fusion.

Le préfixe demande toujours `filter.mode = "tag"` **et** le rapport Proton valide
déjà exigé par la passerelle. La réception reste en observation tant que cette
validation de livraison n'est pas établie. Aucun entraînement ni retour utilisateur
n'active automatiquement une nouvelle version.

## Couverture de toute la population retenue

`export-learning` sélectionne les vecteurs textuels exploitables. Pour auditer son
périmètre sans dissimuler les limites MIME ou les données absentes :

```sh
noisefence --config /etc/noisefence/config.toml export-population /chemin/prive/population.jsonl \
  --since 1788739200 --until 1788825600
```

Adapter ces bornes Unix à un intervalle **réel des 30 derniers jours**, début
inclus et fin exclue. Le fichier `noisefence-population-1` contient un en-tête,
une ligne par message entrant retenu et un bilan final, dans une seule transaction
SQLite. Les notifications produites par le service sont comptées séparément.
Ce périmètre couvre les messages acceptés et encore retenus, pas les refus SMTP
ni des métadonnées déjà supprimées. Il n'est jamais déclaré représentatif par
défaut (`sampling = "unreviewed"`).

Chaque ligne garde les timestamps fiables, l'identité hachée, l'empreinte des
octets originaux quand disponible, les empreintes de campagne quand calculables,
la décision et les observations SMTP typées. L'empreinte brute ne remplace pas
une empreinte de campagne absente. Aucun expéditeur, destinataire, objet, corps,
pièce jointe ou vecteur textuel n'est exporté. Les anciens champs absents restent
inconnus ; aucun en-tête fourni par l'expéditeur ne reconstruit des contrôles.

Les votes sont revérifiés avec les comptes actifs et leurs droits dans le même
instantané. Retours révoqués, désaccords, absence d'annotation, données corrompues,
contexte fourni manuellement et contrôles incomplets sont comptés et restent
visibles. Une erreur de parsing conservée en base ne fait pas disparaître la ligne.
Plusieurs destinataires ne multiplient pas le nombre de messages. Les compteurs
de labels sont exclusifs ; les compteurs de disponibilité peuvent se recouvrir.

Ce bilan prépare l'annotation et la réconciliation avec le test : il ne calcule
pas de taux de capture à partir de labels absents. Une population encore inconnue
ou contradictoire empêche de revendiquer une couverture complète. L'export est
réservé à la CLI administrateur, borné à 50 000 messages/512 Mio, atomique, `0600`,
sans écrasement même en concurrence. Choisir un intervalle plus court au besoin ;
aucune troncature silencieuse. Les fichiers restent privés et soumis à la
conservation de 30 jours, même après suppression des corps de la file.

Références : [calibration des probabilités](https://scikit-learn.org/stable/modules/calibration.html),
[choix du seuil sur un lot distinct](https://scikit-learn.org/stable/modules/classification_threshold.html).
