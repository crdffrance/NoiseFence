# Mécanismes de filtrage natifs Rust

Depuis 0.4.15, NoiseFence dispose d'un moteur complémentaire d'observation, écrit
en Rust. Il transpose les principes des [composites de Rspamd](https://docs.rspamd.com/configuration/composites/),
de sa [détection de similarité](https://docs.rspamd.com/modules/fuzzy_check/) et des
[classifieurs statistiques](https://docs.rspamd.com/configuration/statistic/).
L'implémentation est propre à NoiseFence : ses résultats et ses formats ne sont
pas interchangeables avec ceux de Rspamd. Les modules Lua et règles `.cf` ne se
chargent pas dans ce moteur.

Depuis 0.9.0, une [banque structurée de douze règles](rspamd-rules.md) complète
les motifs : HTML, métadonnées MIME et identité affichée. Les noms et premières
signatures binaires des pièces jointes sont examinés localement ; ils ne sont pas
ajoutés aux caractéristiques textuelles ou aux appels externes.

## Activer la collecte

Ajouter cette table au fichier de configuration et redémarrer le service après
`noisefence --config /etc/noisefence/config.toml check-config` :

```toml
[native_filter]
mode = "observe"
max_bytes = 1048576
max_parallel = 2
timeout_ms = 500
fuzzy_memory = true
# bayes_model = "/var/lib/noisefence/native/candidate/model.json"
```

L'absence de table désactive le module. `observe` est le seul mode accepté : les
points calculés ne modifient ni le score historique, ni la sélection du second
avis, ni le classement, ni les actions de livraison. Un scan limité reste une
observation indisponible. Le mode Proton existant est indépendant de cette table.
Le modèle Bayes est facultatif ; `untrained` signifie qu'aucun poids n'est chargé.

L'analyse CPU s'exécute hors des travailleurs asynchrones Tokio, avec un nombre
borné de tâches. Les rafales attendent une place dans le budget de temps total. Une tâche annulée conserve son permis jusqu'à sa fin réelle.
Le module ne contacte aucun service externe. La mémoire SQLite a son propre
plafond de concurrence, un délai de 200 ms et une interruption de requête.
La configuration impose 1 à 8 tâches, 50 à 1 000 ms, 1 Kio à 2 Mio par message.
Les tables et les poids du module se rechargent au redémarrage ; une révision de
la console réutilise le modèle déjà chargé et ses limites de concurrence.

## Motifs et composites

`regex::RegexSet` compile les motifs par vue : objet décodé, texte visible et HTML.
Il s'agit d'une recherche groupée Rust, sans liaison C vers Hyperscan/Vectorscan.
Les anciennes étiquettes SPAM/PUB sont retirées de l'objet analysé ; les anciens
en-têtes antispam, les identités de transport et les pièces jointes n'entrent pas
dans les caractéristiques textuelles. Les expressions s'appliquent aux vues
bornées : 500 caractères d'objet, 32 000 de texte et 32 000 de HTML. Au maximum
200 parties MIME sont admises. Les dépassements de ces vues limitent ce que le
détecteur peut voir ; un rapport complet désigne les contrôles sur ces vues.

Une table de motifs fournie remplace la banque par défaut, de même pour les
composites. Exemple minimal autonome à placer après `[native_filter]` :

```toml
[[native_filter.patterns]]
id = "ACCOUNT_REQUEST"
label = "Demande de vérification de compte"
family = "content"
weight = 0.5
target = "body"
pattern = '(?i)verify your account|confirmez votre compte'

[[native_filter.patterns]]
id = "ACCOUNT_URGENCY"
label = "Urgence liée au compte"
family = "content"
weight = 0.3
target = "body"
pattern = '(?i)immediately|immédiatement'

[[native_filter.composites]]
id = "ACCOUNT_PRESSURE"
label = "Vérification demandée avec urgence"
family = "content"
weight = 1.0
all = ["ACCOUNT_REQUEST", "ACCOUNT_URGENCY"]
replace = ["ACCOUNT_REQUEST", "ACCOUNT_URGENCY"]

[native_filter.caps.content]
min = -0.5
max = 1.5
```

Les noms, poids et expressions sont validés avant le démarrage. Limites : 256
motifs de 512 octets, 64 composites, 32 références par composite, mémoire de
compilation bornée. Les références inconnues, collisions de noms et cycles sont
refusés. `all` impose toutes les preuves, `any` au moins une. `none` accepte
uniquement des motifs locaux dont la recherche est terminée : l'absence d'un
résultat DNS ou externe ne devient jamais une preuve négative.

`replace` retire une seule fois les poids des symboles absorbés, en conservant
leurs raisons et les composites consommateurs. Les dépendances s'évaluent dans
un ordre déterministe. Une répétition d'un symbole ne multiplie pas son poids.
Les familles sont `lexical`, `semantic`, `content`, `authentication`, `reputation`,
`smtp`, `llm`, `campaign`, `bayes` et `other`. Chaque famille possède des bornes
positives et négatives ; les familles omises dans la configuration héritent des
valeurs par défaut. Les bornes sont limitées à [-5, 0] et [0, 5].

La contribution lexicale est plafonnée par défaut à 1,5 point dans ce calcul
comparatif. Le calcul actif conserve sa valeur originale. Ces plafonds sont des
paramètres à évaluer, pas des seuils de risque calibrés. Le module ne traite
jamais un score comme une probabilité et n'infère pas le consentement à une PUB.

## Similarité et corrections humaines

Le texte est normalisé, découpé en trigrammes de mots et résumé par 32 minima
hachés. Une autre empreinte décrit l'ordre des éléments HTML, sans leurs attributs.
Les tailles sont bornées à 2 048 tokens. La similarité compare les minima ; les
seuils de 0,875 pour le texte et 0,9375 pour le HTML sont des seuils de recherche,
pas des niveaux de confiance statistique.

La mémoire examine au plus 1 000 messages récents avec corrections humaines
d'administrateurs encore actifs et autorisés. Elle exige un unique domaine de
destination et au moins 24 shingles textuels. Deux originaux distincts signalés
spam et aucun exemple légitime correspondant permettent un symbole consultatif.
Le message courant et ses retransmissions exactes sont exclus. Une ressemblance
de structure HTML seule reste informative, car les newsletters et messages
transactionnels légitimes réutilisent également des modèles.

Les corrections contradictoires empêchent le renforcement. Les originaux de
plus de trente jours, comptes désactivés et droits retirés sont exclus. Une
requête incomplète, saturée ou interrompue ne produit pas de symbole positif.
Les historiques dépourvus des nouvelles caractéristiques ne sont pas reconstruits
à partir de leurs seuls objets ou scores.

## OSB Bayes et évaluation

L'extraction Rust utilise des paires de mots séparées de 1 à 4 positions, dans
deux espaces distincts pour l'objet et le corps. Les présences sont hachées dans
65 536 cases, avec un maximum de 8 192 caractéristiques uniques par message.
Le modèle conserve les fréquences documentaires par classe, applique un lissage
additif et des a priori équilibrés. À l'inférence, au maximum 150 indices connus
contribuent ; moins de cinq donne `insufficient_features`. Aucun verdict du
filtre ne devient une annotation d'apprentissage.

Exporter les corrections du domaine en tant qu'administrateur, puis choisir les
frontières chronologiques **avant** de consulter les résultats :

```sh
noisefence --config /etc/noisefence/config.toml native-export \
  --username admin --domain example.org \
  --output /var/lib/noisefence/native/labels.jsonl

noisefence native-train /var/lib/noisefence/native/labels.jsonl \
  --output /var/lib/noisefence/native/candidate \
  --version osb-candidate-1 \
  --train-until "$TRAIN_UNTIL" --validation-until "$VALIDATION_UNTIL"
```

Les deux frontières sont des secondes Unix UTC. Trois périodes : apprentissage,
choix du seuil, test final. Le regroupement exact et par similarité précède le
découpage : les campagnes traversant une frontière ou portant des labels
contradictoires sont exclues et comptées. Les labels d'apprentissage/validation
doivent avoir été disponibles avant la fin de leur période. Chaque période
exige au moins douze campagnes, dont deux de chaque classe. Ce minimum logiciel
est très inférieur à ce qu'exige la démonstration de 0,1 % de faux positifs.

Le seuil est choisi uniquement sur la validation, avec un taux empirique de faux
positifs au plus 0,1 %. Le test final conserve ce seuil. Le rapport publie rappel,
précision, faux positifs, résultats indisponibles et intervalles de Wilson à 95 %.
Il conserve `may_activate: false`, même lorsque les résultats semblent bons.
Un manifeste privé conserve toutes les campagnes consultées, y compris exclues,
pour détecter les recouvrements lors d'un futur test indépendant :

```sh
noisefence native-evaluate /var/lib/noisefence/native/new-labels.jsonl \
  --model /var/lib/noisefence/native/candidate/model.json \
  --manifest /var/lib/noisefence/native/candidate/manifest.json \
  --training-report /var/lib/noisefence/native/candidate/report.json \
  --output /var/lib/noisefence/native/independent-report.json
```

L'évaluation vérifie les empreintes des fichiers, le domaine et le protocole ;
elle exige des observations postérieures au modèle et compte les campagnes
déjà vues, doublons et omissions. `independent` décrit cette séparation ; il ne
certifie ni une population représentative, ni les objectifs de capture. Une
nouvelle sélection des mêmes messages pour ajuster le modèle invaliderait leur
usage comme test indépendant. Le classifieur ne fournit pas de probabilité
calibrée. Ses modèles expirent trente jours après leur création. Un modèle expiré
devient indisponible et laisse la passerelle démarrer ; aucune contribution Bayes
n’est produite. L’évaluation indépendante exclut aussi les observations hors de
la période de validité du modèle.

Les fichiers sont créés sans écrasement, avec permissions 0600 (répertoire 0700).
Les vecteurs et empreintes restent privés malgré leur hachage. La rétention en
base suit les trente jours des métadonnées ; l'exploitant doit aussi supprimer
les exports, historiques et modèles expirés hors base.

## Diagnostic et débit

Le détail d'un message présente le résultat natif, les contributions brutes et
plafonnées, les symboles absorbés, la disponibilité Bayes et la mémoire des
campagnes. L'API applique les droits habituels par destinataire et expose
uniquement le rapport, sans vecteurs, empreintes de correspondance ou texte.

```sh
noisefence native-benchmark tests/fixtures/message.eml \
  --iterations 1000 --concurrency 4
```

La commande est locale : normalisation MIME, extraction OSB, empreintes,
recherche et composites. Elle rapporte débit, p50/p95/p99, tâches incomplètes et
une comparaison de 128 motifs groupés/individuels avec vérification de parité.
Elle exclut explicitement l'inférence d'un modèle entraîné, SQLite, SMTP, la
persistance et les autres analyseurs. Une accélération sur cette mesure ne
démontre donc ni le débit complet du serveur, ni un gain de qualité antispam.
Utiliser également les tests SMTP et la mesure `pipeline_probe` pour le système
complet, avec les modèles et services réellement déployés.

## Contexte des motifs depuis 0.5.0

La vue de recherche normalise l’ASCII pleine chasse et certains caractères de
coupure invisibles, sans convertir les alphabets confusables en lettres latines
ni supprimer les jointures multilingues. Les modèles lexicaux actifs conservent
leurs entrées. Les commentaires et blocs HTML inertes ne deviennent pas des
formulaires natifs.

Le champ facultatif `exclude_negated = true` s’applique uniquement aux motifs
`target = "body"`. Chaque correspondance est examinée séparément : des formulations
locales comme « never provide », « do not enter » ou « ne communiquez jamais »
sont ignorées. La règle native de demande de phrase de récupération l’utilise par
défaut. Un avertissement dans une phrase ne masque pas une demande explicite dans
la suivante. Ce contrôle limité français/anglais ne constitue ni une compréhension
générale du discours ni une liste blanche : citations, négations complexes et
contenu dépassant la vue restent des cas à mesurer sur le corpus récent.

Les points natifs alimentent aussi le candidat calibré, en observation, avec des
ablations distinctes. Voir [Fiabilité](reliability.md) pour la mesure des règles,
la compatibilité de collecte, les limites et la migration des modèles de 0.4.x.
