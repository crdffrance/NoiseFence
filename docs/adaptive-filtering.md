# Catégories adaptatives locales

NoiseFence 0.8 ajoute un module Rust indépendant pour `legitimate`, `publicity`,
`spam`, `phishing` et `scam`. Le Bayes binaire et le moteur de livraison restent
séparés. Ce module est **exclusivement en observation** : sa catégorie et son
action proposée ne participent ni au score ni au marquage ni à la quarantaine.
Une publicité frauduleuse doit être annotée spam, phishing ou escroquerie ; PUB
désigne ici une campagne commerciale légitime. Une annotation incertaine reste vide.

## Algorithmes et limites

Le Bayes utilise les présences de paires OSB, des fréquences documentaires par
classe, un lissage additif, des a priori équilibrés et les 150 caractéristiques
discriminantes les plus fortes. Moins de cinq caractéristiques connues entraîne
une abstention. Les vraisemblances normalisées ne sont pas des probabilités
calibrées de menace.

Le réseau 16×16×5 utilise une couche cachée tanh et une sortie softmax. Ses entrées
sont les tailles et structures du texte/HTML, six motifs locaux explicites
(urgence, identifiants, rendement, phrase de récupération, formulaire,
désabonnement), longueur de l’objet, majuscules, chiffres, liens HTTPS et
exclamations. Ces entrées sont bornées et versionnées avec les motifs configurés.
Le réseau n’utilise ni les verdicts des autres modèles, ni les composites,
ni les corrections humaines comme caractéristiques, ni l’identité d’une boîte.
Il complète l’encodeur E5 existant ; il ne le remplace pas et ne l’appelle pas.

L’entraînement est déterministe, avec équilibrage des classes, pénalité L2,
poids bornés et arrêt anticipé sur validation, au maximum 120 époques.
Les deux classifieurs doivent s’accorder et dépasser leurs seuils et marges.
Une forte sortie softmax seule ne suffit pas. Un échec, une expiration ou une
observation incomplète ne constitue pas un signal de spam.

## Collecte et politiques par domaine

La collecte est désactivée en l’absence de configuration. Exemple à intégrer
dans la configuration existante, sans dupliquer `[native_filter]` :

```toml
[native_filter]
mode = "observe"
max_bytes = 1048576
max_parallel = 2
timeout_ms = 500

[native_filter.adaptive.domains."example.org"]
# Omettre model pour collecter avant le premier entraînement.
# model = "/var/lib/noisefence/adaptive/example.org/candidate/model.json"

[native_filter.adaptive.domains."example.org".classes.phishing]
min_strength = 0.95
min_margin = 0.25
proposed_action = "quarantine"

[native_filter.adaptive.domains."example.org".classes.publicity]
min_strength = 0.95
min_margin = 0.25
proposed_action = "tag"
```

Les valeurs par défaut sont 0,9 et 0,2, avec action `observe`. Les actions `tag`
et `quarantine` sont **simulées**, y compris si le filtrage principal est en mode
application. Aucun réglage de ce module ne permet d’activer leur exécution.
La classe légitime accepte uniquement l’observation. Un seuil issu de la
validation ne peut pas être abaissé par la politique du domaine.

Les domaines sont ceux des **destinataires de livraison** après résolution des
alias. Chaque modèle a exactement un domaine ; aucun entraînement global ni
repli sur le modèle d’un autre domaine. Une enveloppe visant plusieurs domaines
ne collecte pas de vecteur adaptatif et n’affiche aucune prédiction de locataire.
Cette abstention protège aussi les destinataires en copie cachée. Le reste de
l’analyse et de la livraison continue normalement.

Maximum seize domaines configurés, modèle de 8 Mio par domaine, cinq mille
exemples par export. L’inférence réutilise les workers, sémaphores, limites MIME
et délai global du filtre natif. Un worker annulé garde son permis jusqu’à sa fin.
Les fichiers modèles sont chargés au démarrage, jamais par message. Une modification
de configuration ou de modèle nécessite un redémarrage contrôlé.

## Annotations et entraînement

Dans la fiche d’un message, « Apprentissage local » permet d’annoter une catégorie
par domaine accessible. Phishing/escroquerie mettent aussi la correction générale
à spam ; PUB reste légitime pour le risque binaire. Une nouvelle correction
générale supprime l’ancienne précision. Retirer uniquement la catégorie détaillée
laisse la correction générale intacte. Les messages déjà livrés ne changent pas.

L’API utilise les sessions, l’origine et le jeton CSRF existants. Toutes les
lectures et écritures vérifient les droits actuels sur les destinataires, la
période de trente jours et l’état du compte. Les exports nécessitent un compte
administrateur actif et réévaluent aussi les droits actuels des annotateurs.
Les conflits entre annotateurs sont exclus ; aucune prédiction n’est convertie
automatiquement en vérité humaine. Les annotations anciennes spam/PUB ne deviennent
pas artificiellement des annotations phishing/escroquerie.

```sh
noisefence -c /etc/noisefence/config.toml adaptive-export \
  --username admin --domain example.org --output /private/review/examples.jsonl

noisefence adaptive-train /private/review/examples.jsonl \
  --output /private/review/candidate --version example-20260912 \
  --train-until 1788825600 --validation-until 1788998400

noisefence adaptive-evaluate /private/review/future.jsonl \
  --model /private/review/candidate/model.json \
  --manifest /private/review/candidate/manifest.json \
  --training-report /private/review/candidate/report.json \
  --output /private/review/future-report.json
```

Adapter les dates Unix au trafic collecté. Les trois périodes doivent contenir
au moins **20 campagnes indépendantes par classe à l’entraînement**, puis cinq
par classe en validation et cinq en test. Ce sont des minima techniques, pas
une preuve de qualité. Chaque annotation doit avoir été disponible avant la
frontière de sa période. Des annotations effectuées aujourd’hui sur de vieux
messages ne permettent donc pas de simuler un apprentissage qui aurait eu lieu
hier : continuer la collecte et fixer des frontières réalistes.

Les empreintes exactes et les sketches de texte similaires regroupent les
campagnes avant la séparation. Les groupes traversant une frontière ou portant
des catégories contradictoires sont exclus. Cette méthode ne garantit pas de
reconnaître toutes les variantes d’une campagne ; auditer aussi manuellement
les populations. Le budget de comparaison refuse les jeux trop complexes.

Le réseau et les seuils sont sélectionnés sur la validation seule. Pour qu’une
classe puisse émettre un avis, la validation exige au moins cinq avis corrects
sans erreur sur la grille de seuils. Le test n’ajuste aucun paramètre. Le manifeste
garde les campagnes de toutes les périodes et les exclusions ; l’évaluation
ultérieure vérifie les empreintes des artefacts, les dates et les chevauchements.

Les rapports donnent la matrice 5×6 (abstentions comprises), précision, rappel,
faux positifs et intervalles de Wilson à 95 %. Les faux positifs de menace
incluent les catégories légitime et PUB. La confusion entre ces deux catégories
reste visible dans la matrice. Zéro faux positif sur un petit lot ne démontre
pas un taux inférieur à 0,1 %. Aucun rapport ne permet l’activation automatique.

Lancer ces commandes hors du chemin SMTP, éventuellement depuis une tâche
d’exploitation périodique. Examiner les résultats avant de référencer un modèle
en observation. Il n’existe pas de réentraînement automatique depuis les scores.

## Mesures locales, confidentialité et retour arrière

```sh
noisefence -c /etc/noisefence/config.toml adaptive-check /private/sample.eml \
  --domain example.org --iterations 1000
```

Cette commande ne fait ni requête DNS, ni livraison, ni écriture dans la file.
Elle restitue le rapport public et le p95 local de l’extraction et du filtre natif,
avec réutilisation du modèle. Elle ne mesure pas le débit SMTP complet ni les
latences des services externes. Sans modèle configuré, elle mesure la collecte.

Les caractéristiques privées restent dans les observations natives pendant la
conservation du message ; les messages en file suivent les règles existantes.
Les annotations expirent à trente jours, même si le message reste en file.
Les exports ne contiennent ni corps, ni pièces jointes, ni adresses individuelles,
mais leurs caractéristiques textuelles restent sensibles. Fichiers créés en 0600,
répertoires candidats en 0700 ; l’opérateur doit supprimer les exports et modèles
expirés, aucun fichier externe n’est effacé automatiquement.

SQLite reste au schéma 2 : table additive `adaptive_labels` et déclencheurs de
retrait des annotations obsolètes. La version 0.7 ignore les nouveaux champs des
observations. Avant retour à 0.7, retirer `[native_filter.adaptive...]` de la
configuration ; garder la base courante pour préserver les messages acceptés.
La nouvelle empreinte du détecteur exige de reconstruire les candidats optionnels
qui en dépendent. Les modèles lexicaux et sémantiques actifs restent indépendants.

## Inspiration et licence

Implémentation indépendante en Rust des techniques publiées, sans copie de code
C/Lua. Rspamd documente un [Bayes multiclasse](https://docs.rspamd.com/configuration/statistic/)
séparé du risque binaire, ainsi qu’un [module neuronal](https://docs.rspamd.com/modules/neural/)
apprenant à partir de signaux locaux. NoiseFence conserve ses propres artefacts,
limites et étapes de validation ; aucune compatibilité binaire de modèle n’est
revendiquée. Rspamd est distribué sous [Apache 2.0](https://github.com/rspamd/rspamd/blob/b86f72ae34ec515802aa23b60b535e9d25684d65/LICENSE.md) ;
NoiseFence conserve sa licence GPL-3.0-only.
