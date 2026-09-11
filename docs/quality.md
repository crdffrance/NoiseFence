# Qualité du filtrage : observations, annotations et candidats

Depuis 0.4.8, NoiseFence conserve une observation jointe du contenu, des contrôles,
de la réputation et du type de courrier. Le classement appliqué reste distinct
**du candidat en observation**, qui ne peut ni tagger, ni mettre en quarantaine,
ni remplacer la décision de livraison. Aucun modèle privé n’est livré avec le logiciel.

## Corriger sur un échantillon représentatif

La page **Qualité du filtre** est disponible aux administrateurs et aux utilisateurs.
Elle tire au sort 25 à 200 messages parmi ceux auxquels le compte a accès, dans
une période et un domaine choisis. La période proposée commence avec la collecte
introduite dans cette version. Elle inclut les analyses incomplètes. Le tirage
ne consulte aucun score ; sa graine, sa population et ses membres sont figés.
Les messages arrivés ensuite ne modifient pas le lot.

Vérifier l’original dans la boîte du destinataire, puis annoter séparément :

- le risque : légitime, spam/fraude ou incertain ;
- le type : conversation, transaction, notification, newsletter, promotion ou autre.

Une newsletter consentie est légitime et de type newsletter. Une publicité
frauduleuse peut être spam et de type promotion. Le type ne neutralise jamais le
risque. L’objet seul ne constitue pas une preuve ; choisir « Je ne peux pas
conclure » si l’original n’est pas disponible. Aucun label n’est déduit du filtre.
Les scores sont masqués pendant cette annotation.

La console indique séparément le nombre d’annotations de risque et de type
associées à des observations exploitables, les observations manquantes et le
nombre de configurations de détecteurs présentes. Le type est facultatif :
il ne bloque pas une annotation certaine du risque. Ces compteurs ne valident
ni les effectifs par période ni un futur modèle.

Les labels certains mettent aussi à jour les corrections historiques. « Incertain »
retire le vote binaire précédent. Une nouvelle correction historique invalide la
double annotation devenue obsolète. Les messages déjà livrés restent inchangés.
L’accès est revérifié côté serveur à chaque lecture et écriture, avec session,
contrôle d’origine et CSRF pour les mutations. Les copies cachées ne deviennent
pas visibles à d’autres comptes.

## Préparer un candidat sur le serveur

Pour une évaluation plus grande, le CLI autorise jusqu’à 50 000 messages dans une
population de 50 000 maximum. Le même lot s’annote dans la console par pages de 200.
Les dates sont des secondes Unix UTC, dans les trente derniers jours. Exemple
à adapter, en remplaçant les variables par la période, le compte et l’identifiant
renvoyé par la première commande :

```sh
noisefence --config /etc/noisefence/config.toml quality-sample \
  --username "$ANNOTATOR" --since "$SINCE" --until "$UNTIL" \
  --count 10000 --domain example.org

noisefence --config /etc/noisefence/config.toml quality-export \
  --username "$ANNOTATOR" --batch "$BATCH_ID" \
  --output /var/lib/noisefence/quality/sample.jsonl

OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 /opt/noisefence-learning/bin/python \
  /opt/noisefence/current/research/train_quality.py \
  /var/lib/noisefence/quality/sample.jsonl \
  /var/lib/noisefence/quality/candidate-01 --version candidate-01
```

Créer préalablement le répertoire privé et installer `research/requirements.txt`
dans un environnement Python dédié. Le chemin Python de l’exemple est à adapter.
L’export refuse d’écraser un lot. Il ne contient ni corps, ni pièces jointes, ni
objet, ni adresse de correspondant, ni clé privée de jointure ; les vecteurs,
empreintes de campagne et dates restent des données privées. Ne pas les publier
sur GitHub. Les exports et modèles hors SQLite ont une rétention à gérer par
l’exploitant, contrairement aux métadonnées en base qui expirent après trente jours.

L’entraînement exige des annotations humaines dans cinq périodes chronologiques
figées : 50 % entraînement, 15 % choix des paramètres, 15 % calibration, 10 % seuils,
10 % test final. Les campagnes exactes ou proches ne traversent pas ces périodes.
Les campagnes contradictoires et celles qui traversent une frontière sont exclues
et comptées. Une campagne conservée contribue un représentant déterministe.
Depuis 0.4.12, les deux têtes sont entraînées séparément sur les mêmes frontières
temporelles, fixées avec tous les messages conservés, même non annotés ou incomplets.
Chaque période du risque doit contenir au moins douze campagnes et les deux risques :
sinon la commande sort avec le code 3 et un rapport `insufficient_labels`, sans modèle.
Le type utilise ses propres annotations et exige douze campagnes et les six types
par période. S’ils manquent, seul le risque est entraîné ; le type indique
`not_trained` et aucune distribution de types n’est inventée. Un conflit de type
ne supprime pas une annotation de risque cohérente, et réciproquement.
Ce minimum logiciel ne garantit pas une évaluation statistique suffisante.

La régression logistique est régularisée. Le risque reçoit une calibration de
Platt et une zone d’abstention ; les six types reçoivent une calibration de température.
Le rapport mesure rappel, faux positifs, précision et intervalles binomiaux exacts
à 95 %, abstentions, Brier, matrice des types, résultats par type, comparaison au
classement appliqué et neuf ablations prédéfinies : sans LLM, réputation,
historique, modèle lexical, modèle sémantique, identité/authentification,
vision, type de courrier, puis contenu seul. Chaque variante est réentraînée
et calibrée sur les mêmes périodes ; elle ne se règle pas sur le test final.
Retirer une famille mesure son apport conditionnel, pas son indépendance causale.
Les profils de contrôles non rencontrés à l’entraînement sont des abstentions.
Les contrôles indisponibles ne sont jamais transformés en verdict malveillant.

L’unité de test est **la campagne**, pas l’ensemble du trafic. Les messages sans
annotation, inaccessibles, incomplets ou exclus restent comptés. Un sous-ensemble
facile à annoter ne démontre pas le taux de faux positifs de la population.
Pour une revendication sur le trafic, réserver ensuite une population indépendante,
annoter ses messages et compter les omissions et abstentions. Ne pas régler les
seuils sur le lot ayant servi à publier les résultats. Une absence d’erreur sur
quelques dizaines de courriers ne démontre pas l’objectif de 0,1 %.

L’option `--base-history chemin.jsonl` vérifie aussi l’absence de campagnes communes
avec les jeux des modèles de base ou des tests précédents. Ce fichier privé contient
`fingerprint`, `simhash` et `campaign`, comme les exports de fusion. Son absence
reste une limite explicite du rapport ; aucun certificat d’activation n’est produit.

Le modèle `noisefence-quality-model-2` lie par SHA-256 un manifeste privé contenant
toutes les campagnes déjà consultées, y compris celles exclues de l’entraînement,
ainsi que l’historique fourni. Les profils de disponibilité des deux têtes sont
distincts. Conserver `training-manifest.json` avec les poids ; il ne doit pas être
publié. Le format 1 reste lisible, mais seul le format 2 porte cette provenance.

## Évaluer sur un nouveau lot indépendant

Figer le modèle avant le début de la période suivante. Exporter ensuite un
nouveau tirage uniforme entièrement annoté, sans le consulter pour régler le
candidat. Ne pas mélanger plusieurs versions de détecteur lors de l’entraînement :
l’empreinte inclut la version de l’application. Une mise à jour exige de nouvelles
observations compatibles ; elle ne rend pas rétroactivement les anciennes compatibles.

```sh
OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 /opt/noisefence-learning/bin/python \
  /opt/noisefence/current/research/evaluate_quality.py \
  /var/lib/noisefence/quality/independent.jsonl \
  --model /var/lib/noisefence/quality/candidate-01/model.json \
  --training-manifest /var/lib/noisefence/quality/candidate-01/training-manifest.json \
  --output /var/lib/noisefence/quality/evaluation-01.json
```

Cette commande ne modifie aucun seuil, modèle, message ou réglage. Elle refuse
d’écraser le rapport et vérifie l’empreinte du manifeste. Les campagnes communes
avec tous les jeux antérieurs, les doublons, conflits, labels absents, pertes de
droits, observations incompatibles et modèles expirés empêchent une validation
complète. Une provenance inconnue du corpus de base bloque aussi cette validation.
Les prédictions indisponibles comptent comme abstentions, jamais comme bonnes réponses.

Le rapport compare le classement enregistré au candidat pur et au candidat avec
la priorité antivirus principale déjà observée. Il sépare les unités message et
campagne, la calibration du risque et la précision/rappel PUB (newsletter ou
promotion), avec une matrice des six types incluant une colonne indisponible.
Les métriques PUB portent sur les messages également annotés en risque.
Les corrections des destinataires et le dossier choisi par Proton ne sont pas
rejoués ; des appels fournisseurs/LLM enregistrés ne valident pas une autre
politique de sélection de ces appels.

Critères de pilote : au moins vingt spams et cent légitimes indépendants, moins
de faux positifs, autant de spams capturés et pas davantage d’abstentions. Les
objectifs finaux portent sur les bornes binomiales unilatérales à 95 % : capture
au moins 95 %, faux positifs au plus 0,1 %, abstentions au plus 5 %. Ils demandent
beaucoup plus d’exemples et une revue de leur représentativité. Le rapport
contient toujours `may_activate: false`, même si ces tests numériques passent.
Le code de sortie est 0 si le pilote passe, 3 sinon ; il n’autorise aucune activation.

## Expliquer les erreurs sans exporter les messages

Le détail d’un message décompose le score historique avant saturation entre
modèle lexical, sémantique, règles, authentification, réputation, SMTP et LLM.
Une contribution combinée historique reste indivisible si sa décomposition
manque. La somme est vérifiée contre le score enregistré ; une divergence reste
visible. Les poids appris du texte et de la structure MIME partagent des buckets
de hachage : ce rapport ne prétend pas les séparer rétroactivement.

`noisefence audit-confirmation /var/lib/noisefence/state.sqlite3` produit aussi
ces agrégats par faux positifs, spams détectés, erreurs et abstentions, ainsi que
les erreurs propres au second avis, son statut, son coût comptabilisé et ses
durées. Seules les décompositions réconciliées entrent dans les moyennes de
contribution. Les retours contradictoires et inaccessibles sont exclus explicitement.
Il s’agit de corrections ciblées, donc biaisées, pas d’une mesure du trafic.
L’audit n’ouvre pas les corps, n’appelle aucun fournisseur et ne réécrit pas SQLite.

## Charger uniquement en observation

Après revue du rapport et vérification de la parité Python/Rust :

```toml
[quality]
candidate = "/var/lib/noisefence/quality/candidate-01/model.json"
```

Le modèle est un JSON de poids, sans code exécutable, limité à 2 Mio. Redémarrer
le service après validation de la configuration. Protocole, empreinte de politique,
modèles de base, profils et dimensions doivent correspondre. Un candidat expiré
après trente jours ou incompatible s’abstient. La console indique son état séparément
du classement appliqué. Cette version ne propose aucune activation de ses actions.
Les tâches d’entraînement historiques restent inchangées ; ce pipeline joint est
lancé explicitement une fois le lot annoté, sans entraînement automatique sur les
prédictions du filtre.

## Identité, liens et réputation

L’historique d’un correspondant nécessite une source SMTP native, un unique From,
un DKIM aligné validé par DMARC et un seul domaine destinataire. Il utilise uniquement
les corrections antérieures d’administrateurs actifs et autorisés, sur trente jours.
Cinq campagnes légitimes sur trois jours distincts, sans indésirable ni conflit,
établissent un signal de confiance ; jamais une liste blanche. Le local-part garde
sa casse. Une requête interrompue ou saturée devient indisponible, sous une borne
externe de 200 ms incluse dans le délai global d’analyse.

Le contexte de phishing rapproche nom protégé, domaine affiché, domaine Reply-To,
lien OCR/QR et site final d’une chaîne de redirection complète. Une exception
sur un tracker ne dispense pas du contrôle du site final. Les bornes existantes
sur les redirections, le DNS, les adresses publiques et les volumes restent actives.
Aucun nouveau téléchargement de pièce jointe ni exécution de contenu n’est ajouté.
Les nouveaux signaux contextuels alimentent les observations et les candidats ;
ils ne forcent pas seuls le classement historique.

Chaque observation CRDF/VT conserve un digest de l’indicateur, sa portée, son statut,
la date de requête et une borne d’âge du cache. Pour VT, l’identité et le type de
l’objet doivent correspondre ; les analyses de plus de sept jours restent indisponibles.
Pour CRDF, une correspondance portant sur une page précise reste suspecte à
l’échelle de l’hôte, et la date de l’analyse est inconnue si elle n’est pas prouvée.
Une requête synthétique à la racine n’atteste pas toutes les pages du domaine.
Les compteurs distinguent les portées et les indicateurs communs entre fournisseurs.
Voir la [documentation CRDF](https://threatcenter.crdf.fr/api/doc/) et les objets VT
[domaine](https://docs.virustotal.com/reference/domain-info) et
[fichier](https://docs.virustotal.com/reference/file-info).

## Vérifications logicielles et exploitation

`tests/quality.rs`, les tests de console et les tests des connecteurs couvrent la
provenance, les portées, la fraîcheur, les droits, l’export privé et le maintien
de la décision originale. `tests_python/test_quality.py` utilise uniquement des
fixtures synthétiques ; la CI compare les probabilités des poids Python à Rust
à 1e-9 près. Les tests SMTP concurrents vérifient toujours la file durable et les
corps inchangés. Ces tests ne constituent pas une mesure de capture en production.

Les tables d’échantillons et de labels, l’index d’historique et les champs JSON
sont additifs au schéma 2, compatibles avec le binaire 0.4.7. En cas de retour à
cette version, retirer la section `[quality]` si elle a été ajoutée. Ne jamais
restaurer une vieille base qui ferait disparaître des messages acceptés après
la mise à jour. Conserver l’observation tant que les validations Proton et les
mesures indépendantes nécessaires ne sont pas réunies.
Pour revenir à 0.4.11 ou avant, retirer aussi tout candidat de format 2 de la
configuration avant de démarrer l’ancien binaire. Les poids actifs historiques,
les budgets externes et les règles de livraison ne sont pas changés par 0.4.12.
