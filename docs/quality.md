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
Chaque période doit contenir les deux risques et les six types : sinon la commande
sort avec le code 3 et un rapport `insufficient_labels`, sans produire de modèle.
Ce minimum logiciel ne garantit pas une évaluation statistique suffisante.

La régression logistique est régularisée. Le risque reçoit une calibration de
Platt et une zone d’abstention ; les six types reçoivent une calibration de température.
Le rapport mesure rappel, faux positifs, précision et intervalles binomiaux exacts
à 95 %, abstentions, Brier, matrice des types, résultats par type, comparaison au
classement appliqué et ablations sans LLM, fournisseurs ou historique.
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
