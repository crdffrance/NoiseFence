# Recherche dans les messages

Dans **Messages**, saisir un ou plusieurs mots, ou ouvrir **Recherche avancée**.
La recherche locale couvre les objets, expéditeurs d’enveloppe, adresses et alias
accessibles, identifiants NoiseFence et identifiants des règles présentes dans
`scan.reasons`. Par exemple : `fact sept`, `"réunion équipe"`, une adresse ou
`suspicious_link`. Tous les termes sont requis. Les mots de l’index sont recherchés
par début de mot, sans distinction de casse ni d’accents ; les guillemets imposent
une suite de mots exacte. Une adresse ou un identifiant peut aussi être retrouvé
par fragment. Les caractères `*`, `%`, `OR`, `NOT` n’activent pas un langage SQL ou
une syntaxe de requête libre.

Les critères avancés se combinent entre eux et avec le classement et le domaine :

- expéditeur, destinataire/alias, objet, règle et identifiant NoiseFence ;
- état d’une livraison visible (livré, en attente, quarantaine, échec…) ;
- dates de réception, avec journée de fin incluse dans le fuseau du navigateur ;
- score minimum et maximum, correspondant au nombre affiché par la console.

Un score partiel ou indicatif reste recherchable sans devenir un verdict de spam.
Une valeur absente ne devient pas zéro. Un destinataire et un état de livraison
fournis ensemble doivent correspondre à la même livraison autorisée.

Les résultats sont triés du plus récent au plus ancien, par pages de 50. Le total
correspond à tous les critères et aux droits actuels de l’utilisateur. Il est lu
dans le même instantané SQLite que la page. L’arrivée de nouveaux messages entre
deux pages peut décaler la pagination ; aucune liste de recherche n’est figée.

## Conservation et confidentialité

La recherche couvre les métadonnées conservées 30 jours et les messages dont le
fichier est encore conservé pour résolution de la file/quarantaine. Les corps,
pièces jointes, textes OCR, contenus de liens et raisonnements LLM ne sont pas
indexés. Les corps déjà supprimés après livraison ne peuvent pas être recherchés.
Aucune requête ni aucun contenu n’est envoyé à un service externe.

Les destinataires ne sont jamais placés dans l’index commun : leur recherche
passe par les autorisations en vigueur dans `console_access`, y compris pour le
compte administrateur et les accès à un domaine. Une copie cachée non autorisée
ne produit ni résultat ni total. Le domaine sélectionné limite également les
destinataires renvoyés. L’interface n’enregistre pas les recherches dans le stockage
persistant du navigateur ; comme pour l’ancienne API GET, les paramètres peuvent
figurer dans les journaux d’accès du proxy. Protéger et limiter ces journaux.

## API

`GET /api/v1/search/messages` exige une session connectée. Paramètres facultatifs :
`q`, `filter` (défaut `all`), `domain`, `offset`, `sender`, `recipient`, `subject`,
`rule`, `id`, `status`, `after`, `before`, `min_score`, `max_score`.
`after` est un timestamp Unix inclusif et `before` exclusif. Les scores sont
compris entre 0 et 100. Réponse :

```json
{"messages": [], "total": 0, "offset": 0, "has_more": false}
```

L’ancienne route `/api/v1/messages` conserve sa réponse sous forme de tableau et
utilise le même moteur. Les requêtes invalides reçoivent HTTP 400. La recherche
libre est limitée à 600 octets, 12 termes de 200 octets, les champs à 256 octets.
Les lectures utilisent au maximum quatre instantanés WAL concurrents, avec
interruption SQLite après trois secondes. Une saturation renvoie une erreur de
service, jamais une liste vide présentée comme un résultat réussi.

## Index et mise à niveau

Au premier démarrage, une migration transactionnelle ajoute un index
[SQLite FTS5](https://www.sqlite.org/fts5.html), sa vue source et trois déclencheurs.
Elle indexe l’historique sans réécrire les analyses ni les états de livraison.
L’objet est borné à 4096 caractères, l’expéditeur à 1024 et la liste des règles à
16384. Les insertions, modifications et suppressions restent synchronisées dans
la transaction d’origine ; un échec d’indexation ne confirme pas une acceptation
SMTP non persistée.

Le schéma de file reste en version 2. L’index est additif et compatible avec le
binaire 0.11.1, qui embarque la même bibliothèque SQLite. Son effacement sécurisé
FTS5 nécessite SQLite 3.42 ou plus récent pour les outils manipulant cet index.
Ne pas ouvrir ni modifier les tables FTS5 avec un ancien outil SQLite. Sauvegarder
la base de manière cohérente avant mise à niveau ; l’index augmente le stockage
et son premier remplissage dépend de la taille de l’historique. Les déclencheurs
suppriment aussi les entrées et anciens jetons lors de la purge des métadonnées.
Le WAL et les sauvegardes suivent leur propre cycle de conservation.
