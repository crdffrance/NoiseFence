# Plusieurs passerelles MX

Depuis 0.14, NoiseFence peut réunir jusqu’à 16 nœuds autour d’une console centrale.
Les rôles `coordinator` et `worker` concernent la gestion. Les deux serveurs SMTP
analysent les messages et livrent directement aux routes explicites du fournisseur.

```text
Internet ── MX priorité 10 ── mx1 : SMTP + file locale ── fournisseur
         └─ MX priorité 20 ── mx2 : SMTP + file locale ── fournisseur
                               │
                               └── HTTPS sortant vers la console de mx1
                                   réglages / modèles / crédits / historique
```

La priorité MX organise le choix des expéditeurs ; elle n’empêche pas une connexion
directe à mx2. Tous les MX publics doivent donc appliquer le filtrage. Ne pas garder
les MX Proton comme secours public si l’objectif est de faire passer la réception
externe par NoiseFence. Les contraintes de routage interne Proton restent à valider.

## Ce qui est partagé

La console distribue une révision contenant domaines, alias, routes explicites,
actions, niveaux, règles, préférences, RBL et réglages des moteurs. Elle transfère
les modèles autorisés et l’encodeur sémantique, avec manifeste SHA-256. Les fichiers
sont téléchargés en flux, vérifiés, synchronisés sur disque puis activés. Une erreur
conserve la dernière configuration valide ; une nouvelle révision ne change pas
les transactions SMTP déjà commencées. Une modification du modèle sur disque au
coordinateur exige son rechargement validé avant publication.

Chaque nœud possède son identité aléatoire de 256 bits. Seule son empreinte est
stockée dans la base centrale. Les échanges exigent HTTPS avec validation du
certificat, sans redirection ni proxy d’environnement. HTTP n’est disponible que
pour les essais sur une adresse loopback explicite. Le manifeste assure l’intégrité
des fichiers ; l’authentification de l’autorité repose sur TLS et l’identité du nœud,
pas sur une signature indépendante du manifeste ou un certificat client mTLS.

Les clés CRDF, VirusTotal, Scaleway et DQS configurées sont transférées par ce canal
privé et enregistrées avec des permissions restrictives. Les administrateurs des
serveurs rattachés doivent être de confiance. Les clés ARC, certificats SMTP,
comptes Web, sessions, mots de passe et preuves Proton ne sont pas répliqués. Une
référence de clé RBL personnalisée doit être autorisée dans le bootstrap de chaque
nœud pour le même fournisseur et la même zone.

Les corps et pièces jointes restent sur le serveur qui les a acceptés. L’historique
central reçoit analyses, caractéristiques, états par destinataire et les cinq
derniers journaux SMTP de chaque livraison. Les droits de la console et les copies
cachées sont vérifiés sur ces métadonnées. La recherche avancée accepte un filtre
`node` : vide pour tous, `local` pour le coordinateur ou un identifiant comme `mx2`.

La libération/suppression de quarantaine et la relance d’une livraison distante sont
des commandes avec reçu durable. Elles expirent après cinq minutes si le nœud ne
les prend pas en charge. « En attente » ne signifie pas que l’action a été exécutée.
La reprise d’une commande reçue plusieurs fois ne l’exécute pas plusieurs fois.

## Budgets et fonctionnement dégradé

Le plafond LLM est global. Le coordinateur réserve des crédits cumulatifs par
tranches de 0,10 € dans son budget existant. Les réservations locales et distantes
partagent les transactions SQLite. Une réponse perdue renvoie les mêmes crédits.
Les crédits distribués restent comptabilisés même si un nœud est arrêté ou révoqué ;
ils ne sont pas récupérés pendant leur période de validité. L’interface de budget
central inclut donc ces réservations, et non uniquement les appels réellement facturés.

Les quotas CRDF/VirusTotal limités sont alloués de la même façon, par jour et minute.
Le réglage `0` conserve le sens « illimité ». Sans crédits valides, le fournisseur
est indisponible pour cette analyse, jamais une preuve de spam. Les caches, listes
locales, mémoire de correspondants/campagnes, limites par IP et greylisting restent
propres à chaque serveur. Il n’existe pas de quota global par IP dans cette version.
Les mises à jour des bases antivirus et listes de signatures doivent tourner sur
chaque serveur. Synchroniser et superviser les horloges via NTP.

Un nœud ayant déjà synchronisé reste autonome pendant `max_stale_seconds` (24 h par
défaut, maximum sept jours). Il livre sa file même si la console est indisponible.
Il analyse avec la politique en cache et les crédits encore valides. Après expiration,
il répond temporairement `451` à MAIL pour les nouvelles transactions. Un nœud neuf
fait de même jusqu’à sa première synchronisation. Le prochain contact renouvelle
la configuration et remonte les métadonnées restées sur disque. Une erreur de
synchronisation de l’historique est visible et n’empêche pas le renouvellement des
réglages ; les métadonnées concernées restent à résoudre localement.

Cette architecture ne réplique pas les files et ne bascule pas automatiquement la
console. Un courrier déjà accepté sur un serveur indisponible attend son retour.
Une perte définitive de son disque peut perdre ce courrier : prévoir sauvegardes,
stockage fiable et supervision. SMTP peut produire un doublon après perte d’un
accusé final ; l’identifiant NoiseFence n’est pas une garantie globale d’unicité.

## Installation progressive

1. Installer la même release vérifiée sur les deux machines. Prévoir des domaines
   de panne distincts, IP/A/PTR cohérents, ports 25 entrant/sortant, DNS résolveur,
   certificats SMTP valides et espace pour la file et jusqu’à trois jeux de modèles.
2. Sauvegarder de façon cohérente le stockage et la configuration du serveur existant.
   Ajouter la section `config/cluster-coordinator.example.toml` à sa configuration.
   Conserver le mode observation. Vérifier `check-config`, puis redémarrer le service.
3. Adapter le proxy HTTPS avec le bloc `/api/v1/cluster/v1/` de `deploy/nginx.conf`
   (requêtes de 4 Mio, téléchargement en flux), ou le nouvel exemple Caddy.
   Ne pas exposer le port API loopback. L’API conserve ses contrôles d’identité.
4. Ouvrir **Administration → Serveurs MX**, ajouter `mx2` et conserver son identité
   affichée une seule fois. Créer `/etc/noisefence/cluster`, propriétaire `noisefence`,
   mode 0700 ; installer l’identité dans `node.key`, même propriétaire, mode 0600.
   Ne pas mettre cette valeur dans Git, une URL ou la ligne de commande.
5. Sur mx2, utiliser une configuration locale neuve : hostname/TLS/ARC propres,
   répertoire de données vide, routes bootstrap explicites et **100 destinataires
   maximum par transaction**. Installer les services OCR/antivirus/signatures présents
   sur mx1. Ajouter `config/cluster-worker.example.toml`, avec l’URL réelle de mx1.
   L’API du worker n’expose que `/healthz` ; tous les utilisateurs emploient la console
   centrale. Ne pas y créer de comptes ni lancer un entraînement autonome.
6. Démarrer sans publier son MX. Vérifier dans « Serveurs MX » la connexion, l’absence
   d’incident, la révision et l’empreinte appliquées. Contrôler espace disque, crédits,
   files, logs, services de contenu et limites de concurrence sur chaque machine.
7. Envoyer les seuls messages de test autorisés directement à mx2. Vérifier STARTTLS,
   refus de relais ouvert, routes indépendantes des MX publics, réception Proton,
   dossiers d’arrivée, score/raisons, agrégation et droits entre utilisateurs.
   Refaire la validation Proton pour la nouvelle IP avant tout marquage.
8. Couper temporairement la liaison de coordination, vérifier réception/livraison
   locale, puis la remontée d’historique au retour. Tester aussi un arrêt de mx1.
   Publier ensuite seulement `10 mx1.example.org` et `20 mx2.example.org`.

Le changement DNS n’est pas réalisé par la console. Pour tourner une identité,
utiliser « Renouveler l’identité », remplacer le fichier privé sur le worker puis
redémarrer celui-ci. « Désactiver » coupe immédiatement ses accès de synchronisation
et annule ses commandes en attente ; le SMTP continue avec sa politique en cache
jusqu’à expiration. Pour le retirer immédiatement de la réception, retirer le MX et
arrêter son écoute SMTP tout en traitant le courrier déjà accepté.

## Stockage et retour arrière

L’activation du rôle marque le stockage en **schéma 3**. La version 0.14 sait ouvrir
les schémas précédents et ajoute les tables de cluster. Un stockage de cluster exige
son rôle et son identifiant d’origine : supprimer la section ou cloner une file vers
un nouveau worker est refusé. L’installateur refuse un retour automatique vers une
release ne supportant que le schéma 2. Ne jamais abaisser `user_version` à la main.

Avant réception sur le nouveau schéma, une restauration complète de la sauvegarde
précédente est possible. Après réception, conserver une release compatible, vider
les files et planifier une migration avec inventaire des messages. Restaurer une
ancienne sauvegarde de budget sur un nœud actif peut réutiliser des crédits déjà
consommés : arrêter/révoquer ce nœud et réconcilier les comptes avant toute reprise.
Ne jamais faire tourner deux machines avec la même identité ou la même file.

Les commandes CLI de consultation utilisent la dernière politique reçue. La
réinitialisation locale de console est refusée sur un worker. La relance CLI agit
sur la file locale ; la console est nécessaire pour envoyer une relance distante.

## Validation automatisée

`cargo test --locked --test cluster` couvre deux instances HTTP/SMTP loopback,
transfert et reprise d’un modèle, SMTP avant/après synchronisation, refus de relais,
historique sans transfert de corps, ACL et copies cachées, commandes idempotentes,
révocation, restauration de configuration, expiration, remplacement de modèle et
attribution concurrente des crédits. Ces tests synthétiques ne prouvent pas la
livraison Internet ni le classement Proton du futur mx2.
