# Console d’administration

La console et son API sont servies par NoiseFence. Se connecter avec un compte
créé avec `user-add nom --admin` pour accéder à l’administration. Aucun compte
par défaut, secret ou mot de passe n’est fourni dans le logiciel.

## Parcours

- **Messages** : historique de 30 jours, recherche par objet, expéditeur ou
  destinataire visible ; périmètre par domaine ; filtres spam, légitime, analyse
  incomplète et livraison en attente. Ouvrir un message pour ses raisons,
  détecteurs, destinataires autorisés et corrections Spam/Légitime.
- **Domaines** : nom DNS ASCII/punycode, activation, passerelle, acceptation de
  toutes les adresses ou liste explicite, alias vers une destination configurée.
  Un domaine sans passerelle peut servir uniquement à des alias. Un alias
  reste prioritaire sur la réception de toutes les adresses. Les chaînes et
  cycles d’alias sont refusés. Au moins un domaine doit rester actif.
- **Passerelles** : nom, serveurs prioritaires et de secours, port SMTP.
  Un suffixe `:port` sur un serveur remplace le port commun. TLS avec
  vérification du certificat est obligatoire vers les destinations publiques.
  Les hôtes de la passerelle elle-même, domaines protégés et destinations
  privées sont refusés (sauf le mode de test local explicitement configuré).
- **Filtres** : mode observation/marquage, seuil et activation des connecteurs
  installés. Le seuil d’un modèle multilingue est lié à sa calibration ; les
  secrets, modèles, ressources, budgets et tarifs restent gérés côté serveur.
  L’activation du marquage exige toujours une preuve Proton récente et ARC.
  Aucune nouvelle performance de détection n’est déduite de ces commandes.
- **Comptes & accès** : création, rôle, accès, désactivation et nouveau mot de
  passe. Un administrateur voit tous les domaines et peut modifier les réglages.
  Un utilisateur peut recevoir une adresse canonique ou `*@domaine`, sans droit
  d’administration. La modification révoque les sessions du compte concerné,
  y compris sa session courante. Les mots de passe ne sont jamais affichés.
- **État du serveur** : capacité configurée, espace libre, latence maximale de
  la dernière heure (pas un p95), compteurs et budget LLM lorsqu’il est activé,
  200 premières livraisons non résolues, 200 derniers événements d’audit et
  100 dernières révisions. « Réessayer » avance l’échéance d’une livraison
  temporaire ; ne remet pas en file une livraison terminée ou en cours.

## Ajouter un domaine

Créer d’abord sa passerelle de destination, puis associer le domaine. Les deux
modifications peuvent être appliquées ensemble. Pour accepter chaque boîte,
activer « Accepter toutes les adresses du domaine ». Configurer également le
domaine et les boîtes ou le catch-all chez le fournisseur de messagerie final.
Créer ensuite les accès utilisateur souhaités, par exemple `*@exemple.fr`.

« Vérifier et appliquer » présente les changements, puis applique une seule
révision validée. Si un autre administrateur a modifié la configuration, recharger
les réglages et refaire les modifications. Les DNS publics ne sont jamais
modifiés depuis la console. Valider la livraison de bout en bout avant de
modifier les MX. L’ajout d’un domaine à NoiseFence ne prouve pas sa compatibilité
avec Proton ni son acceptation par les serveurs de destination.

## Autorisations et confidentialité

Les contrôles sont effectués dans l’API et SQLite, pas seulement dans l’interface.
Un droit `*@domaine` couvre le domaine de l’adresse d’enveloppe ou de sa destination
canonique, sans inclure les sous-domaines. Les adresses contenant un `@` dans une
partie locale entre guillemets sont traitées avec leur dernier séparateur.
L’accès à un message ne dévoile pas ses autres destinataires cachés hors périmètre.
Une recherche par destinataire ne peut pas utiliser une adresse cachée pour faire
apparaître le message. Les mêmes règles revalident les corrections utilisées dans
les exports d’apprentissage. Un administrateur a accès à tous les destinataires.

Les mutations exigent une session active, une origine autorisée et un jeton CSRF.
Les modifications de comptes et de configuration revérifient les droits dans leur
transaction. Les mots de passe restent hachés en Argon2id. Les corps ne sont pas
exposés dans la console ; leur conservation suit la file et les règles existantes.
Les événements d’audit sont conservés 30 jours. Les 100 dernières configurations
peuvent contenir des noms de domaines et d’adresses, mais aucun secret de connecteur.

## Persistance, application et récupération

Le fichier TOML constitue la configuration initiale et porte les paramètres
infrastructure : écoute, certificats, clés, modèles, limites et budgets. Une fois
une révision enregistrée dans `state.sqlite3`, la console devient la source des
réglages de routage et filtrage qu’elle expose. Les outils CLI, y compris
`check-config`, consomment cette même politique enregistrée. Modifier ces champs
dans le TOML ne remplace pas une révision active. Modifier un modèle ou une
calibration exige de réconcilier les paramètres enregistrés avant redémarrage.

Une écriture SQLite durable précède le remplacement atomique de la configuration
en mémoire. La déconnexion du navigateur n’interrompt pas cette application.
Chaque transaction SMTP garde sa configuration du MAIL jusqu’à DATA. Les nouveaux
messages utilisent la nouvelle politique ; ceux déjà acceptés gardent leur route
persistée. Les limites globales d’analyse et les moteurs lourds sont partagés entre
révisions. Le modèle lexical chargé et son empreinte sont également conservés
avec le modèle multilingue : remplacer un fichier sur disque demande un
redémarrage, qui revalide leur calibration. Une nouvelle route ne redirige pas des messages déjà en file.

Pour revenir à une ancienne configuration, la charger depuis l’état du serveur,
l’examiner puis l’appliquer. La restauration est une nouvelle révision et passe
les validations actuelles. La configuration initiale peut aussi être chargée.

Si la révision empêche le démarrage, arrêter le service et restaurer la politique
du TOML, sans supprimer la file, les comptes ou l’historique :

```sh
sudo systemctl stop noisefence
sudo -u noisefence /opt/noisefence/noisefence --config /etc/noisefence/config.toml console-reset
sudo systemctl start noisefence
```

Sauvegarder la base et les données avant une mise à jour. Un retour vers un binaire
antérieur à cette console ignore les révisions et les droits par domaine ; il ne
comprend pas les nouvelles routes `hôte:port`. Pour revenir en arrière après des
changements de routage, préparer un TOML équivalent et traiter ces routes avant le
retour de version. Ne jamais remplacer une base contenant des messages acceptés
par une ancienne sauvegarde.

## Validation automatisée

`tests/console.rs` couvre les accès globaux/domaines/boîtes, BCC, alias, recherches,
statistiques, CSRF, révocation, compteurs de versions, refus des configurations
invalides, persistance, retour à une révision antérieure et changement de route
pendant une transaction SMTP. Les suites stockage, relais et apprentissage
contrôlent aussi les autorisations et la responsabilité de livraison existantes.
Les lectures de la console utilisent quatre connexions SQLite en lecture seule au maximum, interrompues après trois secondes de requête ; elles ne monopolisent pas le verrou d’écriture de la file. Les tests vérifient également cette isolation et les conflits entre deux administrateurs.
La compilation TypeScript, le lint et le build statique sont exécutés en CI.
