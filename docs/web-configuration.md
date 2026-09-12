# Configurer la messagerie depuis le Web

Depuis la version 0.13.0, **Filtres** regroupe les politiques, niveaux, actions,
poids, règles, fournisseurs et paramètres des moteurs. Les domaines, adresses,
alias et relais restent dans **Domaines** et **Passerelles**.

## Administration

- **Réputation IP · RBL** : ajouter, modifier, désactiver et supprimer des listes ;
  définir les codes exacts, la prise en charge IPv6, le nombre de fournisseurs
  indépendants, le délai, la concurrence, le cache et l’action SMTP.
  Les ajouts sont désactivés initialement. Les préréglages sont des raccourcis de
  saisie, pas une autorisation d’usage. Vérifier les conditions du fournisseur.
- **Tester ce brouillon** : recherches DNS sur l’IP saisie, pour les listes IP
  activées du brouillon. Aucun email n’est envoyé, aucun réglage n’est appliqué.
  Ce test ne teste pas le connecteur Spamhaus DQS intégré ni les listes de domaines
  URIBL. Une erreur, une réponse inconnue ou un délai dépassé reste indisponible.
- **Moteurs de détection** : activer les connecteurs installés, l’authentification
  et les contributions expérimentales. Le connecteur Spamhaus DQS s’active ici
  après enregistrement d’une clé autorisée.
- **Paramètres avancés** : limites d’analyse ; modèle/projet Scaleway, sélection
  des scores, budget, prix vérifiés, texte envoyé, sortie, délais et concurrence ;
  limites OCR/images/PDF/QR ; politique DNS/SMTP ; réputation CRDF/VirusTotal et
  redirections ; règles HTML/MIME natives, motifs, composites et plafonds.
  Les prix et budgets sont présentés en euros. Le serveur conserve ses unités
  entières en micro-euros. La vérification tarifaire n’est pas renouvelée
  automatiquement : renseigner la date réelle de vérification.
- **Protection avancée** : clés CRDF/VirusTotal, quotas, identités protégées,
  exceptions et activation du suivi des liens. Un quota nul signifie illimité.
- **Préférences des utilisateurs** : autoriser la personnalisation, borner les
  seuils et le nombre de règles, sélectionner les actions permises et consulter
  ou supprimer les préférences existantes.

Les réglages natifs sont consultatifs. Les modèles entraînés et la calibration
continuent à suivre la procédure de validation existante ; l’éditeur ne permet
pas de remplacer un modèle par un chemin arbitraire. Les motifs associés à un
modèle adaptatif sont liés à son protocole et ne peuvent pas être modifiés sans
revalidation. Les limites système, ports d’écoute, certificats et stockage
restent administrés sur le serveur.

## Clés et changements

Les clés Scaleway et Spamhaus sont saisies dans **Paramètres avancés**. Le serveur
les stocke dans `data_dir/credentials/` avec un répertoire 0700 et des fichiers
0600, écrits puis synchronisés avant renommage. Une clé enregistrée par le Web
prévaut sur la variable d’environnement du même fournisseur. Seul son état de
configuration est exposé. Son contenu n’entre ni dans les révisions, ni dans
l’audit, ni dans l’export. La rotation recharge la configuration courante ; elle
n’applique pas le brouillon de filtres et n’active pas un fournisseur désactivé.
Si le rechargement échoue, la réponse indique que la clé est enregistrée mais
qu’une réapplication est nécessaire. Sauvegarder également le répertoire privé
des clés ; sa rotation est distincte de la restauration d’une révision.

Un fournisseur RBL personnalisé peut réutiliser une référence de clé déjà
configurée sur le serveur uniquement pour sa zone et son fournisseur d’origine.
Il ne peut pas obtenir une variable d’environnement arbitraire via les requêtes
DNS. Spamhaus DQS possède son propre connecteur IP et domaines, avec traitement
spécifique des codes ; ne pas dupliquer ZEN avec SBL/XBL/PBL dans les listes IP.

**Enregistrer** affiche les modifications à examiner avant application.
L’import d’un export JSON prépare un brouillon validé côté serveur. L’export
contient les réglages et préférences de messagerie, sans secrets. Les blocs JSON
avancés nécessitent leur validation explicite avant l’enregistrement global.
Un conflit de révision demande un rechargement et ne remplace jamais silencieusement
une modification concurrente. Les 100 dernières révisions restent consultables.

Les nouvelles transactions SMTP utilisent un instantané cohérent : une modification
entre MAIL et DATA ne change pas les contrôles du message en cours. Les files et
messages déjà acceptés ne sont pas retraités. Les instances des moteurs partagent
leurs limites de concurrence pendant les changements. Baisser une limite attend
la fin du travail déjà admis ; la modification ne l’annule pas. Les budgets
persistants ne sont pas remis à zéro par un changement de configuration.

## Mes filtres

Tout utilisateur connecté peut ouvrir **Mes filtres** pour une adresse autorisée.
Un droit `*@domaine` permet aussi une préférence de domaine et des préférences
pour ses boîtes. Un droit sur une seule boîte n’accorde pas la gestion du domaine.
Les permissions sont revérifiées dans la transaction d’enregistrement, avec la
validité de la session. Les noms de boîtes conservent leur casse.

Une préférence appartient à la **boîte ou au domaine**, pas au compte qui l’a
créée : les comptes autorisés sur une boîte partagée gèrent la même préférence.
Révoquer un compte retire son accès sans effacer les réglages de la boîte.
Les destinataires et règles des autres portées ne sont pas renvoyés par l’API.

Chaque portée peut définir un seuil, une action pour Spam/PUB/À vérifier,
une durée de quarantaine et jusqu’à 20 règles à 1–8 conditions. Les champs
comprennent expéditeur, From, objet, texte MIME, destinataire, taille, score,
catégorie initiale, signal et DMARC. Les comparaisons sont bornées : pas de code
ni de regex utilisateur. Une règle peut expirer.

L’ordre de sélection est : adresse SMTP originale, destination canonique de
l’alias, domaine original, domaine de destination. Une préférence exacte remplace
celle du domaine ; son seuil peut hériter des profils administrateur. Supprimer
la préférence rétablit l’héritage. Les règles personnelles s’exécutent d’abord,
les règles administrateur ensuite ; une règle personnelle ne peut pas arrêter
les règles globales. L’antivirus, les protections pour analyse incomplète et le
mode Observation restent prioritaires. Le marquage personnel exige lui aussi les
validations Proton et ARC. En observation, les décisions sont consignées mais les
messages sont transmis sans marquage ni quarantaine.

## Mise à niveau et retour arrière

Les révisions antérieures héritent des paramètres de moteurs et RBL du fichier
serveur. Une liste RBL explicitement vide désactive les listes personnalisées ;
elle n’est pas remplacée par les valeurs du fichier au redémarrage. Aucune
préférence personnelle n’est créée lors de la mise à niveau et aucune action
n’est activée automatiquement.

Le schéma de file reste 2. **Un ancien binaire ne comprend pas une révision contenant
les nouveaux champs.** Avant de redescendre sous 0.13.0, utiliser cette version
pour examiner les préférences, arrêter brièvement la réception, sauvegarder
l’état courant et convertir uniquement la configuration de console vers l’ancien
format, ou revenir à une révision antérieure dépourvue de ces champs. Ne pas
restaurer une ancienne copie de la base complète : elle ferait perdre les messages
acceptés depuis la sauvegarde. La nouvelle couche de paramètres doit être reportée
dans le fichier de l’ancienne version si l’on veut la conserver. Désactiver une
référence `NOISEFENCE_WEB_DQS` avant retour arrière et remettre les variables de
clés attendues par l’ancien binaire. Les messages et états de livraison restent
compatibles ; conserver la file courante.
