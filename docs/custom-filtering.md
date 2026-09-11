# Règles, profils et invitations (0.4.9)

Dans **Administration → Filtres → Règles & profils**, créez des profils puis
leurs affectations. Le bouton d’application général enregistre une révision
atomique ; le brouillon et sa simulation ne changent pas les messages reçus.
Les réglages ne sont pas rétroactifs.

## Portées et niveaux

`*` désigne l’organisation, `*@exemple.fr` un domaine configuré et une adresse
complète un destinataire accepté. Priorité des affectations : adresse SMTP
initiale, destination de l’alias, domaine initial, domaine de destination,
organisation. Une seule affectation est autorisée pour chaque portée.
Un profil sans affectation n’a aucun effet.

Un profil définit les actions Spam, Publicité et À examiner, la durée de
quarantaine (1 à 30 jours), la corroboration et un seuil hérité ou personnalisé.
Les préréglages de seuil sont prudent (98), équilibré (95), strict (90).
Ces indices ne sont pas des probabilités et ces noms ne garantissent aucun taux
de capture. Le seuil du modèle multilingue ou d’une fusion active reste verrouillé.
Une corroboration exigée globalement ne peut pas être désactivée par un profil.

Les règles s’appliquent ensuite, par priorité croissante et identifiant stable
pour départager les égalités. Elles combinent 1 à 8 conditions avec ET ou OU.
Une règle suivante peut remplacer un effet précédent ; « Arrêter » empêche cela.
Une expiration est exclusive et exprimée en UTC. Limites : 100 règles, 32 profils,
1 000 affectations. Les valeurs sont des littéraux de 256 octets au maximum,
insensibles à la casse, sans expression régulière ni code exécutable.

Les conditions portent sur l’enveloppe, From, l’objet décodé, le texte MIME,
le destinataire, la taille, l’indice original, la catégorie originale, un signal
ou DMARC. L’expéditeur SMTP et From peuvent être falsifiés : une exception large
fondée uniquement sur ces champs est déconseillée. Pour une exception, combinez
les preuves nécessaires et utilisez une portée limitée.

Une donnée absente parce qu’un contrôle n’a pas été réalisé est **inconnue**,
y compris pour l’opérateur « Est absent ». Les corps dépassant les limites
MIME/texte ou les messages HTML sans partie texte ne sont pas évalués par les
conditions de texte. Le moteur de détection HTML existant continue à fonctionner.
La simulation utilise seulement les faits saisis : aucun contrôle distant,
aucune livraison et aucun entraînement. Elle ne mesure pas la précision.

## Priorités et livraison

Une détection de malware par l’antivirus principal conserve la catégorie Spam
et l’action antivirus générale. L’observation force la transmission ; une analyse
incomplète empêche le marquage et les actions personnalisées, sauf la quarantaine
d’un malware confirmé prévue par la politique globale. Les règles explicites
peuvent changer une catégorie sans altérer les preuves ni les scores originaux.
Les préfixes restent soumis à la validation Proton, à l’authentification et à ARC.

Les contrôles de contenu et réseau sont exécutés une fois. Les conditions communes
sont réutilisées par les destinataires ; chaque livraison conserve sa propre
évaluation. Jusqu’à six variantes de catégorie/préfixe peuvent être nécessaires.
Leurs fichiers sont synchronisés sur disque avant une transaction SQLite unique,
puis seulement le serveur répond 250. Une erreur ne laisse aucun sous-ensemble
accepté. Les doublons SMTP après perte de la réponse finale restent possibles.

Le corps original reste identique dans chaque variante. Les variantes apparaissent
comme des entrées distinctes dans l’historique ; le `transaction_id` commun est
conservé dans les métadonnées. Les statistiques de console comptent les variantes,
pas exclusivement les transactions SMTP. Les campagnes d’entraînement restent
dédupliquées par leurs empreintes originales. Une évaluation par destinataire
contient le profil, les règles déclenchées, l’action demandée/appliquée et
l’empreinte de la politique, sans corps ni valeurs des conditions. Les ACL filtrent
ces évaluations, y compris pour les copies cachées.

## Inviter un utilisateur

Dans **Administration → Comptes & accès → Inviter un utilisateur**, choisissez
un identifiant neuf, ses adresses/domaines, son rôle et une validité de 1 à 7 jours.
Copiez le lien affiché une seule fois et partagez-le avec la personne concernée.
Aucun email n’est envoyé automatiquement. Un nouveau lien pour le même identifiant
révoque les précédents. La liste permet aussi une révocation immédiate.

Le destinataire voit ses accès, choisit et confirme son mot de passe (12 à 128
octets), puis utilise la connexion normale. Le compte n’est créé qu’à l’activation.
L’invitation ne réinitialise jamais un compte existant. Seul un administrateur
peut inviter ; les droits du créateur et les accès configurés sont revérifiés
à l’activation. Modifier le compte du créateur invalide ses invitations en attente.

Le jeton aléatoire de 256 bits est haché dans SQLite, à usage unique et expirant.
Il est transmis dans un fragment d’URL, retiré immédiatement de la barre d’adresse,
puis conservé seulement en mémoire. Les protections Origin, CSRF administrateur,
limitation de fréquence et Argon2id s’appliquent. Ces choix reprennent les principes
de gestion de jetons de l’[OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).
Les invitations expirées sont supprimées après 30 jours ; les actions sont auditées.

## Mise à niveau et retour arrière

Les nouvelles tables sont additives au schéma 2. Les révisions existantes sont
inchangées et `custom_filtering` est absent tant qu’aucune règle n’est enregistrée.
Le mode observation et les réglages existants sont conservés au déploiement.

Le binaire 0.4.8 sait livrer les variantes standards déjà en file. Si une politique
personnalisée a été enregistrée, **avant** de revenir à ce binaire, désactivez-la
par une nouvelle révision de configuration contenant `custom_filtering: null`
puis vérifiez que le champ a été omis dans la révision sérialisée. L’API accepte
ce retrait ; l’historique des anciennes révisions reste conservé. Contrôlez aussi
les validations de marquage de la politique générale. Ne restaurez jamais une
ancienne base de données : elle pourrait perdre des messages acceptés depuis.
