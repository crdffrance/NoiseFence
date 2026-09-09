# Actions et quarantaine

Depuis **0.4.0-dev.1**, le classement et le traitement sont séparés. Dans
**Filtres → Actions après détection**, l’administrateur choisit pour les catégories
**Malware confirmé**, **Spam** et **PUB** :

| Action | Traitement |
| --- | --- |
| Transmettre sans préfixe | Enregistrer l’analyse puis relayer le message |
| Tagger et transmettre | Ajouter `[SPAM]` ou `[PUB]`, puis relayer ; validation Proton et ARC obligatoire |
| Placer en quarantaine | Accepter durablement, retenir chaque livraison, permettre une libération ou une suppression |

Le mode **Observation** transmet tous les messages sans préfixe, même lorsqu’une
action de quarantaine est prévue. Le mode **Actif — appliquer les actions**
(`filter.mode = "enforce"`) applique les actions enregistrées. L’ancien mode
`tag` reste accepté avec les mêmes actions ; il est conservé pour les installations
existantes. Sans configuration `[actions]`, le comportement historique est préservé.
Une mise à jour du logiciel n’active ni le marquage ni la quarantaine.

La quarantaine ne modifie pas l’objet et peut être activée sans rapport de
compatibilité de préfixe Proton. Le marquage conserve ses validations existantes,
y compris le rapport propre au préfixe `[PUB]`. La priorité est : malware du
scanner principal, décision spam, publicité légitime, autres messages.
Une analyse incomplète transmet sans préfixe, sauf si un malware du scanner
principal est confirmé et son action est explicitement **Quarantaine**.
Les messages **À vérifier** sont transmis sans préfixe. Un résultat consultatif
ne remplace pas à lui seul la décision du moteur.

## Gérer les messages retenus

Ouvrir **Messages → Quarantaine**, puis un message. Pour chaque destinataire
autorisé, la console présente la date d’expiration et deux commandes :

- **Libérer et transmettre** : remettre ce destinataire dans la file normale,
  sans préfixe ajouté lors de la libération. La route et l’expéditeur d’enveloppe
  d’origine sont conservés. Le délai de réessai SMTP recommence à la libération.
- **Supprimer** : terminer définitivement cette livraison sans l’envoyer.

La confirmation affichée nomme le destinataire concerné. Une action ne touche pas
les copies cachées hors périmètre. Session, CSRF, origine et droits sur le
destinataire sont vérifiés côté serveur ; la transaction revérifie les droits et
la validité de la session. Une seconde libération ou une action sur un message
expiré est refusée. Le rôle administrateur couvre tous les destinataires.

Une correction **Spam / PUB / Légitime** alimente les retours de classification ;
elle ne libère pas une quarantaine et ne change pas une livraison déjà terminée.
Une libération n’efface pas la détection, notamment celle de malware. Les corps,
HTML et pièces jointes ne sont pas exposés dans la console.

La conservation est réglable de **1 à 30 jours** (14 par défaut). L’échéance est
fixée à l’acceptation ; modifier les réglages n’affecte pas les messages déjà
retenus. À expiration, le nettoyage périodique marque la livraison **expirée**,
sans envoi ni notification de non-livraison. La suppression manuelle et l’expiration
sont des décisions de la politique de quarantaine, distinctes des échecs SMTP.
L’expiration peut être enregistrée quelques minutes après l’échéance ; aucune
libération n’est permise après celle-ci.

Le corps reste dans le spool privé tant qu’un destinataire est en attente,
en cours, en échec non résolu ou en quarantaine. Il est supprimé une fois tous
les destinataires résolus. Les messages encore conservés restent consultables
dans l’historique même au-delà de 30 jours, par exemple après une libération
tardive suivie de réessais. Les métadonnées résolues et l’audit suivent la
conservation de 30 jours. Surveiller `quarantined_deliveries` et l’espace disque.

## Personnaliser les filtres

Les connecteurs, la confirmation du spam, les options de réputation, d’OCR,
d’usurpation et les catégories de mailing restent configurables dans **Filtres**.
Le panneau **Règles heuristiques personnalisées** ajoute huit contributions
réglables : urgence, demande d’identifiants, promesse financière, formulaire HTML,
lien IDN, lien vers une IP, domaine de réponse différent et objet en majuscules.

Chaque poids est compris entre 0 et 3. Il est ajouté à l’indice avant sa conversion
en score ; ce n’est pas un nombre de points de pourcentage. Zéro neutralise la
contribution explicite de la règle. Les observations et caractéristiques des
modèles sont conservées ; le modèle peut toujours reconnaître ces éléments.
Le bouton de restauration supprime les surcharges et reprend les poids par défaut.
La confirmation reste active selon son réglage, la priorité antivirus est intacte
et une fusion validée conserve sa propre décision. Le seuil multilingue demeure
lié à la calibration du modèle. Une modification de poids demande une évaluation
des faux positifs et du rappel sur des messages indépendants.

Exemple de configuration initiale (la console prend ensuite priorité) :

```toml
[actions]
spam = "quarantine"
publicity = "deliver"
malware = "quarantine"
quarantine_days = 14

[filter]
mode = "observe" # passer à "enforce" pour appliquer les actions
threshold = 95.0
require_corroboration = true

[filter.rule_weights]
urgency = 0.0
financial_lure = 1.5
```

Les réglages sont validés et versionnés comme les autres paramètres de la console.
Les transactions SMTP en cours conservent leur politique jusqu’à la fin de DATA.
Les messages acceptés conservent leur action, leur échéance et leur route.

## Migration de stockage

L’ouverture de la base migre atomiquement son schéma de 1 vers **2**, sans
modifier les messages ni les états historiques. La table `delivery_policy`
enregistre l’action, l’échéance de quarantaine et l’instant de libération par
livraison. Le fichier `.eml` reste unique par message. `250` n’est envoyé qu’après
la persistance du fichier, du répertoire et de la transaction complète.

Les versions 0.3 refusent une base de schéma 2. Ce verrou empêche leur ancien
nettoyage de supprimer les corps en quarantaine. **Ne jamais diminuer manuellement
`PRAGMA user_version`.** Après migration, conserver un binaire compatible pour une
correction. Un retour vers 0.3 exige une restauration cohérente de la sauvegarde
de base, spool et configuration prise à l’arrêt, et une réconciliation des messages
acceptés depuis : une restauration aveugle peut perdre des messages.

Les archives déclarent `storage_schema` dans `build.json`. L’installateur nécessite
Python 3.11+ et refuse son retour automatique à un binaire incompatible, après
avoir arrêté le candidat pour éviter une migration concurrente.
