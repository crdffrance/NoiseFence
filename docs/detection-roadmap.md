# Renforcer NoiseFence : architecture et entraînement

Le but est une protection mesurée, pas un nombre maximal de moteurs. Le candidat
historique actuel détecte 60,94 % des spams de son test et n’est pas activé. Ajouter
un antivirus ou un LLM ne transforme pas ce résultat en une garantie de capture.
Chaque couche doit montrer son gain sur un jeu indépendant et son coût en erreurs,
latence, mémoire et appels externes.

## État de la version de développement

Implémentés : connecteurs de scan ClamAV sur sockets distinctes, stockage des
verdicts et affichage, classifieurs logistique et Bernoulli Bayes, client Scaleway
avec budget durable et validation JSON. Le test réel EICAR passe dans un conteneur
local ; les tests LLM utilisent un serveur HTTPS simulé, sans envoi à Scaleway.
Les guides [antivirus](antivirus.md) et [Scaleway](scaleway.md) décrivent l'activation.

La comparaison historique utilise les mêmes 4 659 exemples d'entraînement,
609 de validation et 606 de test. Bayes détecte 1 spam sur 192 (0,52 %), contre
117 sur 192 (60,94 %) pour la logistique ; aucun faux positif observé sur seulement
414 messages légitimes. Les deux candidats sont refusés. Ajouter Bayes ne constitue
donc pas un gain démontré ; il reste un point de comparaison expérimental.

Restent à réaliser : politique opérationnelle pour les fichiers malveillants,
installation et surveillance sur la cible, isolation et essais réels Scaleway,
corpus récent indépendant, calibration de la combinaison et mesures complètes.
La quarantaine, les arbres et l'encodeur multilingue ne sont pas implémentés.

## Chaîne de décision

1. **SMTP et authentification.** Destinataires explicites, limites, TLS, SPF,
   DKIM, DMARC et ARC sur l’original, file durable. Les erreurs de protocole,
   de ressources et les verdicts de contenu restent séparés.
2. **Antivirus local.** Envoyer le message à ClamAV par socket Unix avec INSTREAM.
   ClamAV décode MIME et les archives dans des limites de temps, taille et profondeur.
   FreshClam maintient les bases officielles. Aucune pièce jointe n’est exécutée.
3. **Signatures complémentaires.** Ajouter une sélection conservatrice de bases
   non officielles, avec vérification d’intégrité/signature et rechargement contrôlé.
   Une signature de spam/phishing ou une archive chiffrée ne constitue pas à elle
   seule la preuve d’un virus. Conserver le fournisseur et le nom du déclencheur.
4. **Analyse locale combinée.** Réputation IP/domaines, alignement des identités,
   règles MIME/HTML/liens, classifieurs textuels et structurels. Aucun téléchargement
   de lien, aucune exécution de script ou macro. Les indisponibilités sont visibles.
5. **LLM Scaleway sur les cas ambigus.** Projet et application IAM dédiés, clé limitée
   au projet, API compatible Chat Completions, sortie JSON à schéma fermé. Envoyer
   seulement un extrait textuel borné ; aucune pièce jointe binaire. Le message est
   une donnée hostile, jamais une instruction pour l’assistant. Pas d’outils ni de
   navigation accessibles au modèle. Un dépassement de délai, de budget ou une
   réponse invalide laisse la décision au pipeline local.
6. **Décision et traçabilité.** Conserver les résultats de chaque moteur, leurs
   versions, les raisons et les latences. Le LLM fournit un signal, pas une commande
   de livraison, de suppression ou de modification des permissions.

Les politiques antivirus et le plafond LLM sont des paramètres opérateur explicites.
La quarantaine de fichiers malveillants, si activée, sera distincte du classement
antispam. Les signatures non officielles à fort taux de faux positifs ne doivent pas
provoquer automatiquement la rétention d’un message légitime.

## Jeu de données

- Utiliser SpamAssassin historique uniquement pour le démarrage et les régressions.
  Ajouter des exemples récents autorisés, en français et dans les langues réellement
  reçues : échanges métier, factures, notifications, listes, transferts, phishing,
  usurpation, spam commercial et messages avec pièces jointes.
- Les corrections d’un utilisateur ne portent que sur ses destinataires. Conserver
  leur provenance ; exclure les contradictions et plafonner l’influence d’un compte
  ou d’une campagne. Un retour ne modifie jamais directement le modèle actif.
- Retirer anciens scores, dossiers, marqueurs de corpus et en-têtes des filtres.
  Regrouper doublons exacts et variantes de campagne avant la séparation. Garder
  domaines, langues et dates pour contrôler les effets de fuite et la dérive.
- Pour une évaluation représentative, viser au moins 10 000 messages légitimes et
  2 000 spams indépendants dans le test final. Ce volume ne garantit pas que les
  sous-groupes soient assez grands ; publier leurs effectifs et intervalles.
- Les corps livrés sont supprimés du spool. Constituer un corpus brut distinct
  uniquement avec des messages autorisés pour l’entraînement et une conservation
  explicite. Les caractéristiques hachées ne rendent pas les messages anonymes.

## Comparaison des modèles

Construire d’abord une référence reproductible : régression logistique L2 sur TF-IDF
et structure, puis modèle bayésien sur les mêmes données. Comparer ensuite un modèle
d’arbres sur les signaux structurés et, si le gain le justifie, un encodeur multilingue
local. Les modèles volumineux doivent justifier leur mémoire et leur latence sur
4 vCPU / 8 Go. La sortie LLM peut être une caractéristique du modèle de combinaison ;
elle ne doit pas servir seule de vérité d’entraînement.

Séparer quatre usages : entraînement des modèles de base, ajustement de la
combinaison, calibration des seuils, puis test gelé. Lorsque les dates sont connues,
le test contient des campagnes plus récentes que l’entraînement. Les groupes de
campagne ne traversent aucune partition. Si le corpus ne permet pas cela, signaler
explicitement la limite et refuser une conclusion de qualité de production.

Publier pour chaque candidat rappel, faux positifs, précision, PR-AUC, calibration,
intervalles de confiance et résultats par langue/type de message. Comparer les
ablatifs : local seul, local + réputation, local + antivirus/signatures, puis ajout
du LLM. Mesurer aussi la part de messages qui consultent Scaleway et son coût réel.

## Conditions d’activation

- Objectif de capture : au moins 95 % sur le test indépendant ; publier aussi
  l’intervalle de confiance, sans présenter l’objectif comme déjà atteint.
- Faux positifs : au plus 0,1 %, avec borne supérieure de l’intervalle à 95 %
  compatible avec cet objectif. Un test minuscule avec zéro erreur ne suffit pas.
- Mesurer le pipeline complet, pas seulement le score textuel. Aucun moteur ne doit
  dégrader sensiblement une catégorie légitime critique sans correction préalable.
- Viser p95 inférieur à 500 ms sur messages jusqu’à 1 Mo avec caches chauds ; publier
  séparément les cas antivirus coûteux, les appels LLM et les analyses incomplètes.
- Versionner modèle, schéma de caractéristiques, règles, signatures et prompt LLM.
  Activer un candidat validé d’abord en observation puis progressivement. Garder
  le modèle précédent et une procédure de retour arrière.
- La compatibilité Proton reste un jalon distinct. Les premiers essais directs et
  relayés arrivent en spam ; ils ne valident ni la modification de Subject ni ARC.

## Exploitation et isolation

ClamAV utilise une socket Unix locale, pas un port public sans authentification.
Les accès utilisateurs passent par HTTPS et SMTP STARTTLS. Les clés Scaleway restent
dans les secrets du serveur ; le dépôt contient seulement des exemples. Le projet
Scaleway, l’application IAM et la clé doivent être propres à NoiseFence, avec le
minimum de permissions pour appeler les modèles choisis. Aucune instance GPU
permanente n’est nécessaire pour commencer avec les API serverless.

Le budget mensuel doit être suivi durablement et réservé avant chaque requête afin
que les appels concurrents ne dépassent pas le plafond. Compter aussi les requêtes
interrompues dont la facturation est incertaine. Une limite locale ne remplace pas
les contrôles et les alertes de facturation du fournisseur.

Références : [ClamAV et son protocole de scan](https://docs.clamav.net/manual/Usage/Scanning.html),
[bases officielles](https://docs.clamav.net/manual/Usage/SignatureManagement.html),
[Scaleway Generative APIs](https://www.scaleway.com/en/docs/generative-apis/api-cli/using-generative-apis/).
