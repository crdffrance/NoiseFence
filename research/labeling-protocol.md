# Étiquetage et validation du filtrage

Ce protocole définit la cible commune du modèle local, de la combinaison des
signaux et des évaluations. Il ne transforme ni un score automatique ni un dossier
Proton en vérité d’entraînement.

## Étiquettes

| Étiquette | Critère | Exemples |
| --- | --- | --- |
| `legit` | Correspondance attendue ou consentie, sans tentative de tromperie connue | Échanges professionnels, factures, confirmation de commande, alerte de sécurité réelle, newsletter à laquelle le destinataire est abonné |
| `spam` | Sollicitation non désirée ou non consentie, sans preuve suffisante de phishing | Prospection non sollicitée, promotion répétitive, pourriel générique |
| `phishing` | Tromperie destinée à obtenir un secret, un paiement ou une action compromettante | Faux portail d’authentification, usurpation de fournisseur pour changer un RIB, fausse mise à jour piégée |
| `uncertain` | Contexte, consentement ou preuves insuffisants, ou annotateurs en désaccord | Newsletter dont l’abonnement est inconnu, message commercial dont le destinataire ne peut confirmer l’origine |

Une alerte de sécurité, une facture, un lien ou un vocabulaire urgent ne suffisent
pas à justifier `phishing`. Un échec SPF/DMARC ou une réputation indisponible ne
déterminent pas l’étiquette. Le consentement doit être connu pour distinguer une
newsletter légitime d’une sollicitation indésirable. Un message légitime signalé
comme indésirable par préférence personnelle conserve cette information séparée ;
elle ne devient pas automatiquement une règle globale pour tous les utilisateurs.

Le classifieur actuellement déployé est binaire : `spam` et `phishing` forment la
cible « indésirable ». Publier les rappels de ces deux sous-classes séparément
lorsque les annotations le permettent. Une ancienne étiquette binaire `spam` ne
prouve pas l’absence de phishing. La console « Spam / Légitime » produit un retour
binaire ; elle ne fournit pas à elle seule une annotation en trois classes.

Les cas `uncertain` restent dans un lot de révision, exclus de l’ajustement et des
métriques binaires. Conserver leur nombre et la raison de l’incertitude. Les labels
d’un corpus tiers sont des labels de source tant qu’ils ne sont pas revus. Un LLM
peut aider à prioriser les révisions ; il ne valide pas ses propres prédictions.

## Constitution du corpus récent

Conserver une provenance vérifiable pour chaque message : empreinte de l’original,
source, période de réception connue, autorisation d’usage, langue, type de message,
étiquette et mode d’annotation. La date de réception fiable ne se déduit pas du
champ `Date` fourni par l’expéditeur. Ne pas visiter les liens, charger les images
distantes ou exécuter les pièces jointes pendant l’annotation.

Échantillonner aussi les messages correctement classés. Un export composé
uniquement de corrections mesure les erreurs connues, pas la population du
serveur. Les notifications automatiques, listes de diffusion, transferts, factures
et échanges professionnels français doivent être présents dans le jeu légitime.
Les textes synthétiques sont une source d’augmentation ou un diagnostic distinct,
pas un substitut à ces messages réels.

Avant toute séparation, retirer les anciens en-têtes de filtres et regrouper les
doublons exacts et les variantes de campagne. Les chemins, labels, dossiers,
identifiants du corpus et explications des annotateurs restent hors des entrées du
détecteur. Toute campagne qui rejoint un jeu réservé doit être exclue des lots
d’ajustement. La similarité canonique/SimHash est une heuristique : compléter
l’audit par dates, domaines et familles de campagne lorsque ces données sont
fiables.

## Séparation des usages

1. **Entraînement des moteurs** : vocabulaire/IDF, coefficients lexicaux et tête
   sémantique apprennent sur ce lot uniquement.
2. **Développement** : choix limité et annoncé des variantes ; les résultats
   observés ne deviennent pas un test indépendant.
3. **Apprentissage de la combinaison** : utiliser les sorties de moteurs qui
   n’ont pas appris sur les campagnes correspondantes, par lot distinct ou
   prédictions hors pli regroupées par campagne. Ne pas apprendre la combinaison
   sur les prédictions d’entraînement des mêmes moteurs.
4. **Calibration des probabilités** : ajuster sur un lot distinct. La proportion
   d’indésirables de ce lot doit être documentée ; une probabilité calibrée sur un
   mélange artificiel 50/50 ne vaut pas automatiquement sur le trafic réel.
5. **Choix du seuil** : lot réservé distinct du test. Sélectionner un seuil commun
   sous la contrainte de faux positifs ; ne pas régler un seuil différent pour
   masquer les erreurs d’une langue ou d’une source.
6. **Test final gelé** : annoncer son périmètre et figer les artefacts avant de
   produire les prédictions. Tout test consulté devient un résultat historique ;
   le réutiliser pour sélectionner un autre candidat retire son indépendance.

La séparation historique 60/10/10/20 sert aux expériences de contenu existantes.
Elle ne fournit pas automatiquement les lots supplémentaires nécessaires à
l’apprentissage et à la calibration de la combinaison complète.

## Décision et preuves nécessaires

Comparer les couches avec la même contrainte de faux positifs : contenu seul,
contenu + authentification/politique SMTP, réputation, signatures, puis LLM.
Représenter explicitement les contrôles désactivés, non sollicités, complets et
indisponibles. Une erreur DNS ne doit pas être encodée comme un résultat « sain ».
Tester les pannes et la sélection conditionnelle du LLM, en conservant la règle de
transmission sans préfixe lorsque l’analyse est incomplète.

Pour chaque candidat, conserver les empreintes du code, des données et des modèles,
les versions des caractéristiques, règles, bases de signatures et prompts. Publier
effectifs, TP/FP/FN/TN, rappel, précision, taux de faux positifs et intervalles à
95 %, ainsi que les résultats par langue et catégorie légitime critique. Mesurer
la calibration séparément de la capacité de classement. Un indice de suspicion
95/100 ne signifie pas 95 % de probabilité sans cette validation.

Le test récent indépendant visé comprend au moins 10 000 légitimes et 2 000
indésirables. Le rappel visé est ≥ 95 %, avec taux de faux positifs ≤ 0,1 % et borne
supérieure de son intervalle à 95 % compatible avec cette limite. Publier les
intervalles même si ces objectifs échouent. Un petit lot sans faux positif ne
suffit pas ; les sous-groupes exigent eux aussi des effectifs interprétables.

Mesurer le pipeline complet sur la machine de référence (4 vCPU, 8 Go), avec p95
visé < 500 ms pour les messages ≤ 1 Mo et caches chauds. Les cas utilisant un LLM,
les incidents et les contrôles indisponibles doivent rester visibles dans les
mesures. Vérifier ensuite le dossier d’arrivée chez Proton séparément du score
NoiseFence, notamment après modification d’objet ou scellement ARC.

Références : [calibration des probabilités](https://scikit-learn.org/stable/modules/calibration.html),
[sélection du seuil](https://scikit-learn.org/stable/modules/classification_threshold.html),
[prédictions hors entraînement pour la combinaison](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.StackingClassifier.html).
