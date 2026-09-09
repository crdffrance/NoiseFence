# Cohérence des décisions

Depuis 0.3.0-dev.22, `decision-policy-1` résout le classement après le score
historique, la fusion éventuelle et les observations des contrôles. Le résultat
stocké pilote la catégorie, la console, les compteurs et les en-têtes SMTP.
Le classement, l’exhaustivité des contrôles et la modification de l’objet sont
trois informations distinctes.

| Situation | Classement | Préfixe possible |
| --- | --- | --- |
| Malware reconnu par l’antivirus principal | Spam, motif antivirus prioritaire | `[SPAM]` si analyse complète et marquage autorisé |
| Même détection, autre contrôle incomplet | Spam, avec analyse incomplète | Aucun |
| Score élevé corroboré, sans malware | Spam | `[SPAM]` si marquage autorisé |
| Score élevé non corroboré, option de confirmation active | À vérifier | Aucun |
| Décision légitime et promotion/newsletter reconnue | PUB | `[PUB]` si marquage autorisé |
| Décision légitime, sans publicité reconnue | Légitime | Aucun |
| Analyse incomplète sans détection de malware reconnue | Indéterminé | Aucun |

La priorité antivirus ne s’applique qu’au statut `malware` du **scanner principal**.
Le connecteur distingue déjà les signatures officielles, les préfixes non
officiels explicitement approuvés, les heuristiques, PUA, contenus non analysables
et erreurs. Les résultats consultatifs, le scanner complémentaire, CRDF et
VirusTotal en observation ne reçoivent pas cette priorité. Une signature peut
être erronée : sa provenance et le retour humain restent nécessaires au suivi.
Le résultat `clean` ne constitue pas une autorisation générale et n’annule aucun
autre signal. La distinction PUA suit la [documentation ClamAV](https://docs.clamav.net/faq/faq-pua.html).

Pour cette décision, `decision.source = antivirus`, `outcome = unwanted` et
`score = null`. Aucun poids artificiel ne force l’indice à 100. L’indice de suspicion
historique reste dans `scan.score`, les caractéristiques restent intactes, et le
motif `malware_priority` explique la priorité. Le résultat de fusion reste
consultable séparément. Un LLM favorable, un score faible ou une newsletter ne
peuvent effacer une détection de malware du scanner principal. L’indice historique
combine le contenu et les signaux consultatifs actifs ; ce n’est pas un score
exclusivement textuel.

Un échec ultérieur ne supprime pas les contrôles déjà réussis. `complete = false`
interdit toujours la modification de l’objet, même pour un malware détecté.
Un tel message apparaît dans les filtres **Spam** et **Analyse incomplète** ;
ce second filtre décrit l’état des contrôles, pas une catégorie concurrente.
Aucune quarantaine, suppression ou réponse SMTP de rejet n’est ajoutée.
Les validations Proton et ARC restent requises pour le marquage.

## Signaux consultatifs

L’avis du LLM emploie une seule fonction pour sa contribution au score et sa
confirmation : résultat terminé et validé, spam/phishing avec confiance et
probabilité déclarées ≥ 0,9, poids +1,5 ; légitime avec confiance ≥ 0,95 et
probabilité ≤ 0,1, poids −0,5. Un avis périmé associé à une erreur, un nombre hors
bornes ou un avis ambigu ne contribue pas. Ces nombres déclarés ne sont pas
des probabilités calibrées. Aucun nouvel appel externe n’est déclenché.

ZEN 2/3/4/9 garde la contribution de réputation existante (+4, une seule fois
par IP). PBL 10/11 et BCL 30 sont conservés avec un poids nul et ne corroborent
pas le score. Les listes PBL décrivent une politique d’émission ; BCL est
distinct de SBL/XBL. Une réponse mélangée à un code d’erreur reste indisponible.
Scoring et confirmation partagent cette interprétation de la
[table des zones Spamhaus](https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/040-zones.html).

L’application répétée de la confirmation conserve son explication et ne cumule
pas les raisons. Les sources corrélées ne deviennent pas de nouveaux votes parce
qu’elles sont affichées dans plusieurs panneaux. Les poids appris et les seuils
de production ne changent pas dans cette version.

## Validation et compatibilité

Les tests couvrent les désaccords antivirus/LLM/fusion/PUB, seuils bas et hauts,
pannes des scanners, modes observation/marquage, préfixes exclusifs, corps
inchangés, en-têtes falsifiés, persistance et droits de console. Les matrices
synthétiques vérifient des invariants logiciels ; elles ne mesurent pas un taux
de capture ni des faux positifs sur du trafic indépendant récent.

`audit-confirmation` ajoute `with_decision_policy` pour comparer aussi la priorité
antivirus sur les observations historiques admissibles. Cet audit ne rejoue ni
les requêtes DQS ni le prompt LLM ni les poids du score. Il ne réécrit aucune
décision historique. Les analyses incomplètes et fusions sont comptées à part.

La nouvelle valeur de source `antivirus` nécessite dev.21 ou plus récent pour
lire les nouvelles décisions. Après réception de telles décisions, ne pas revenir
à un ancien binaire qui ne connaît pas cette valeur ; conserver la base et déployer
une correction compatible. Le retour aux anciens MX reste possible. L’empreinte
de politique inclut cette résolution : une fusion activée doit être validée avec
les artefacts et la politique exacts de cette version.
