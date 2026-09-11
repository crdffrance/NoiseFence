# Cohérence des décisions

Depuis 0.4.11, `decision-policy-2` résout le classement après le score
historique, la fusion éventuelle et les observations des contrôles. Le résultat
stocké pilote la catégorie, la console, les compteurs et les en-têtes SMTP.
Le classement, l’exhaustivité des contrôles et la modification de l’objet sont
trois informations distinctes.

| Situation | Classement | Préfixe possible |
| --- | --- | --- |
| Malware reconnu par l’antivirus principal | Spam, motif antivirus prioritaire | `[SPAM]` si analyse complète et marquage autorisé |
| Même détection, autre contrôle incomplet | Spam, avec analyse incomplète | Aucun |
| Score élevé corroboré, sans malware ni second avis contradictoire | Spam | `[SPAM]` si marquage autorisé |
| Désaccord explicite entre classement historique et second avis, sans malware | À vérifier | Aucun |
| Second avis ambigu sans score élevé corroboré | À vérifier | Aucun |
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
Depuis 0.4, les [actions configurables](actions.md) peuvent retenir un message en quarantaine. La détection de malware confirmée reste admissible à cette action même si un autre contrôle échoue. Les autres analyses incomplètes transmettent sans préfixe ; aucune réponse SMTP de rejet n’est fondée sur le score.
Les validations Proton et ARC restent requises pour le marquage.

## Signaux consultatifs

L’avis du LLM emploie une fonction commune pour sa contribution au score : résultat terminé et validé, spam/phishing avec confiance et
probabilité déclarées ≥ 0,9, poids +1,5 ; légitime avec confiance ≥ 0,95 et
probabilité ≤ 0,1, poids −0,5. Un avis périmé associé à une erreur, un nombre hors
bornes ou un avis ambigu ne contribue pas. Ces nombres déclarés ne sont pas
des probabilités calibrées. L’arbitrage réutilise le résultat enregistré sans
déclencher de nouvel appel externe. Le LLM ne corrobore jamais sa propre
contribution au score.

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

## Arbitrage du second avis

Pour une analyse complète dont la décision est historique (`legacy`), un avis
terminé et valide est comparé à cette décision. L’avis est déterminé seulement
si sa confiance déclarée est ≥ 0,5 et sa catégorie cohérente avec le côté de 0,5
de sa probabilité déclarée : légitime en dessous, spam/phishing au-dessus.
À la frontière, avec une confiance moindre, une contradiction interne ou une
catégorie ambiguë, il est indéterminé. Ces bornes assurent la cohérence de la
réponse ; elles ne constituent pas une calibration statistique.

Un désaccord explicite dans l’un ou l’autre sens donne **À vérifier**, même avec
une réputation défavorable. Un avis indéterminé donne aussi À vérifier, sauf si
le score élevé possède une corroboration de transport/réputation admissible.
Un accord conserve le classement sous réserve de l’option de confirmation ;
le score historique incluant déjà le poids LLM, cet accord n’est pas une preuve
indépendante. Les analyses incomplètes, avis absents, non sélectionnés, invalides
ou indisponibles ne sont pas transformés en avis favorables. La fusion validée
conserve sa politique et l’antivirus principal conserve sa priorité.

L’abstention d’arbitrage a `decision.score = null`. Le score brut, les observations
et caractéristiques restent disponibles. Le rapport additif `arbitration`
conserve la décision d’entrée, le second avis, la résolution et la décision finale.
La console les distingue. Les profils de sensibilité réappliquent cet arbitrage
avec leur seuil ; les règles explicites d’un administrateur restent des choix de
politique et non des observations du moteur. Les décisions déjà enregistrées ne
sont pas réécrites.

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
`with_arbitration` compare l’arbitrage seul sans activer la corroboration optionnelle.
`recent` donne les transitions sur au plus 100 messages récents, sans identité,
objet, texte ni vecteur. Ce sont des simulations sur observations enregistrées,
pas un taux de capture mesuré. Les spams détectés, manqués et à vérifier ainsi que
les légitimes, faux positifs et légitimes à vérifier sont comptés séparément.
Le champ additif est lisible après retour à 0.4.10 ; aucune migration SQLite n’est
nécessaire. Les artefacts de fusion doivent toujours correspondre à la politique.

La nouvelle valeur de source `antivirus` nécessite dev.21 ou plus récent pour
lire les nouvelles décisions. Après réception de telles décisions, ne pas revenir
à un ancien binaire qui ne connaît pas cette valeur ; conserver la base et déployer
une correction compatible. Le retour aux anciens MX reste possible. L’empreinte
de politique inclut cette résolution : une fusion activée doit être validée avec
les artefacts et la politique exacts de cette version.
