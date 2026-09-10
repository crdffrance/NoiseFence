# Entraînement Enron du 10 septembre 2026

**Candidat entraîné et vérifié en Rust, non activé.** Il améliore la détection du
lot Enron fourni, mais réduit la capture sur les autres références. Le modèle de
production reste inchangé. Les [résultats détaillés](enron-training-20260910.json)
conservent les effectifs, intervalles, variantes comparées et empreintes.

## Données et séparation

L'archive `enron_spam_data.zip` contient 33 716 lignes : 16 545 légitimes et
17 171 spams, avec des dates déclarées de 1999 à 2005. Les labels sont ceux de la
source, sans revue individuelle du consentement ou du phishing. Le CSV ne conserve
pas le contexte SMTP ni le MIME original. Les messages ne sont pas redistribués.

L'import retire 51 lignes vides, 3 172 répétitions exactes et 84 octets NUL ;
l'extraction Rust écarte ensuite 37 messages incomplets ou trop courts. L'audit
croisé exclut 18 575 messages reliés aux corpus déjà connus et 778 variantes
supplémentaires. Il reste **11 103 nouveaux représentants de campagne** :
3 464 légitimes et 7 639 spams.

Le contrôle normalisant aussi la ponctuation est indispensable : l'audit initial
sans cette normalisation ne repérait que 328 recouvrements. Ce premier regroupement
a été abandonné **avant tout ajustement ou score de test**. Les identifiants,
dates, chemins et labels ne sont jamais des caractéristiques du détecteur.

| Partition | Historique + ajout | Dont nouvel Enron |
|---|---:|---:|
| Entraînement | 34 255 | 6 758 |
| Développement | 5 791 | 1 097 |
| Calibration | 5 783 | 1 135 |
| Test | 11 209 | 2 113 |
| Référence Nazario 2025 | 426 | 0 |

Les partitions historiques sont conservées. Toute nouvelle composante reliée à
une référence est exclue des ajouts, y compris par transitivité. Les références
incluent également les diagnostics et lots français réservés. Canonicalisation
et SimHash restent des heuristiques, sans garantie absolue d'indépendance.

## Modèle et résultats

Le schéma 3 comporte 262 144 caractéristiques de mots, caractères et structure.
Huit candidats sont comparés sur le développement uniquement. La logistique L2
avec ratios bayésiens, `C=100`, est retenue. L'IDF, les ratios et coefficients
utilisent seulement l'entraînement. Le seuil global utilise uniquement les
légitimes de calibration ; aucune correction n'est effectuée après le test.
Le score 95/100 est un indice de suspicion, pas une probabilité calibrée.

La comparaison ci-dessous concerne le **composant textuel seul**, avec les seuils
figés des deux modèles. Elle ne mesure pas E5, DNS, réputation, OCR, antivirus,
LLM ou les décisions finales de la passerelle.

| Mesure | Modèle textuel actuel | Candidat Enron |
|---|---:|---:|
| Capture, nouveau test Enron (1 437 spams) | 1 189 / 82,74 % | 1 271 / 88,45 % |
| Faux positifs, nouveau test Enron (676 légitimes) | 0 | 0 |
| Capture, test combiné (6 544 spams) | 6 071 / 92,77 % | 6 052 / 92,48 % |
| Faux positifs, test combiné (4 665 légitimes) | 2 / 0,0429 % | 0 / 0 % observé |
| Capture, référence Nazario 2025 (426 phishings) | 399 / 93,66 % | 366 / 85,92 % |

Le candidat trouve 82 spams supplémentaires du nouveau test Enron, mais en perd
101 sur le test historique et 33 sur Nazario. Il retire les deux faux positifs
historiques de cette comparaison. Ce compromis ne justifie pas une activation.

Intervalles de Wilson à 95 % du candidat :

- Nouveau test Enron : rappel **86,69–90,00 %** ; faux positifs **0–0,5651 %**.
- Test combiné : rappel **91,82–93,10 %** ; faux positifs **0–0,0823 %**.
- Nazario : rappel **82,29–88,90 %**, sans estimation des faux positifs car aucun
  message légitime n'est présent dans cette archive.

Les anciens tests ont déjà été consultés et restent des références historiques.
Le sous-ensemble Enron supplémentaire est également ancien. Aucun de ces résultats
ne démontre les performances sur un trafic récent représentatif en français.
Le petit lot de 676 légitimes ne suffit pas à établir une limite de 0,1 %.

## Vérification et artefacts

Le modèle est chargé par NoiseFence 0.4.5 et vérifié sur 22 messages réservés,
dont des légitimes proches du seuil : caractéristiques et décisions identiques,
erreur maximale de score **1,42 × 10⁻¹⁴**. L'analyse sans envoi ni mise en file est
vérifiée. Les 53 tests Python passent avec OpenSSL 3 ; les tests du nouvel exemple
Rust, Clippy et le formatage passent aussi.

Poids privés : `models/enron-20260910-candidate/model.json`.
SHA-256 : `0a5f4601038dcc1ca1879b9d01fa3c4b148ca954348a86e3a458fc154ab6256a`.
Le dossier conserve les rapports, la sélection figée, la comparaison, les
prédictions privées et la vérification Rust. Le [guide de reproduction](enron-training.md)
décrit les commandes. Aucun email de ce corpus n'a été envoyé ; aucun modèle,
seuil, routage ou réglage de production n'a été modifié.

Le prochain lot utile doit inclure des légitimes et indésirables récents annotés,
notamment en français, avec des campagnes distinctes. Les présents tests sont
figés comme références ; ils ne doivent pas sélectionner une nouvelle variante.
