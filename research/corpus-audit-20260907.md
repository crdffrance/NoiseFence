# Données récentes et diagnostic sur textes courts

Le modèle figé repère **9 des 23 textes étiquetés phishing**, sans faux positif
parmi **77 textes étiquetés légitimes**, dans ce diagnostic supplémentaire.
Le [rapport JSON](text-challenge-20260907.json) donne les effectifs et les limites.
Ce résultat ne valide pas la capture sur le trafic réel ; il montre pourquoi
la réussite sur un email privé ne suffit pas à évaluer le modèle.

## Provenance vérifiée

Une publication récente ne garantit pas des emails récents. Le corpus
[MeAJOR](https://arxiv.org/html/2507.17978v1) réunit notamment les anciens TREC
2005–2007. Le [projet DataPhish décrit en 2025](https://arxiv.org/html/2511.21448v1)
annonce des messages plus récents, mais son dépôt référencé répond 404 lors du
contrôle du 7 septembre 2026. Ses données n'ont pas été acquises.

[Sting9](https://sting9.org/dataset) vise les signalements de menaces. Sa page
d'accès mentionne CC0, alors que sa [licence liée](https://sting9.org/license)
énonce des restrictions commerciales. Il n'est pas utilisé ici ; aucune cohorte
légitime représentative n'y a été établie.

Le [jeu universitaire de Miltchev, Rangelov et Genchev, v1](https://zenodo.org/records/13474746)
est accessible sous [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).
Il mélange réel et synthétique. L'audit du CSV vérifié trouve 2 000 lignes,
mais seulement 100 textes distincts de 68 à 103 caractères. Il ne contient ni
date par message, ni indicateur réel/synthétique, ni contexte SMTP d'origine.
Les textes originaux ne sont pas redistribués dans NoiseFence.

## Méthode et résultats

Avant toute prédiction, les poids, le seuil 95, les empreintes et la sélection
des 100 textes distincts ont été figés. Chaque texte devient le corps d'un MIME
`text/plain; charset=utf-8`, encodé en 8 bits avec les fins de ligne SMTP de
`email.message.EmailMessage`. Aucun objet, expéditeur, destinataire ou horodatage
n'est inventé. Les labels du CSV restent séparés des caractéristiques.

Les exemples Rust `research_text`, `semantic_probe` et `feedback_probe`, avec
`features-export --feature-version 3`, utilisent l'extraction et les modèles
locaux existants. Les 100 prédictions sont complètes. Aucun DNS, scanner, LLM
externe, apprentissage ou envoi SMTP n'intervient dans ce diagnostic.

| Sélection | Légitimes | Phishing | Phishing détectés | Faux positifs |
| --- | ---: | ---: | ---: | ---: |
| Textes exacts distincts | 77 | 23 | 9 | 0 |
| Représentants de groupes similaires | 59 | 19 | 9 | 0 |

Le modèle lexical et sa combinaison E5 donnent les mêmes classements. Les
groupes utilisent le texte canonique et une distance SimHash d'au plus trois
bits, avec un représentant choisi par empreinte avant prédiction. Aucun
rapprochement avec les 61 198 messages des sources existantes n'est trouvé par
cette heuristique ; ce n'est pas une preuve absolue d'indépendance.

Les répétitions et la sélection de courts exemples empêchent d'en déduire un
taux de faux positifs de production ou un intervalle de confiance représentatif.
Certaines formulations étiquetées phishing pourraient également apparaître dans
une notification légitime : sans expéditeur ni lien réel, le texte seul peut
être ambigu. Le résultat est rapporté contre les labels fournis par les auteurs.

Les poids et la configuration de production restent inchangés. Ce jeu demeure
exclu de l'entraînement et ne pourra pas servir de nouvelle validation aveugle
après examen. La prochaine calibration exige des emails récents autorisés,
annotés et représentatifs, avec séparation des campagnes et contexte de réception.
