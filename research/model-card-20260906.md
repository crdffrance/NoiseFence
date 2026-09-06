# Candidat NoiseFence du 6 septembre 2026

**Statut : modèle entraîné et vérifié en Rust, non approuvé pour le classement
automatique en production.** Les mesures montrent un progrès, pas une détection
parfaite ni une validation de tous les moteurs combinés.

## Modèle et protocole

Le candidat retenu est une régression logistique L2 sur TF-IDF, avec pondération
supervisée des caractéristiques par un rapport de vraisemblance bayésien. Les
paramètres sont appris sur les emails ; ce modèle n'est pas une liste de règles
écrites pour les cas testés. Les poids JSON s'exécutent directement en Rust,
sans Python ni service LLM lors de l'inférence locale.

Le schéma 3 utilise 262 144 caractéristiques hachées : mots, bigrammes, groupes
de 3 à 5 caractères et structure du message. Le texte HTML non visible et les
anciens marqueurs antispam sont exclus. Les observations locales déjà apprises
ne sont pas ajoutées une seconde fois comme poids manuels. La décision conserve
le score non arrondi ; l'arrondi n'est utile que pour l'affichage.

Les 61 512 emails préparés proviennent d'Apache SpamAssassin, des archives brutes
Enron-Spam et de Nazario 2015–2025. L'export retient 61 198 messages ; les autres
sont vides, incomplets ou hors des limites. Le regroupement heuristique conserve
46 361 représentants et écarte 14 837 doublons ou variantes proches. Dix exemples
anciens partageant un groupe avec 2025 sont exclus de l'apprentissage.

| Partition | Emails | Usage |
|---|---:|---|
| Entraînement | 27 497 | TF-IDF, ratios bayésiens et poids |
| Développement | 4 694 | Famille de caractéristiques et régularisation |
| Calibration | 4 648 | Position du seuil, avec emails légitimes uniquement |
| Test interne | 9 096 | Mesure après choix du modèle |
| Archive Nazario 2025 | 426 | Test externe, exclu de tout ajustement |

Seize candidats sont comparés : deux schémas, deux familles de modèles linéaires,
quatre régularisations. Le choix est figé sur le développement avant l'évaluation
finale. Le schéma 3 avec pondération bayésienne, C=100, est retenu. La marge
numérique du seuil évite les différences de décision dues à l'ordre des additions
flottantes entre BLAS et Rust. Ce score est un indice, pas une probabilité calibrée.

## Résultats après calibration

| Mesure | Test interne | Phishing de l'archive 2025 |
|---|---:|---:|
| Messages légitimes | 3 989 | 0 |
| Spams/phishings | 5 107 | 426 |
| Détections | 4 882 | 399 |
| Rappel | **95,59 %** | **93,66 %** |
| Intervalle de rappel à 95 % | 95,00–96,12 % | 90,94–95,61 % |
| Faux positifs | **2** | Non mesurable |
| Taux de faux positifs | **0,0501 %** | Non mesurable |
| Intervalle des faux positifs à 95 % | **0,0138–0,1826 %** | Non mesurable |
| Précision | 99,959 % | Non représentative : aucun légitime |

La borne supérieure de 0,1826 % dépasse la cible de 0,1 %. Le rappel de 93,66 %
sur le test externe reste inférieur à 95 %. Les ham sont historiques : même un
succès numérique sur ce corpus ne démontrerait pas la qualité sur des boîtes
professionnelles actuelles, notamment en français. Le regroupement par similarité
ne prouve pas l'absence de toute campagne partagée. Les intervalles supposent
des observations indépendantes et doivent être interprétés avec cette limite.

## Exécution native

Les caractéristiques et décisions de 22 emails tenus à l'écart de l'entraînement,
dont des légitimes proches du seuil, ont été comparées entre Python et Rust.
Erreur absolue maximale de score : **1,42 × 10⁻¹⁴**. L'analyse sans livraison a
également été vérifiée. Un cas privé de régression, exclu de l'apprentissage et
des métriques indépendantes, dépasse désormais le seuil avec le modèle local seul.

Sur le Mac ARM64 utilisé pour la R&D, modèle déjà chargé :

| Message | Itérations | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| 10 127 octets | 1 000 | 0,961 ms | 1,106 ms | 1,246 ms |
| 1 048 521 octets | 100 | 16,907 ms | 17,386 ms | 30,233 ms |

Sur le serveur Debian 13 x86-64 de référence, 4 vCPU et 8 Go de RAM :

| Message | Itérations | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| 10 127 octets | 1 000 | 1,777 ms | 1,837 ms | 2,166 ms |
| 1 048 521 octets | 100 | 30,308 ms | 31,819 ms | 64,954 ms |

Ces mesures comprennent l'extraction MIME/texte et le modèle. Elles excluent DNS,
antivirus, LLM, file, chargement du modèle et relais. Le binaire R&D a été exécuté
séparément avec une priorité réduite, puis les fichiers temporaires ont été
supprimés. Le service actif n'a pas été remplacé. Le pipeline complet reste à mesurer.

## Traçabilité et suite

- Modèle : `research-nb-logistic-1788730448-calibrated`.
- SHA-256 des poids : `eda9070844f4d7472aa828ff9fcf504526232d6401670dc5ec5cd207bdab3854`.
- [Mesures détaillées par source](model-report-20260906.json).
- [Sources épinglées et attributions](sources.lock.json).
- [Reproduction de l'expérience](README.md).

Les poids et les données de travail sont conservés localement. Aucun candidat
n'a été activé en production, aucun MX n'a changé et aucun email supplémentaire
n'a été livré pendant cette expérience. La compatibilité Proton reste un jalon
distinct. Les corpus historiques contiennent parfois une ligne séparatrice mbox,
qui n'est pas une commande SMTP ni une caractéristique du modèle.

La R&D doit encore couvrir les faux négatifs récents, la généralisation
multilingue, des légitimes récents représentatifs et la combinaison avec les
autres moteurs. Une [comparaison avec encodeur multilingue local](semantic-card-20260907.md)
est désormais disponible, ainsi que son portage Rust et ses mesures sur le VPS.
Les jeux déjà examinés deviennent des références de développement pour les
itérations suivantes ; une nouvelle validation indépendante est nécessaire pour
une affirmation finale de qualité. Aucun changement de seuil ne doit être choisi
sur le test pour fabriquer un succès.

Références méthodologiques : [logistique scikit-learn](https://scikit-learn.org/stable/modules/linear_model.html#logistic-regression),
[rapports bayésiens et modèles linéaires, Wang et Manning](https://aclanthology.org/P12-2018/),
[limites de généralisation des corpus de phishing, E-PhishGen](https://arxiv.org/abs/2509.01791).
