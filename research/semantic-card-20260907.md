# Comparaison multilingue locale du 7 septembre 2026

**R&D sur le développement, aucun déploiement ni validation de qualité finale.**
Un encodeur préentraîné optionnel complète le classifieur appris localement ;
le moteur SMTP et le modèle lexical Rust restent distincts de cet encodeur.

## Protocole figé avant les mesures de référence

- Même entraînement : 27 497 représentants de campagnes.
- Même développement : 2 022 légitimes et 2 672 spams.
- [multilingual-e5-small](https://huggingface.co/intfloat/multilingual-e5-small),
  révision `614241f622f53c4eeff9890bdc4f31cfecc418b3`, licence MIT déclarée.
- Poids figés, vecteurs de 384 dimensions, préfixe `query: `, moyenne masquée puis
  normalisation L2, séquences tronquées à 256 tokens. Inférence PyTorch locale,
  sans service externe, outils, liens visités ni pièces jointes exécutées.
- Quatre têtes logistiques L2 : C = 0,1 / 1 / 10 / 100.
- Combinaisons de logit lexical + α × logit sémantique, avec α parmi
  0,1 / 0,25 / 0,5 / 1 / 2. Seuils comparés à 0,1 % de faux positifs empiriques.
- Choix sur le rappel de développement, PR-AUC en cas d'égalité. Aucun choix
  effectué sur la calibration, le test interne ou l'archive 2025.

## Résultat de sélection

| Candidat | Détections / 2 672 | Rappel | Faux positifs / 2 022 |
|---|---:|---:|---:|
| Lexical natif seul | 2 569 | 96,15 % | 2 |
| Meilleur encodeur seul, tête C=10 | 1 930 | 72,23 % | 2 |
| Lexical + 0,1 × sémantique C=10 | **2 600** | **97,31 %** | **2** |

Le gain est de 31 détections nettes sur le développement. Le modèle lexical
reste essentiel ; la tête sur encodeur seule donne un rappel nettement inférieur
au même niveau de faux positifs. Les 2 erreurs sur 2 022 légitimes donnent un
intervalle de Wilson à 95 % de **0,0271 à 0,3599 %**. Cela ne prouve pas la cible
de production et le choix parmi plusieurs candidats ajoute un biais de sélection.

Les 32 191 textes ont été encodés en 216,2 secondes sur le GPU local du Mac,
par lots de 16. Ce débit de préparation n'est pas une latence de production sur
le VPS. Les poids Safetensors et fichiers associés ont été vérifiés contre
les empreintes du fichier de verrouillage avant chargement. Cette sélection Python
a ensuite été portée en Rust et vérifiée comme décrit ci-dessous.

[Détail des candidats](semantic-development-20260907.json) et
[reproduction](README.md#comparer-un-encodeur-multilingue-local).

## Mesures de référence après calibration

La combinaison ci-dessus a été figée avant ces calculs. Le seuil est ajusté sur
les 2 008 légitimes de calibration, sans modifier les poids ni α. Les partitions
de référence avaient déjà été examinées dans l'expérience lexicale précédente.

| Mesure | Lexical seul | Combinaison figée |
|---|---:|---:|
| Rappel, 5 107 spams du test historique | 95,59 % (4 882) | **95,83 % (4 894)** |
| Faux positifs, 3 989 légitimes historiques | 2 (0,0501 %) | **1 (0,0251 %)** |
| Intervalle de rappel à 95 % | 95,00–96,12 % | 95,25–96,34 % |
| Intervalle du taux de faux positifs à 95 % | 0,0138–0,1826 % | **0,0044–0,1419 %** |
| Rappel sur les 426 phishings Nazario 2025 | 93,66 % (399) | **94,84 % (404)** |
| Intervalle du rappel 2025 à 95 % | 90,94–95,61 % | 92,30–96,57 % |

Le gain externe est de cinq détections nettes. **94,84 % reste inférieur à 95 %** ;
la borne haute du taux de faux positifs reste supérieure à 0,1 %. Aucun légitime
2025 n'est présent dans l'archive, donc son taux de faux positifs n'est pas mesurable.
Le statut reste `eligible: false`. Ces observations justifient de poursuivre la
R&D, pas de modifier le seuil sur ce test ni d'activer le marquage automatique.

[Résultats détaillés et empreintes de la sélection](semantic-reference-20260907.json).

## Portage Rust et limites d'exécution

L'option de compilation `semantic` charge les fichiers Safetensors locaux avec
Candle 0.11.0 et le tokenizer 0.22.2, sans client de téléchargement. Les trois
fichiers nécessaires doivent correspondre exactement aux empreintes épinglées.
Le manifeste de combinaison lie les coefficients au SHA-256 du modèle lexical
calibré, à la révision de l'encodeur, au schéma de texte et au seuil.

Les 24 messages de contrôle donnent les mêmes tokens et décisions. L'écart
maximal de score complet Python/Rust est de **0,0000033 point sur 100**.
Huit légitimes proches du seuil de calibration font partie de ces contrôles.
Cinq autres entrées synthétiques couvrent accents français, arabe, japonais,
texte vide et longueur maximale ; l'écart maximal des vecteurs est de 1,60 × 10⁻⁷.
Ces contrôles de concordance ne mesurent pas la qualité dans ces langues.

Sur le VPS Debian 13 x86-64, 4 vCPU / 8 Go, 100 itérations et modèle chargé :

| Message | p50 | p95 | p99 |
|---|---:|---:|---:|
| 10 127 octets | 296,460 ms | **340,490 ms** | 380,506 ms |
| 1 048 521 octets | 340,415 ms | **373,483 ms** | 393,923 ms |

Le benchmark comprend MIME, caractéristiques lexicales, encodeur et combinaison.
Il exclut DNS, antivirus, LLM, file et chargement initial. Pendant le benchmark,
la mémoire résidente observée est de 794 032 Kio, avec un pic de 1 220 424 Kio
incluant le chargement. Ce relevé ponctuel ne prouve pas une limite maximale sous
toutes les charges. Le processus comporte neuf threads, dont les threads du
runtime et du calcul ; les pools de calcul sont configurés à quatre threads.

L'inférence serveur s'exécute hors des threads réseau, avec un créneau CPU par
défaut et un délai de 500 ms. Si un calcul dépasse son délai, son créneau reste
occupé jusqu'à sa fin ; une nouvelle demande occupée n'empile pas d'autres calculs.
Le score lexical calibré est conservé et l'analyse devient incomplète, sans
préfixe. Les vecteurs sont conservés avec les autres caractéristiques pendant
30 jours ; l'API utilisateur expose le statut et la latence, pas ces vecteurs.

[Mesures natives](native-hybrid-validation-20260907.json). Le service de production
n'a pas été remplacé et les fichiers temporaires du VPS ont été supprimés.

## Limites

Les légitimes sont historiques et ne valident pas le trafic français actuel.
Un encodeur multilingue ne rend pas cette évaluation multilingue : il manque des
messages récents représentatifs, des annotations par langue et une mesure par
sous-groupe. Un recouvrement avec le préentraînement de l'encodeur est inconnu.
Le texte long est tronqué et le contenu des pièces jointes n'est pas utilisé.

Le choix de combinaison est figé avant une mesure sur les autres partitions.
Ces tests ont déjà été examinés lors de la première expérience lexicale : ils
servent désormais de références de R&D et ne constituent pas une nouvelle
validation indépendante. La combinaison avec SPF, DMARC, réputation, antivirus,
signatures et avis LLM reste à évaluer séparément. Aucun résultat présenté ici
n'autorise à annoncer une détection parfaite.
