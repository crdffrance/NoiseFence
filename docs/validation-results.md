# Résultats locaux — 6 septembre 2026

## Code et protocoles

28 tests automatisés : SMTP et PIPELINING, alias et refus du relais ouvert,
DATA interrompu, pression disque, ambiguïtés CRLF, reprise de file,
destinataires multiples, notifications d’échec, transaction annulée,
TLS réel et certificat non fiable, droits par utilisateur et BCC, sessions et CSRF,
conservation, falsification des résultats, objets encodés et limites des signatures.

Le test cryptographique utilise une clé publique de test et un cache DNS local :
DKIM valide sur l’original et la version observée ; DKIM invalide après modification
de l’objet ; ARC valide sur la version modifiée ; ARC invalide après altération du corps.
Il vérifie la cryptographie, pas la confiance accordée au sceau par Proton.

Les tests passent sur macOS ARM64 et Linux. Le build Linux utilise l’image officielle
Rust 1.98 Bookworm, empreinte `sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922`.
La CI reproduit formatage, Clippy, tests et compilation. Le binaire doit être utilisé
sur l’architecture correspondante avec glibc 2.36 ou plus récente.

La console passe TypeScript et le lint. L’export statique est compilé, servi par Axum
avec réponse HTTP 200 ; l’API sans session renvoie 401. L’audit npm indique zéro
vulnérabilité connue à cette date. Aucune validation visuelle automatisée ni conformité
WebMCP n’est revendiquée.

## Modèle candidat : objectifs non atteints

Source : corpus public Apache SpamAssassin historique. 5 874 exemples après import
et déduplication normalisée, dont 4 659 pour l’entraînement, 609 pour la validation,
606 pour le test. Les variantes éloignées d’une campagne peuvent échapper au regroupement.
Ce résultat est exploratoire sur données anciennes, sans garantie d’indépendance temporelle.

| Mesure sur le test | Résultat |
|---|---:|
| Spams détectés | 117 / 192 |
| Rappel | 60,94 % |
| IC 95 % du rappel | 53,89–67,56 % |
| Messages légitimes marqués | 0 / 414 |
| Faux positifs observés | 0 % |
| IC 95 % des faux positifs | 0–0,919 % |
| Précision observée | 100 % |
| Activation du candidat | Refusée |

Le rapport lisible par machine est [model-bootstrap.report.json](model-bootstrap.report.json).
Le faible effectif ne démontre pas ≤ 0,1 % de faux positifs. Le rappel reste sous 95 %.
Le contrôle d’activation refuse donc ce candidat. Cette mesure porte sur le classifieur
local ; les règles, l’authentification et la réputation du pipeline complet doivent être
évaluées séparément sur un corpus récent et représentatif. Aucun modèle candidat n’est
activé dans la configuration livrée.

## Rapidité et robustesse

Extraction locale sur un message synthétique de 1 048 521 octets, 1 000 répétitions
sur le Mac de développement : p50 3,954 ms, p95 7,491 ms. Ce test exclut DNS,
classification avec modèle chargé, TLS et persistance. Ce n’est pas une mesure du
surcoût complet sur la machine de référence 4 vCPU / 8 Go.

La réception limite quatre analyses concurrentes. Les vérifications réseau d’un message
sont bornées à cinq secondes et une analyse incomplète conserve l’objet sans préfixe.

Les cibles libFuzzer SMTP/MIME ont été compilées et exécutées sur 10 000 entrées chacune,
ainsi que 5 000 mutations déterministes dans les tests. Ces premières exécutions stables
n’avaient pas d’instrumentation de couverture/sanitizer : elles constituent un contrôle
de fonctionnement du harnais, pas une campagne de fuzzing guidée. Des campagnes longues
instrumentées et les essais réels de disque plein/crash matériel restent à réaliser.

## Jalon Proton en attente

Les essais réels Proton ne sont pas encore réalisés. Aucun MX n’a été modifié.
Les huit cas du protocole [proton-validation.md](proton-validation.md) restent à exécuter.
Le mode observation reste la configuration de départ et le marquage exige un rapport
récent renseigné avec des preuves de livraison. Les détails du serveur et les adresses
réelles appartiennent à la configuration locale de chaque déploiement.
