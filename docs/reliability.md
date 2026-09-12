# Fiabilité du filtre

Depuis 0.5.0, la page **Fiabilité** complète l’annotation à scores masqués dans
**Qualité du filtre**. Elle n’écrit aucun réglage et n’active aucun modèle.

## Lire le bilan

Les fenêtres couvrent 1 à 29 jours, au maximum 5 000 messages récents accessibles,
32 Mio de diagnostics et deux secondes de calcul. Les lignes de plus de 512 Kio
ou illisibles sont signalées. Les limites SQLite et la concurrence des lectures
restent celles de la console. Un bilan partiel ne calcule pas d’alerte de changement
de distribution. Un même message avec plusieurs destinataires autorisés compte
une fois. Seules les annotations du compte courant sont utilisées ; les droits
sur les destinataires sont revérifiés à chaque requête.

- **Annotations de qualité** : corrections explicites de risque, y compris celles
  conservées dans les lots. **Corrections ciblées** : retours historiques hors de
  ces annotations. Ces derniers sont souvent concentrés sur les erreurs.
- Les réponses incertaines ne deviennent jamais légitimes. Une abstention sur
  un spam diminue le rappel ; une abstention n’est pas un faux positif de marquage.
- Rappel, faux positifs, précision et abstention portent sur les annotations
  disponibles. Les intervalles de Wilson à 95 % ne corrigent ni le biais de
  sélection ni la dépendance entre campagnes. Sans annotations, le résultat est
  indisponible. Zéro erreur sur dix messages ne démontre pas 0,1 % de faux positifs.
- Les variations comparent les dernières 24 h au reste de la période : au moins
  trente observations dans chaque groupe, hausse d’au moins quinze points et
  intervalles séparés. Ce sont des alertes descriptives à examiner, pas une preuve
  statistique de régression, ni un mécanisme de désactivation automatique.
- Les quotas, limites et indisponibilités restent distincts d’une absence de
  détection. Les alertes de disponibilité demandent au moins trois incidents
  sur 10 % des contrôles configurés observés dans les dernières 24 h.

La latence p95 est celle enregistrée par le parcours d’analyse, avec ses vérifications
externes. Elle ne mesure ni le délai total SMTP ni le benchmark à caches chauds.

## Mesurer l’apport des règles

Le tableau conserve occurrences, annotations, regroupements et cooccurrences.
Pour les observations historiques complètes dont le score peut être reconstruit
et la politique de décision rejouée, le retrait d’un poids recalcule la décision.
Il compte les faux positifs évités et les spams détectés qui seraient perdus.

Cette ablation retire **le poids uniquement** : l’antivirus, les preuves, la
corroboration et l’avis LLM restent figés. Elle ne simule pas de nouveaux appels,
les actions par destinataire ou le dossier Proton. Les symboles natifs restent
consultatifs ; aucun effet fictif sur la livraison ne leur est attribué.

Les comparaisons candidates utilisent uniquement les prédictions enregistrées et
les mêmes messages annotés. La sélection des cas couverts doit être examinée dans
l’évaluation indépendante décrite dans [le protocole qualité](quality.md).

## Stabiliser la collecte et entraîner

La compatibilité lie tous les sources Rust et SQL, les protocoles et auxiliaires
runtime, les dépendances verrouillées, le compilateur, la cible, les options de
compilation, les modèles et les paramètres. Seule la version de notre propre
paquet est normalisée dans les manifests ; la version publiée et le verrou brut
restent conservés comme provenance. Le champ `application` existant porte la
version et l’empreinte dans le suffixe `-nf1.…`, sans ajouter de
champ au format strict lu par les anciens binaires. Les agents HTTP de vérification ont leur propre
version de protocole, indépendante de la version du logiciel.

Une modification du moteur, d’un modèle, du système de compilation ou des paramètres
crée un nouveau groupe. Les anciens enregistrements sans empreinte de compatibilité
restent strictement séparés. Une mise à jour du frontend seul ou du numéro de version
peut préserver le groupe, à moteur, compilation et paramètres identiques. Ce mécanisme
ne prétend pas figer les bases de réputation externes ou leurs réponses.

1. Garder la collecte et les paramètres stables. Utiliser le début de collecte du
   moteur courant proposé dans la console. Le tirage inclut les analyses incomplètes
   et n’est jamais fondé sur le score.
2. Annoter les originaux, puis exporter un lot privé avec `quality-export`. Conserver
   les anciens lots ; ne pas recalculer leurs signaux à partir des seuls objets.
3. Exécuter `train_quality.py` selon [la procédure](quality.md). Les contributions
   natives de contenu, campagne et Bayes sont des entrées supplémentaires, avec
   leurs états de disponibilité. Les logits Bayes sont bornés et ne sont pas des
   probabilités calibrées. Les poids lexicaux historiques ne sont pas recomptés.
4. Le candidat compare onze ablations, dont sans moteur natif et sans Bayes natif.
   S’il manque des annotations ou des campagnes dans les cinq périodes, aucun
   modèle n’est produit. Un échantillon mélangeant des groupes est refusé : choisir
   une période homogène, conserver les exclusions et leur portée dans le rapport.
5. Geler le modèle, les seuils et le manifeste. Tirer un nouveau lot futur, indépendant
   des campagnes d’apprentissage et des tests précédents. Exécuter `evaluate_quality.py`.
   Mesurer couverture, abstention, calibration, rappel, erreurs et intervalles.
6. Ne pas activer un candidat sur la seule base de l’accord avec le filtre existant
   ou d’une poignée de corrections. Les cibles ≥95 % / ≤0,1 % restent à démontrer.

Commandes de bilan local (sans contenu exporté ni mutation de politique) :

```sh
noisefence --config /etc/noisefence/config.toml reliability-audit \
  --username "$ANNOTATOR" --days 7 --domain example.org
noisefence --config /etc/noisefence/config.toml proton-check
```

`GET /api/v1/quality/reliability?days=7&domain=example.org` exige une session.
Les utilisateurs voient uniquement leur périmètre. Les contrôles système et
rapports Proton sont réservés aux administrateurs. Aucune clé ni réponse brute
fournisseur ne figure dans le bilan.

## Signatures et Proton

L’administration interroge ClamD avec `zVERSION`, sans envoyer de message : deux
requêtes locales concurrentes au maximum, délai de 500 ms, réponse de 512 octets
maximum. Une date non reconnue ou une commande indisponible donnent un état inconnu.
L’absence de fuseau dans la date impose une incertitude de ±14 h. La fraîcheur est
comparée à trois jours ; elle ne certifie pas le jeu exact de signatures chargé.
Voir le [protocole ClamD officiel](https://docs.clamav.net/manual/Usage/ClamdProtocol.html).

Les checklists SPAM et PUB contrôlent les rapports existants : préfixe, domaines,
hôte, date, huit cas documentés et limite de contournement acceptée. Une acceptation
SMTP seule ne prouve pas l’arrivée en réception. Suivre la [matrice Proton](proton-validation.md),
avec arrivée directe, relais intact, relais marqué, dossier constaté et en-têtes
finaux. Le mode observation reste nécessaire tant que cette validation manque.

## Migration 0.4.x → 0.5.0

Le nouveau protocole d’observations ajoute les entrées natives. Le protocole du
contenu natif passe à `noisefence-native-content-2` pour exclure les exemples HTML
inertes. Les anciens modèles candidats conjoints, modèles OSB et artefacts de
fusion sont incompatibles : retirer leurs chemins optionnels avant `check-config`,
puis collecter et entraîner de nouveaux candidats. Le modèle lexical/sémantique
historique conserve son format et son comportement. Vérifier explicitement toute
installation utilisant une fusion en décision avant mise à jour.

Aucune migration SQLite ; les nouvelles observations restent dans les champs JSON
existants. Le déploiement doit sauvegarder configuration et données, conserver
les modèles antérieurs, vérifier `check-config`, puis contrôler file, TLS et API.
Pour un retour à 0.4.15, restaurer la configuration antérieure et conserver la base
courante afin de ne pas perdre les messages acceptés depuis la sauvegarde. Les
motifs personnalisés contenant `exclude_negated` doivent être retirés de cette
ancienne configuration. Aucun historique n’est réécrit.
