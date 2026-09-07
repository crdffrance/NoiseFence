# Mesurer le traitement complet

`model-benchmark` mesure l'extraction et l'inférence locales. Pour mesurer aussi
les connecteurs, le banc `pipeline_probe` appelle le même `Engine::process` que
la réception SMTP, plusieurs fois dans un seul processus. Il charge le modèle
une fois et conserve les caches entre essais. Il ne démarre aucun serveur SMTP,
ne met aucun message en file et ne livre aucun email.

```sh
cargo build --release --locked --features semantic --example pipeline_probe
python3 tests/pipeline_probe.py target/release/examples/pipeline_probe
```

Le workflow manuel `pipeline probe build` fournit aussi un exécutable Linux
x86-64 avec les empreintes de l'exécutable, des sources du moteur et du banc.
Il ne contient ni configuration de production, ni corpus, ni modèle entraîné.

## Définir les cas

Créer un manifeste privé, ici `reports/cases.json`, contenant un à huit cas :

```json
[
  {
    "id": "legitime-texte",
    "path": "legitime.eml",
    "source_ip": "192.0.2.10",
    "helo": "sender.example.test",
    "mail_from": "sender@example.test"
  }
]
```

Le chemin est relatif au manifeste, ou absolu. Chaque message doit être un
fichier régulier, valide, de taille inférieure ou égale à 1 Mio. Les noms de cas
sont des identifiants, sans contenu privé. L'exemple d'adresse IP ci-dessus est
réservé à la documentation : il ne représente pas un expéditeur authentifié.
Pour les vérifications DNS, indiquer le contexte réellement observé à la
réception ou documenter explicitement le caractère synthétique de ce contexte.

La configuration doit désigner les modèles et les connecteurs à mesurer, avec
leurs paramètres habituels. Conserver le même nombre de threads CPU et les
mêmes limites que sur le serveur de référence. Enregistrer séparément CPU, RAM,
charge concurrente, empreintes des modèles et version des bases antivirus.

```sh
RAYON_NUM_THREADS=4 CANDLE_NUM_THREADS=4 TOKENIZERS_PARALLELISM=false \
  target/release/examples/pipeline_probe \
  --config config/local.toml --cases reports/cases.json \
  --output reports/pipeline.jsonl --iterations 30 --warmup 3 --interval-ms 100
```

Le banc exécute les cas séquentiellement, avec quatre workers Tokio. Les cycles
de chauffe figurent dans le fichier mais sont exclus des quantiles. L'intervalle
entre appels est aussi exclu. Les mesures englobent `Engine::process`, dont la
réécriture des en-têtes, mais excluent la lecture des fichiers, le chargement du
modèle, la réception SMTP, la persistance et le relais. Ce n'est pas un test de
débit ou de surcharge du serveur SMTP.

## Contenu externe et coûts

Les vérifications DNS et les scanners suivent la configuration du moteur. Un
LLM payant configuré exige le drapeau explicite `--allow-paid-llm`. Il peut recevoir
les extraits textuels autorisés et utilise le budget durable de `data_dir`.
Ne pas remplacer ce répertoire par un répertoire vide pour contourner le budget.
Les cycles de chauffe peuvent aussi produire des appels payants.

N'utiliser que du contenu autorisé pour ces connecteurs. Les essais de coût et
de latence externes peuvent se faire sur des messages synthétiques. Les
résultats d'un message privé analysé sans réseau ne sont pas comparables à un
essai de toute la chaîne avec DNS et LLM.

## Lire les résultats

Le fichier JSONL commence par la configuration des vérifications, contient une
ligne par appel, puis un récapitulatif `record: "summary", run_finished: true`.
L'absence de ce récapitulatif indique une exécution interrompue ou échouée. Un
fichier existant est refusé ; le banc n'écrase pas une mesure antérieure.

Chaque cas présente p50, p95 et maximum en microsecondes, par rang le plus proche,
ainsi que les nombres d'analyses complètes, incomplètes et en erreur. Les échecs
restent dans `all_trials`. `complete_trials_only` est une vue complémentaire :
elle ne doit pas masquer les délais dépassés ou les services indisponibles.
Vérifier aussi les statuts des composants : un LLM limité par le budget ou jugé
inutile n'a pas exécuté une requête complète.

Le score, la version du modèle, les identifiants des raisons et les durées des
composants sont enregistrés, sans corps, objet, explication LLM ni vecteurs de
caractéristiques. Le rapport comporte l'empreinte du message. Les entrées et
résultats privés restent exclus de Git ; leur conservation relève de l'exploitant.

Ne pas additionner toutes les durées de composants : certains contrôles se
chevauchent. Ne pas agréger plusieurs cas comme s'ils représentaient la fréquence
réelle de ces messages. Un p95 sur quelques messages synthétiques vérifie ces
cas sur cette machine ; il ne démontre ni le p95 du trafic réel, ni la capture,
ni les faux positifs. Mesurer ensuite un ensemble récent représentatif, avec
les statuts des contrôles et les incertitudes, avant toute revendication globale.
