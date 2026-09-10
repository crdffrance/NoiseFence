# Moteurs complémentaires en recherche

Le cycle 0.5 ajoute des observations et des mécanismes optionnels. Leur présence
dans le binaire ne démontre pas une amélioration du taux de capture. Les réglages
des nouveaux modules se font dans le TOML, avec validation et redémarrage ; la
console affiche leurs diagnostics. Les règles et actions déjà disponibles dans
l’administration conservent leur propre configuration.

| Module | Configuration | Traitement et résultat |
| --- | --- | --- |
| [Heuristiques FR/EN](heuristics.md) | `[heuristics]` | Expressions compilées une fois ; identifiants, familles, occurrences, poids candidat et contribution réelle |
| [Documents et images](content-inspection.md) | `[content_inspection]` | HTML, PDF, images, archives Office et macros ; limites explicites, aucune exécution locale |
| [Historique de confiance](sender-history.md) | `[sender_history]` | Identités authentifiées, campagnes distinctes et corrections humaines ; portée par destinataire, révocation et expiration |
| [Admission SMTP](smtp-admission.md) | `[smtp_admission]` | Greylisting durable et temporisation bornée avant acceptation ; observation par défaut |
| [Vérification ciblée d’expéditeur](challenge.md) | `[challenge]` | Demande explicite depuis une copie en quarantaine, code visuel et lien à usage unique, quotas durables et libération limitée aux droits correspondants |
| [Analyse dynamique](sandbox-pipeline.md) | `[sandbox]` et `[sandbox_pipeline]` | Intention durable avec le message, traitement en arrière-plan par un CAPEv2 privé, résultats consultatifs et quarantaine facultative |

## Démarrer une observation locale

Ajouter les sections suivantes à une configuration valide :

```toml
[heuristics]
mode = "observation"

[content_inspection]
max_raw_bytes = 2097152

[sender_history]
mode = "observation"

[smtp_admission]
enabled = false
mode = "observe"
```

Les moteurs heuristique et documentaire partagent 1 à 4 places CPU, selon
`smtp.max_processing`. Leur travail s’exécute hors des threads réseau. Un délai
d’attente de 500 ms n’interrompt pas brutalement le décodeur : sa place reste
réservée jusqu’à sa fin. Les budgets de taille, de structure et de décompression
bornent séparément le travail. Un résultat absent, limité ou indisponible ne
devient jamais un résultat réussi dans l’interface.

La contribution numérique expérimentale des heuristiques est autorisée
uniquement en mode global `observe`. Son empreinte de calibration n’est pas une
preuve de qualité. L’historique de confiance propose des candidats ; il ne saute
pas les vérifications de malware et ne blanchit pas automatiquement un domaine.

Le challenge nécessite une origine HTTPS identique à celle de la console. Le
connecteur CAPE nécessite sa propre activation, une instance privée et une VM
isolée préparée par l’administrateur. Aucun de ces mécanismes n’est activé par
l’exemple. Le connecteur ne peut pas attester lui-même l’isolation de la VM.

## Reproduire les observations sur un corpus de développement

Le manifeste JSONL utilise les champs `path`, `spam`, `source`, `year` et
`external_test`. Les chemins sont relatifs à la racine autorisée. Les lignes
réservées au test indépendant sont exclues avant l’ouverture des messages.

```sh
cargo build --release --locked
RUST_LOG=noisefence=info target/release/noisefence \
  --config config/research.example.toml research-detectors \
  --manifest /chemin/developpement/manifest.jsonl \
  --root /chemin/developpement/messages \
  --output /chemin/prive/observations.jsonl --limit 100000
```

Cette commande n’ouvre ni résolveur DNS, ni modèle, ni base de production, ni
connecteur réseau. Le fichier de sortie privé est créé atomiquement et ne peut
pas écraser un résultat précédent. Il conserve des observations, empreintes et
temps, sans corps ni extraits de message.

Les archives mbox peuvent commencer par une ligne `From ` propre au conteneur,
qui n’est pas un en-tête RFC 5322. Préparer des copies de développement en retirant
cette seule ligne de conteneur et en rétablissant CRLF ; consigner la transformation
et l’empreinte de l’archive. Ne pas modifier les octets reçus par SMTP avant les
vérifications d’authentification.

Le [relevé du 10 septembre](../research/local-detectors-20260910.json) conserve
les résultats avant et après cette préparation sur 6 046 messages Apache
historiques. Après préparation, le coût des deux moteurs locaux est p50 39 µs,
p95 377 µs et p99 1 037 µs sur le poste de développement ARM64/macOS. Ces mesures
séquentielles excluent l’extraction principale, les modèles, le DNS, la file et
le relais ; elles ne valident pas la cible serveur de 4 vCPU/8 Go.

Les correspondances de règles sont des observations, pas des prédictions de
spam. Ce corpus ancien ne prouve ni le rappel ni le taux de faux positifs sur
le trafic actuel. Le [programme complet](../research/engine-program.md) conserve
les preuves manquantes et les conditions de validation.

Le candidat 0.5.0-dev.2 permet d’entraîner la [fusion v2](../research/fusion.md)
avec ces observations locales, depuis les données conservées lors de la réception
SMTP. Le protocole lie le modèle au catalogue et à la configuration des moteurs.
Les observations de développement exportées ci-dessus ne remplacent pas les
preuves SMTP ni les retours humains nécessaires à cette expérience.
