# Apprentissage à partir des corrections

La commande `export-learning` conserve les caractéristiques de schéma 3 et les
vecteurs de l’encodeur multilingue après suppression des corps livrés. Elle n’utilise
pas les emails bruts. L’export est privé : les caractéristiques apprises ne sont pas
une anonymisation et ne doivent pas être publiées avec le code source.

Depuis 0.3.0-dev.8, le champ additionnel [evidence](decision-evidence.md) conserve
les contrôles fiables des nouvelles sessions SMTP. Les contextes locaux, fournis
manuellement et historiques restent exclus de ce champ. L’entraîneur de contenu
actuel l’ignore ; il prépare les entrées nécessaires à une future fusion apprise.

## Exporter

```sh
noisefence --config /etc/noisefence/config.toml export-learning feedback.jsonl --require-semantic
```

La sortie JSONL `noisefence-learning-1` contient un identifiant pseudonyme, les dates
de réception et de correction, le label humain, les empreintes de campagne,
les caractéristiques lexicales et, si disponible, le vecteur sémantique avec son
encodeur, sa révision, son préfixe, sa méthode de normalisation et ses limites.
Elle ne contient ni objet, ni corps, ni expéditeur, ni destinataires/BCC, ni compte
utilisateur. Elle n’est pas accessible dans l’API de la console.

Seules les corrections de comptes actifs disposant encore d’un droit sur un
destinataire d’enveloppe sont retenues. Les désaccords, les notifications automatiques,
les extractions locales incomplètes et les métadonnées de plus de 30 jours sont exclus.
Une panne DNS, de scanner ou de LLM ne retire pas une correction dont les
caractéristiques locales sont complètes et vérifiées. Ce statut est enregistré
avant les contrôles externes ; une ancienne analyse incomplète sans ce statut
reste exclue. Le compteur `exported_with_incomplete_checks` rend cette distinction
visible. Elle ne change pas la livraison sans préfixe en cas d'analyse incomplète.
Les anciennes lignes sans empreinte de campagne ou protocole vérifiable ne sont
pas reconstituées par supposition. Les exclusions sont comptées dans le résultat.
`--require-semantic` exclut les lignes dont l’encodeur n’est pas exactement celui
attendu ; l’omettre permet un candidat lexical.

L’export lit un instantané SQLite en WAL, écrit en flux dans un fichier temporaire
0600, synchronise les données puis remplace atomiquement la précédente sortie.
Une erreur de lecture ou un vecteur invalide préserve le précédent export complet.
Cette commande ne reprend pas la file et ne change pas l’état des livraisons.

## Entraîner un candidat

Le runtime numérique est séparé du service SMTP. Les versions de
`research/requirements.txt` sont épinglées ; utiliser un environnement Python
compatible avec ces versions (par exemple Python 3.11). Aucun téléchargement
d’encodeur n’est nécessaire : ses vecteurs sont déjà enregistrés par Rust.

```sh
python3.11 -m venv /opt/noisefence-learning
/opt/noisefence-learning/bin/python -m pip install -r /opt/noisefence/current/research/requirements.txt

OPENBLAS_NUM_THREADS=2 OMP_NUM_THREADS=2 /opt/noisefence-learning/bin/python \
  /opt/noisefence/current/research/train_feedback.py \
  feedback.jsonl candidat-nouveau --hybrid
```

Le dossier de destination doit être nouveau. `--hybrid` exige un vecteur compatible
pour chaque ligne ; il ne se rabat pas silencieusement sur un entraînement lexical.
Sans cet argument, les caractéristiques lexicales seules sont utilisées.

Le traitement regroupe les empreintes canoniques et les SimHash distants de trois
bits au plus, élimine les groupes aux labels contradictoires et conserve un
représentant par groupe. Cette heuristique ne garantit pas la détection de toutes
les variantes d’une campagne. Les partitions par groupe sont 60 % entraînement,
10 % développement, 10 % calibration et 20 % test. Chaque partition doit contenir
les deux classes ; sinon le traitement échoue sans publier de candidat.

L’IDF et les poids sont ajustés uniquement sur l’entraînement. La régularisation,
le modèle lexical et la combinaison sémantique sont sélectionnés sur le
développement. Le seuil utilise uniquement les messages légitimes de calibration.
Le test ne sélectionne ni poids, ni hyperparamètres, ni seuil.

Le dossier publié atomiquement contient `model.json`, `report.json`,
`predictions.json` et, pour le mode hybride, `native-combination.json` lié à
l’empreinte SHA-256 exacte du modèle lexical. Tous ces fichiers restent privés.
Les prédictions permettent de contrôler la concordance avec Rust sans garder
les corps. Il n’y a ni pickle exécutable ni accès réseau pendant l’entraînement.
L'option `--aggregate-only` omet `predictions.json` et conserve les poids et les
métriques agrégées. Le service périodique utilise toujours cette option. Un jeu
valide qui manque d'exemples des deux classes retourne le code 3 avec
`status: insufficient_feedback`, sans candidat ; un export invalide ou une erreur
du solveur reste un échec distinct.

## Exécution périodique et limites

`deploy/noisefence-train.service` choisit le pipeline selon le modèle configuré :
ancien entraînement Rust pour les caractéristiques historiques, nouveau runtime
pour le schéma 3. L’environnement Python doit être préparé avant d’activer le
timer pour ce dernier. Un autre chemin peut être indiqué par
`NOISEFENCE_TRAIN_PYTHON` dans `/etc/noisefence/training.env`.

Le service est limité à deux CPU, 4 Go de mémoire et 35 minutes, avec réseau
désactivé et une priorité OOM moins favorable que le service SMTP. Un verrou
empêche deux entraînements simultanés. L'export et l'entraînement utilisent la
même release résolue du binaire, même pendant une mise à jour. Les candidats sont
écrits dans `/var/lib/noisefence/models/candidates/` ; `latest-candidate.json`
désigne le dernier entraînement réussi. Un échec préserve le candidat précédent.
Le snapshot du service se trouve dans le répertoire privé `/run/noisefence-learning`,
géré par `RuntimeDirectory` de systemd. Il est supprimé après le traitement,
y compris lors d'une terminaison brutale du service ; un redémarrage du serveur
efface aussi ce stockage temporaire. Ce comportement est testé sous Linux avec
sortie normale et SIGKILL. Les candidats agrégés sont préparés sur leur système
de fichiers puis publiés par renommage atomique. Ils ne contiennent ni liste de
messages, ni labels individuels, ni vecteurs par message. Un arrêt brutal peut
laisser un dossier `.candidate-stage-*` de poids partiels, sans snapshot privé ;
celui-ci ne devient pas le dernier candidat. Les poids appris ne constituent
pas une garantie d'anonymisation.

`last-training.json` indique `candidate_prepared`, `insufficient_feedback` ou
`failed`, avec des dates et compteurs agrégés. Un manque de corrections laisse
le service terminer normalement et préserve le candidat précédent. Une erreur
réelle échoue ; une terminaison brutale est aussi visible dans l'état systemd
et peut empêcher l'écriture du dernier statut JSON. Le service crée ses
répertoires au premier démarrage.

Après installation du runtime et de la release :

```sh
sudo install -m 0644 /opt/noisefence/current/deploy/noisefence-train.service /etc/systemd/system/
sudo install -m 0644 /opt/noisefence/current/deploy/noisefence-train.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start noisefence-train.service
sudo systemctl enable --now noisefence-train.timer
sudo cat /var/lib/noisefence/models/last-training.json
systemctl status noisefence-train.service noisefence-train.timer
```

Un lancement manuel peut choisir un répertoire privé avec `--scratch-directory`.
Sans systemd, il ne bénéficie pas du nettoyage après SIGKILL. Les exports manuels,
prédictions individuelles de recherche et sauvegardes doivent être purgés
séparément selon la conservation à 30 jours ; ils ne sont pas gérés par le timer.

**Un candidat issu des seules corrections porte toujours `eligible: false`.**
Les erreurs signalées sont un échantillon biaisé, et les mêmes tests peuvent être
revus lors des entraînements périodiques. Le rapport n’autorise donc aucune
activation automatique. Il faut une évaluation récente, indépendante et
représentative de la chaîne complète avant activation du marquage. Un modèle
hybride doit être déployé avec les deux fichiers compatibles ; remplacer son seul
modèle lexical invaliderait la liaison vérifiée au démarrage.

Les corrections peuvent être erronées ou abusives. Le regroupement limite la
surreprésentation d’une même campagne ; il ne remplace pas la revue des données
et ne garantit pas la résistance à l’empoisonnement par un compte autorisé.
