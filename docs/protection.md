# Protections complémentaires

Disponibles depuis 0.3.0-dev.16. Les observations sont visibles dans le détail des
messages et l’export `export-learning`, conservées 30 jours avec les métadonnées.
Elles ne changent pas le score, le modèle, le préfixe, les corps ou les décisions
Proton. Une nouvelle calibration indépendante sera nécessaire pour les intégrer
au classement. Les indicateurs d’un même domaine et les familles de détection
sont regroupés : une détection HTML, QR, CRDF et VT ne constitue pas quatre preuves
indépendantes. Les rapports sont calculés localement ; aucun en-tête fourni par
l’expéditeur ne peut forger une observation NoiseFence.

Ajouter au TOML initial, puis redémarrer le service :

```toml
[protection]
timeout_ms = 1200
max_parallel = 2
crdf_per_minute = 2
crdf_per_day = 200
virustotal_per_minute = 4
virustotal_per_day = 500
```

Les plafonds sont des budgets locaux conservateurs, à adapter au contrat réel.
Leurs compteurs persistent sur disque et ne sont pas réinitialisés par le redémarrage du
service ni par un changement de plafond. Les réglages de la console priment sur ceux du TOML une fois une
révision enregistrée ; activer le module dans Filtres après son installation.

## Console et clés

Dans **Filtres → Protections complémentaires**, renseigner une clé CRDF et/ou
VirusTotal, cliquer sur **Enregistrer la clé**, activer le connecteur puis
**Vérifier et appliquer**. Les clés sont stockées dans
`/var/lib/noisefence/protection/crdf.key` et `virustotal.key`, fichiers 0600 dans
un répertoire 0700. Elles ne sont jamais renvoyées par l’API, incluses dans les
révisions, les journaux, les commandes, Git ou les archives publiques. La
modification nécessite un administrateur actif, une session valide, la bonne
origine et un jeton CSRF. Chaque sauvegarde de clé est auditée sans sa valeur.
Le remplacement prend effet aux prochains appels, sans redémarrage. Désactiver
le connecteur dans la console pour arrêter les consultations.

Les paramètres `identity`, `links`, `campaigns`, `crdf`, `virustotal`, `follow_urls`, les noms
protégés et les exceptions de réponse/suivi sont versionnés dans la console.
Les exceptions portent sur un hôte exact et une seule heuristique : elles ne
contournent jamais SPF/DKIM/DMARC, la réputation, l’antivirus ou le modèle.

## Quotas configurables (depuis 0.4.5)

Dans chaque carte de fournisseur, désactiver **Utiliser les plafonds du serveur**
pour choisir des limites par minute et par jour. **Clé illimitée** enlève les deux
plafonds ; les cases **Illimité** permettent aussi de ne lever qu’une limite.
Enregistrer avec **Vérifier et appliquer**. Le changement est audité, versionné et
s’applique dès la prochaine transaction SMTP, sans redémarrage. Un message déjà
en cours conserve sa politique. **Actualiser les compteurs** affiche l’usage actuel.

L’API de configuration accepte `crdf_quota` et `virustotal_quota` dans `protection`,
par exemple `"crdf_quota": {"minute": 0, "day": 0}`. Zéro signifie explicitement
illimité ; tout entier positif jusqu’à 4 294 967 295 est un plafond. Les deux champs
sont obligatoires dans un objet de quota. Un quota absent ou `null` hérite des valeurs
du TOML (`crdf_per_minute`, etc.), qui acceptent également zéro. Les anciennes
révisions conservent donc leurs plafonds initiaux. Le connecteur se désactive avec
son interrupteur, jamais avec un quota zéro. Les budgets sont indépendants par
fournisseur et partagés entre domaines, utilisateurs et connexions du serveur.

Les compteurs mesurent les requêtes réservées avant l’appel HTTP, même si celui-ci
échoue ou est annulé. Le cache ne les consomme pas. Les fenêtres sont fixes :
minute UTC et jour UTC (remise à zéro à minuit UTC). Modifier les limites ou la clé
ne remet pas les compteurs à zéro. Le mode illimité continue de compter les appels.
L’API administrateur `/admin/protection` expose les limites effectives, celles du
TOML, la consommation, les échéances et la pause éventuelle ; une lecture impossible
donne un compteur indisponible, pas un faux zéro.

« Illimité » retire uniquement les budgets locaux. La concurrence, les délais,
les douze indicateurs maximum par fournisseur/message, le cache et les pauses de
cinq minutes en cas de refus du fournisseur restent actifs. Les quotas ne changent
pas les scores. Les limites de capacité restent dans le TOML et nécessitent un
redémarrage. Revenir à un ancien binaire exige d’abord de restaurer une révision
sans les nouveaux champs de quota ; aucun changement du schéma SQLite n’est requis.

## CRDF et VirusTotal

CRDF utilise **POST `search_urls.json`**, droit `lookup`, clé dans `X-API-Key`.
Seuls des domaines sont communiqués, sous la forme d’une racine synthétique
`https://domaine/` acceptée par cette API. Aucun chemin, paramètre ou fragment
du message n’est transmis. Les domaines nus étaient refusés comme URL invalides ;
ce format est corrigé depuis 0.4.5. La méthode ne soumet pas d’URL à l’analyse et
n’appelle pas `submit_url`, `ai_score` ou les API de modification. Une absence de
résultat reste « inconnu ». Une correspondance portant seulement sur un chemin
ou une requête reste suspecte au niveau du domaine, sans condamner tout un
service partagé. Un résultat contradictoire, mal formé, refusé ou
indisponible ne devient pas une détection.

VirusTotal utilise seulement **GET `/api/v3/domains/{domain}`** et
**GET `/api/v3/files/{sha256}`**, clé dans `x-apikey`. Aucun message, fichier,
URL complète, paramètre de lien ou texte OCR n’est envoyé. Un fichier inconnu
n’est pas téléversé. Un rapport de plus de sept jours est signalé comme ancien.
Les détections de moins de trois moteurs restent suspectes, pas un verdict
malveillant automatique. Le nombre de moteurs ne constitue pas une probabilité
calibrée ni une preuve d’indépendance des signatures.

L’API publique VirusTotal interdit certains usages en produit/service commercial
et les processus métier ne contribuant pas de nouveaux fichiers. Pour cette
passerelle d’organisation, utiliser une licence autorisant explicitement ces
consultations ; une simple clé gratuite n’est pas suffisante. Les données des
fournisseurs ne sont pas redistribuées avec le logiciel GPL.

Les appels aux fournisseurs utilisent TLS vérifié et les deux API fixes, sans
suivre leurs redirections HTTP. Les réponses sont limitées à 256 Kio. Huit
domaines et huit empreintes au maximum sont extraits du message. Le suivi
optionnel des liens ajoute les domaines des sauts effectivement visités et
traite leurs dernières destinations en priorité. Il reste au plus douze
consultations par fournisseur et message ; les cibles omises et les quotas
sont indiqués dans le rapport. Le délai est commun à toutes les consultations d’un
fournisseur, pas renouvelé pour chaque cible. Les caches durent au plus 30
minutes (cinq minutes pour inconnu/ancien) et contiennent des empreintes, jamais
les clés ou URLs. Les erreurs de droits/quota déclenchent une pause de cinq
minutes. Les plafonds, pauses et états incomplets sont explicites ; aucun ne
change le classement actuel.

Spamhaus DQS reste disponible via `filter.spamhaus_key_env`, avec une clé
commercialement autorisée dans l’environnement systemd. Il possède déjà ses
contrôles de codes de retour, cache DNS et traitement séparé des erreurs.

## Usurpation et campagnes

Les domaines sont normalisés avec IDNA et comparés avec une Public Suffix List
embarquée, y compris les suffixes privés. Les ressemblances couvrent les fautes
à une modification et un sous-ensemble d’homoglyphes courants ; elles ne
constituent pas une couverture exhaustive d’Unicode. Les noms affichés doivent
correspondre exactement à un nom protégé configuré. L’alignement DMARC est
présenté séparément : le simple nom affiché n’est jamais authentifié.

Les campagnes utilisent au plus les 1 000 messages récents de la fenêtre de
30 jours. Seuls les retours d’administrateurs encore actifs sont utilisés. Au
moins deux messages de contenus distincts confirmés spam sont requis ; un
retour légitime contradictoire annule la correspondance. Les messages trop
courts ou les transactions couvrant plusieurs domaines restent non évalués.
Les empreintes exactes/SimHash sont comparées dans le domaine de destination,
sans révéler des identifiants, destinataires cachés ou messages d’autres domaines.
Les corrections peuvent prendre effet sur les prochains messages, jamais sur
les messages déjà livrés. La recherche reste consultative et bornée en temps.

## Base locale de liens

Les liens HTML sont parsés avec un parseur HTML5. Les URLs du texte, des ancres,
des formulaires et du texte OCR/QR rejoignent le même ensemble pour l’analyse
passive. Par défaut, les liens ne sont pas ouverts. Depuis 0.4.4,
**Suivre les redirections des liens** active les visites HTTP des liens du texte,
des ancres et de l’OCR/QR ; les actions de formulaire restent passives.
Le détail des limites, effets des visites et protections réseau figure dans
[Suivi des URLs](url-resolution.md).
Une base correspond à des URLs exactes (chemin/requête
conservés), sans condamner tout un service partagé pour une page malveillante.

Importer un flux texte autorisé, une URL par ligne :

```sh
sudo -u noisefence python3 /opt/noisefence/current/deploy/update-url-feed.py \
  --input /chemin/flux-autorise.txt
```

Ou installer les unités `noisefence-url-feed.service` et `.timer`, créer
`/etc/noisefence/url-feed.env` en 0600 contenant
`NOISEFENCE_PHISHING_FEED_URL=https://fournisseur/flux-autorise`, puis activer le
timer. Les unités ne sont pas activées sans source autorisée configurée.
Le flux OpenPhish Community est un exemple de format compatible ; vérifier ses
conditions d’usage avant configuration. Aucun flux commercial n’est embarqué.

Téléchargement HTTPS de 20 secondes maximum, 8 Mio/50 000 URLs, remplacement
atomique après validation ; un échec conserve le flux précédent. La base est
rechargée sous 60 secondes, et ignorée si elle a plus de 72 heures. Une base
absente ou ancienne reste distincte d’une base sans correspondance. Les liens
et paramètres du flux restent côté serveur et ne sont pas affichés dans la
console. Le parseur local limite les MIME, le HTML et les indicateurs examinés.

## Validation

Les fixtures locales couvrent domaines ressemblants, liens trompeurs, entités
HTML, suffixes publics/privés, exceptions exactes, QR/HTML corrélés, expiration
de flux, pièces jointes encodées, erreurs fournisseurs, quotas persistants,
contradictions de campagnes, accès administrateur/CSRF et invariance du score.
Aucun test n’envoie de message, de pièce jointe privée ou d’appel payant.

Sources : [CRDF](https://threatcenter.crdf.fr/api/doc/),
[VirusTotal domaines](https://docs.virustotal.com/reference/domain-info),
[VirusTotal fichiers](https://docs.virustotal.com/reference/file-info),
[restrictions VirusTotal](https://docs.virustotal.com/reference/public-vs-premium-api),
[OpenPhish](https://www.openphish.com/phishing_feeds.html).
