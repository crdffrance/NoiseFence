# Réputation IP avant DATA

NoiseFence interroge les listes IP DNSBL configurées après validation d’au moins
un destinataire, avant la réponse `354`, le stockage du corps et l’acquisition
d’une capacité d’analyse. Un refus à cette étape évite OCR, antivirus, modèles,
redirections et API de réputation. En observation, ces analyses continuent :
aucune économie de contenu ni amélioration du taux de capture n’est revendiquée.

Seule l’IP de la connexion TCP est utilisée. Un `Received`, un HELO, un expéditeur
ou un en-tête `X-NoiseFence-*` fourni dans le message ne peut la remplacer.
Les IP privées et réservées sont ignorées ; placer un proxy SMTP devant cette
écoute fait donc perdre la réputation du véritable pair. Aucun protocole PROXY
ni en-tête de confiance implicite n’est accepté.

## Configuration

Sans listes ni clé DQS, aucun appel DNSBL n’est fait. L’intégration Spamhaus utilise
la variable déjà déclarée dans `[filter].spamhaus_key_env` et ajoute ZEN aux
contrôles précoces. Désactiver « Réputation » dans la console désactive aussi ce
contrôle ZEN. Les listes supplémentaires sont administrées dans le fichier du
serveur et demandent un redémarrage ; elles ne dépendent pas de cet interrupteur.

```toml
[rbl]
action = "observe"          # observe, defer (451), reject (550)
minimum_providers = 2       # de 1 à 8 ; opérateurs distincts
timeout_ms = 800            # budget global ; 10 à 2 000 ms
max_parallel = 8            # requêtes DNS actives partagées entre connexions
cache_entries = 4096        # 1 à 16 384 entrées
cache_ttl_seconds = 60      # plafond, sans prolonger le TTL DNS

# Exemple fictif à remplacer par une liste IP autorisée et ses codes documentés.
[[rbl.lists]]
id = "provider_a_ip"
provider = "provider_a"
zone = "dnsbl.provider.example"
listed_codes = ["127.0.0.2"]
observe_codes = ["127.0.0.10"]
ipv6 = false               # true seulement si le fournisseur prend en charge IPv6
# key_env = "PROVIDER_A_DNS_KEY" # requête IP-inversée.clé.zone si nécessaire
```

Les sept listes personnalisées maximum s’ajoutent au connecteur ZEN. Le même
`provider` doit identifier toutes les listes d’un même opérateur : deux zones
de cet opérateur ne constituent qu’un vote. Une seule liste avec le seuil par
défaut produit des observations, sans refus. Les zones Spamhaus sont réservées
au connecteur DQS pour conserver l’interprétation de leurs catégories et erreurs.
Les codes des autres fournisseurs sont des adresses IPv4 **exactes**, sans masque
ni logique bit à bit ; renseigner toutes les combinaisons documentées ou ne pas
utiliser une liste incompatible. Ne jamais inscrire les codes d’erreur dans
`listed_codes` ou `observe_codes`.

Pour appliquer un refus, il faut simultanément `filter.mode = "enforce"`, une
action RBL `defer` ou `reject`, assez de fournisseurs positifs et aucun résultat
indisponible. Le mode `observe` ou `tag` impose toujours l’observation, quelle que
soit l’action RBL demandée. Les validations de configuration et de livraison
existantes restent exigées. Les destinataires inconnus restent refusés séparément.

Les refus `451`/`550` interviennent avant acceptation SMTP : aucun message n’est
mis en file et aucun avis d’échec n’est généré par NoiseFence. L’émetteur traite
la réponse SMTP. Après refus, une nouvelle transaction exige `MAIL` et `RCPT`.
`defer` est un refus temporaire de réputation, **pas du greylisting** : il n’existe
pas de temporisation d’un triplet expéditeur/destinataire/IP ni de liste de passage
automatique au deuxième essai. Les limites existantes de connexions, de connexions
par IP et d’analyses restent indépendantes ; aucun quota horaire n’est ajouté ici.

## Résultats, limites et faux positifs

- Seul NXDOMAIN signifie « non listée ». NODATA, SERVFAIL, REFUSED, timeout,
  réponse inattendue ou mixant codes valides et codes d’erreur sont indisponibles.
  Une IP non listée n’est pas une preuve de légitimité.
- ZEN SBL/CSS/XBL/DROP constitue un vote ; PBL et BCL restent des observations
  sans vote. Ces catégories et codes sont vérifiés dans le connecteur existant.
- IPv4 utilise les octets inversés, IPv6 les 32 chiffres hexadécimaux inversés.
  Les adresses IPv4 mappées en IPv6 sont normalisées. Chaque requête demande des
  enregistrements A même pour une IP IPv6, avec un plafond de 32 réponses.
- Les requêtes avancent concurremment dans un délai global, sans tâche applicative
  détachée. Une saturation rend le contrôle indisponible immédiatement. Le cache
  est utilisable même lorsque toutes les capacités DNS sont occupées. Les erreurs
  reçues sont mémorisées une seconde comme indisponibles ; un timeout n’est pas
  mémorisé. Les TTL positifs/négatifs nuls ne sont pas prolongés.
- Les TXT du fournisseur ne sont ni affichés ni interpolés dans SMTP. Les rapports
  ne contiennent que noms logiques des listes, codes, disponibilité, durée, cache
  et action. Les requêtes contenant une clé ne sont jamais journalisées par ce
  module ; éviter les logs de débogage DNS du résolveur sur un service à clé.

Le rapport `early_rbl` est attaché aux messages acceptés **après** le calcul des
décisions : il ne change ni score ni complétude et ne double pas le poids ZEN
existant. Le contrôle ZEN après DATA est conservé, avec son propre cache et sa
propre vérification : un transfert DATA long peut avoir dépassé le TTL observé
avant réception. DBL, les domaines du corps et les destinations des URL restent
contrôlés après réception. Une URIBL de domaines ne doit pas être configurée
comme une DNSBL d’IP.

Le journal `SMTP early RBL check` conserve aussi les décisions de refus, qui
n’apparaissent pas comme messages dans la console puisqu’aucun corps n’a été
accepté. La fiche d’un message accepté affiche les contrôles avant réception,
dans le périmètre des droits habituels. La rétention des métadonnées reste de
30 jours et SQLite conserve le schéma 2.

## Vérifier sans envoyer d’email

```sh
noisefence --config /etc/noisefence/config.toml rbl-check \
  --source-ip 8.8.8.8 --iterations 3
```

Cette commande n’ouvre ni file ni modèle et ne transmet aucun message. Elle
effectue de vraies requêtes IP auprès des seules listes configurées ; vérifier
le droit d’usage, le résolveur et les quotas du fournisseur au préalable. Elle
utilise le fichier de configuration, pas la révision effective de la console.
Tester également une IP publique positive et une IP publique négative fournies par l’opérateur,
puis observer un échantillon récent et annoté avant toute application de refus.

Les tests automatisés utilisent uniquement des réponses déterministes et des
sockets locaux, avec contrôle des erreurs DNS, du cache, des délais, des codes,
du consensus, de la livraison en observation et du refus avant stockage/analyse.
Ils ne mesurent pas la couverture d’une liste sur le trafic réel.

Migration : champs de rapport optionnels lisibles sur les anciens messages et
ignorés par 0.6.0. Le changement de code modifie l’empreinte de compatibilité du
détecteur ; les candidats qualité/fusion optionnels doivent être reconstruits
sur une collecte compatible avant activation. Aucun modèle n’est activé ni seuil
de classification changé par cette version. Pour revenir à 0.6.0, retirer la
nouvelle table `[rbl]` du fichier de configuration si elle a été ajoutée, en
conservant la file et la base courantes.

Références : [format DNSBL, RFC 5782](https://www.rfc-editor.org/info/rfc5782/),
[requêtes DQS](https://docs.spamhaus.com/datasets/docs/source/70-access-methods/data-query-service/040-dqs-queries.html),
[codes et catégories Spamhaus](https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/040-zones.html),
[conditions d’usage Spamhaus](https://www.spamhaus.org/faqs/dnsbl-usage/).
