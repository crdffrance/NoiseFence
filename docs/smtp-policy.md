# Contrôles de cohérence SMTP et DNS

NoiseFence reprend des principes de
[policyd-weight](https://github.com/policyd-weight/policyd-weight/tree/18d2e97a40b7d836d35e25921def508e6a719e49) :
croiser l'identité HELO/EHLO, l'IP de connexion, le DNS inverse et le domaine de
l'expéditeur d'enveloppe, avec des poids et un cache. L'implémentation Rust est
indépendante ; aucun code Perl, ancienne liste DNSBL ou coefficient historique
n'est incorporé. Le dépôt de référence indique que le projet est abandonné.

Les vérifications utilisent l'IP de la socket, le dernier HELO/EHLO et MAIL FROM.
Les en-têtes `Received`, `Authentication-Results` et `X-NoiseFence-*` reçus ne
fournissent jamais ces identités. SPF/DKIM/DMARC et Spamhaus DQS restent leurs
propres signaux existants : ils ne sont pas comptés une deuxième fois ici.
Le connecteur DQS existant interroge aussi le HELO et le domaine de MAIL FROM,
en priorité avant les liens du corps ; il conserve au plus 12 domaines uniques
et une seule contribution de réputation de domaine par message. Son activation
exige toujours une clé Spamhaus autorisée ; aucune nouvelle liste publique
n’est activée implicitement. Une absence de résultat DNSBL n’est pas un certificat
de légitimité.

## Activer l'observation

Ajouter une table de premier niveau dans la configuration, puis vérifier celle-ci
et redémarrer le service :

```toml
[smtp_policy]
contribute_to_score = false
timeout_ms = 800
max_parallel = 8
cache_entries = 4096
cache_ttl_seconds = 300
```

La table absente désactive le module. Avec `contribute_to_score = false`, les
résultats sont calculés et visibles sans changer le score du message. Le champ
`candidate_weight` permet de mesurer la contribution proposée. Après calibration,
`contribute_to_score = true` applique cette contribution. Le mode global
`filter.mode` et la validation Proton continuent à contrôler le marquage.

## Signaux de la version `smtp-policy-1`

Les poids sont des contributions au logit, pas des pourcentages ni une mesure de
probabilité. Ils sont expérimentaux et n'ont pas encore de gain de capture démontré.

| Vérification | Observation | Poids candidat |
|---|---|---:|
| HELO/EHLO | Nom résolvant vers l'IP de connexion | −0,15 |
| HELO/EHLO | Littéral IPv4/IPv6 correspondant | 0 |
| HELO/EHLO | Adresse différente / aucune adresse | +0,25 / +0,5 |
| HELO/EHLO | Littéral différent ou syntaxe inhabituelle | +0,5 |
| HELO/EHLO | Client annonçant le nom de cette passerelle | +0,75 |
| PTR | Au moins un nom confirmé par A/AAAA vers l'IP | −0,15 |
| PTR | Absent / aucun nom confirmé | +0,25 / +0,5 |
| MAIL FROM | MX présent ou repli A/AAAA sans MX | 0 |
| MAIL FROM | Enveloppe vide de notification de livraison | 0 |
| MAIL FROM | Null MX ou aucune route MX/A/AAAA | +0,75 |

Une seule observation par famille entre dans la somme. La contribution totale
est plafonnée entre **−0,25 et +1,5**, car HELO et PTR sont corrélés. Les crédits
DNS ne court-circuitent jamais l'analyse du contenu, de l'authentification ou
de la réputation. Le MX indique ici une déclaration DNS : sa présence ne prouve
ni l'accessibilité SMTP de sa cible ni la légitimité du message.

Un serveur sortant n'a pas à correspondre au MX entrant du domaine. Les noms
dynamiques, ressemblances textuelles entre domaines et appartenances à un /24
ne constituent pas des preuves d'usurpation. Ils ne reçoivent donc pas de poids.
Le repli A/AAAA est respecté selon
[RFC 5321 §5.1](https://www.rfc-editor.org/rfc/rfc5321.html#section-5.1).
Le Null MX unique `0 .` est distingué de l'absence de MX, suivant
[RFC 7505](https://www.rfc-editor.org/rfc/rfc7505.html).

## Délais, erreurs et traçabilité

Le module s'exécute après DATA, en parallèle des contrôles d'authentification et
dans leur délai global de cinq secondes. Il ne change aucune réponse de refus
fondée sur le score et ne rejette pas un message à cause du HELO, conformément à
[RFC 5321 §4.1.4](https://www.rfc-editor.org/rfc/rfc5321.html#section-4.1.4).
Cette version ne cherche donc pas à économiser le transfert du corps avant DATA.

Son délai propre est de 800 ms par défaut, au plus 2 000 ms. Au maximum huit
analyses de politique sont actives par défaut ; une saturation rend le contrôle
indisponible immédiatement. Aucune tâche DNS applicative détachée n'est lancée.
Les noms sont validés et interrogés comme noms absolus auprès du résolveur système.
Aucun lien n'est ouvert, aucune adresse de destinataire ni contenu transmis au DNS.

Les recherches portent sur au plus quatre PTR, 32 réponses par requête et
14 recherches A/AAAA/PTR/MX par analyse, hors retransmissions internes du résolveur.
Le cache applicatif est borné en nombre d'entrées et respecte les TTL positifs et
négatifs, avec un plafond configuré. Un TTL nul n'est pas mis en cache. Une erreur
du résolveur est mémorisée une seconde comme **indisponible**, jamais comme absence.
Le résolveur Hickory possède aussi son cache DNS interne.

SERVFAIL, REFUSED, timeout, erreur sur une famille IP, réponse incohérente ou
dépassement du budget PTR rendent le résultat incomplet. Les contributions
partielles sont abandonnées, le score local est conservé et la livraison se fait
sans préfixe. Une confirmation positive d'un PTR suffit même si un autre PTR
n'est pas confirmable. Les erreurs d'autres familles de contrôles restent visibles.

Le résultat `smtp_policy` contient version, statut, durée, observations,
`candidate_weight`, `applied_weight` et `scoring_enabled`. Il est conservé avec
les métadonnées pendant 30 jours et soumis aux droits existants par destinataire.
Les anciens messages sans ce champ se lisent comme module désactivé. Les poids
et caractéristiques du classifieur de contenu ne sont pas modifiés.

## Tester sans envoyer de message

```sh
noisefence --config /etc/noisefence/config.toml smtp-check \
  --source-ip 192.0.2.10 --helo mx.sender.example \
  --mail-from sender@sender.example --iterations 3
```

Remplacer les valeurs de documentation par un contexte SMTP réellement observé.
La commande renvoie une ligne JSON par essai, sans ouvrir la file, charger le
modèle, appeler le LLM ou envoyer un email. Elle accepte aussi `--mail-from ''`
et `--helo '[IPv6:2001:db8::10]'`. Les répétitions partagent le cache ; la première
mesure doit rester séparée des suivantes. `analyze` et le banc `pipeline_probe`
incluent ces contrôles lorsque la table est configurée. `scan`, qui ne connaît
pas le contexte SMTP d'origine, reste une analyse hors réseau du contenu.

Les tests utilisent des réponses DNS déterministes pour les identités IPv4/IPv6,
plusieurs PTR, Null MX, repli implicite, NXDOMAIN/NODATA, erreurs temporaires,
cache, plafonds et délais. Les mesures sur les corpus de contenu ne permettent
pas d'évaluer cette couche sans les IP et enveloppes originales fiables.
