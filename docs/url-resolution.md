# Suivi des URLs

Disponible depuis **0.5.0-dev.15** dans les protections complémentaires. Dans
**Filtres → Protections complémentaires**, activer **Suivre les redirections des
liens**, puis **Vérifier et appliquer**. La révision est auditée comme les autres
réglages. Les configurations existantes conservent le suivi désactivé.

Les nouveaux messages reçus par SMTP font alors l’objet de visites HTTP GET
automatiques. Le traitement local hors ligne n’ouvre aucun lien. Une visite
peut déclencher un compteur de suivi, révéler l’IP du serveur au site ou consommer
un lien à usage unique : cette conséquence est rappelée dans la console.

## Parcours et vérifications

Le moteur extrait les URLs HTTP/HTTPS du texte, des ancres HTML et du texte
OCR/QR. Il suit les réponses 301, 302, 303, 307 et 308, les en-têtes `Refresh`
et les balises HTML `meta refresh`, avec résolution des chemins relatifs, des
entités HTML et de la première balise `base`. Les délais de rafraîchissement
valides ne provoquent pas d’attente. Les boucles et redirections ambiguës
interrompent le parcours.

Chaque URL visitée, y compris la destination finale, est comparée exactement à
la base locale de phishing si le contrôle des liens est activé. Les domaines
découverts rejoignent les consultations CRDF et VirusTotal lorsqu’elles sont
configurées. Les dernières destinations sont prioritaires dans le budget de
douze indicateurs par fournisseur ; cela ne garantit pas une consultation si le
quota ou le délai est épuisé. Les chemins et paramètres complets restent locaux
pour ces consultations : les connecteurs envoient des domaines, pas des URLs.

Le moteur n’exécute pas JavaScript et ne charge ni images, ni iframes, ni scripts,
ni feuilles de style. Il ne soumet pas les formulaires et ne réutilise ni cookies,
ni authentification, ni référent HTTP. Une page HTML contenant des scripts sans
redirection déclarative est signalée comme incomplète. Les contenus compressés
malgré `Accept-Encoding: identity` et les HTML non UTF-8 sont également incomplets.
Un contenu non HTML termine le parcours HTTP sans analyse de son corps. Ce
résolveur HTTP ne reproduit donc pas toutes les navigations d’un navigateur.

La console affiche les domaines enregistrables des sauts, les codes HTTP, la
durée, le motif d’interruption et les omissions. « Destination HTTP atteinte »
n’est pas un verdict de sûreté. Une indisponibilité ou un quota ne devient pas
une preuve de spam. Ces observations restent consultatives, comme les autres
protections complémentaires : elles ne créent pas de poids arbitraire dans le
classement. Un parcours absent, incomplet ou tronqué interdit néanmoins les
raccourcis de confiance de l’historique expéditeur lorsque le suivi est activé.

## Limites et réseau

Réglages du serveur, avec redémarrage après modification des limites :

```toml
[protection.url_resolution]
timeout_ms = 1200
max_urls = 4
max_redirects = 5
max_parallel = 2
blocked_ips = []
```

Le délai de 1,2 seconde couvre toutes les URLs et tous leurs sauts pour un même
message ; il n’est pas renouvelé à chaque connexion. Le délai global d’analyse
du message reste applicable. Au plus deux messages effectuent ce travail en
même temps ; une saturation est immédiatement signalée. Chaque URL reçoit au
plus cinq redirections, soit six requêtes. Chaque réponse HTML est limitée à
64 Kio, y compris lorsqu’elle arrive en morceaux. Le nombre d’éléments de
navigation HTML examinés est borné. Au plus huit URLs sont retenues à
l’extraction ; une troncature est indiquée, avec un nombre d’omissions minimal
quand le total exact n’est pas disponible.

Avant chaque connexion, le moteur résout les familles A et AAAA, contrôle toutes
les adresses et les fixe dans un nouveau client HTTP. Les redirections
automatiques du client et les proxys d’environnement sont désactivés. Seuls
HTTP sur 80 et HTTPS sur 443 sont autorisés, avec vérification normale du
certificat et du nom TLS. Les URLs contenant des identifiants sont refusées.
Les adresses privées, locales, réservées, de métadonnées cloud, les mécanismes
de transition IPv6 et les adresses des interfaces du serveur sont exclus.
Une réponse DNS partiellement indisponible interrompt le parcours.

`blocked_ips` permet aussi d’exclure les IP publiques de NAT ou d’administration
qui ne figurent pas sur une interface locale. Ces contrôles s’exécutent dans
le processus NoiseFence ; ils ne constituent pas un espace réseau séparé.
Pour le déploiement, compléter les exclusions selon la topologie et appliquer
la même séparation des réseaux internes au filtrage de sortie. Ce fonctionnement
s’appuie sur les [recommandations OWASP contre les SSRF](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

## Conservation et tests

Les réponses HTML sont abandonnées après inspection. Le rapport conserve les
empreintes SHA-256 des URLs, les domaines enregistrables sans sous-domaines,
les codes HTTP et les états. Il ne conserve ni chemin, ni requête, ni page
téléchargée. Il suit les autorisations et la conservation des diagnostics du
message ; les anciens messages ne se voient pas attribuer une visite inventée.

Les tests utilisent uniquement des serveurs locaux et des messages synthétiques :
redirections HTTP et HTML, requêtes sans secrets, réponses TLS non fiables,
changement DNS entre deux sauts, destinations privées, boucles, plafonds,
expiration, quotas fournisseur et correspondance exacte de la destination dans
la base locale. Ils ne mesurent pas un taux de capture sur du trafic réel.
