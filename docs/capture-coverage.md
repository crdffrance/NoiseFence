# Couverture et contexte du filtrage — 0.6.0

## Réputation et redirections

Le cache des douze cibles prioritaires est consulté avant les portes de capacité,
quotas et pauses fournisseur. Les destinations découvertes restent prioritaires.
Les cibles supplémentaires sont comptées comme omises. Une absence d’information,
un rapport VirusTotal ancien ou une erreur ne vaut jamais preuve de malveillance.

[CRDF search_urls](https://threatcenter.crdf.fr/api/doc/) accepte une liste de
cibles. NoiseFence regroupe jusqu’à douze racines de domaines par requête, sans
adresses de messagerie, chemin, paramètres d’URL ou corps. Chaque réponse doit
correspondre une seule fois à une cible demandée. Une réponse mal associée invalide
le lot. Une détection de page ne condamne pas son domaine entier. VirusTotal utilise
uniquement les rapports existants de domaines ou empreintes ; aucune soumission
nouvelle de contenu ou fichier.

La limite compte les réservations de requêtes, après acquisition d’une capacité
réseau. Une panne au moment de l’envoi peut conserver une réservation sans réponse :
le compteur reste prudent. Les caches individuels et les compteurs UTC persistent.
Zéro reste « illimité », sans supprimer les limites de parallélisme et de durée.
Le client n’effectue pas de reprise implicite. Une erreur de connexion ou HTTP
502/503/504 sans pause explicite permet au plus une reprise, après 50 ms, avec une
nouvelle réservation et dans le même délai global. Les erreurs 429/authentification
ne sont pas reprises. La pause `Retry-After` valide sur 429/503 est persistée et
bornée à sept jours ; un délai plus long déjà enregistré reste prioritaire.
Voir aussi [les erreurs VirusTotal](https://docs.virustotal.com/reference/errors).

Les chaînes de redirection utilisent les capacités partagées disponibles dans un
délai global. Une chaîne lente ne bloque pas les autres capacités. Le client garde
la vérification DNS de chaque saut, l’épinglage réseau, les certificats TLS, les
adresses interdites et la limite de lecture de 64 Kio. Il n’exécute pas JavaScript.
Les pages volumineuses ou dépendantes d’un script restent incomplètes. La fin d’une
analyse annule ses tâches HTTP ; aucune exploration continue en arrière-plan.

## Exploiter les diagnostics

La page Fiabilité montre les requêtes, réponses HTTP, incidents récupérés ou non,
pauses et indicateurs omis. Les raisons de redirection distinguent contraintes de
sécurité, transport, capacité de lecture et réponses distantes. Le groupe courant
est séparé des dernières 24 h toutes versions confondues. Les anciens messages
n’ont pas tous les nouveaux compteurs ; zéro historique ne prouve pas zéro requête.

Le contexte des spams manqués et des abstentions porte exclusivement sur les cas
annotés spam par le compte autorisé. Les corrections ciblées restent séparées des
annotations qualité. Plusieurs incidents peuvent concerner un même message ; ils
sont des pistes de diagnostic, pas une démonstration causale. Les jeux synthétiques
de régression couvrent notamment les quotas avec résultat malveillant en cache,
les reprises, les cibles mal associées, les liens lents et les changements de
correspondant. Ils ne mesurent pas le rappel sur le trafic réel.

## Mémoire comportementale consultative

Une identité doit provenir d’une session SMTP, avec une unique adresse From et un
DKIM aligné DMARC. La clé inclut le domaine destinataire. Les observations incluent
une empreinte de l’unique destinataire d’enveloppe, au plus huit domaines de liens
hachés dans ce périmètre et six types de motifs natifs, sans conserver le texte.
Un message avec plusieurs destinataires d’enveloppe ne conserve pas ce contexte ;
aucune identité de copie cachée n’est exposée à un autre compte.

La référence utilise uniquement les labels humains antérieurs d’administrateurs
actifs ayant accès au message. Les corrections contradictoires sont exclues ; une
campagne exacte contribue une fois. Les échantillons doivent partager le protocole
et la politique native, sur trente jours, avec au moins cinq campagnes légitimes
et trois jours distincts. Une donnée partielle, une requête expirée, un changement
de politique ou un échantillon trop petit ne crée pas une nouveauté supposée.
La lecture SQLite est bornée à 2 000 lignes et 200 ms ; l’interruption désactive la
comparaison, sans bloquer la livraison.

Les booléens de nouveauté alimentent uniquement le candidat qualité en observation,
avec états indisponibles explicites et ablation dédiée. Ils ne créent pas de liste
blanche, ne changent pas le score actif et ne concluent pas à une fraude. Les
rapports publics et exports qualité retirent les clés et échantillons privés.
Ces métadonnées suivent la rétention de trente jours des messages ; aucun corps
supplémentaire n’est conservé. Les poids lexicaux, sémantiques et budgets LLM ne
sont pas modifiés par cette version.

## Migration et preuve de qualité

Le protocole qualité contient de nouvelles caractéristiques. Un candidat antérieur
à 0.6.0 est refusé : retirer son chemin optionnel avant `check-config`, conserver
le modèle privé à part et réentraîner un candidat sur de nouvelles observations
compatibles. Ne pas mélanger les cohortes ou reconstruire des messages effacés.
La mémoire comportementale démarre sans référence ; elle doit recueillir des
annotations récentes. Les nouveaux champs de diagnostics sont optionnels pour
les anciens lecteurs de messages et n’ajoutent pas de migration SQLite.

La sélection des seuils dans `train_quality.py` respecte les budgets empiriques
sur la seule période de sélection, avec ex æquo inclus. La période de test et
l’évaluation prospective gardent les campagnes antérieures à l’écart. Les objectifs
95 % de rappel et 0,1 % de faux positifs restent à démontrer avec leurs intervalles ;
une suite de tests logicielle ou un très petit lot annoté ne les établit pas.
Aucun candidat n’est activé automatiquement. Le mode observation et les contrôles
de validation Proton restent appliqués avant tout marquage.
