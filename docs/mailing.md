# Publicités et newsletters (PUB)

NoiseFence distingue les publicités légitimes du spam. La catégorie visible suit
la décision de sécurité : **spam prioritaire**, puis PUB si l’analyse est complète,
puis légitime. Une analyse indéterminée ne reçoit pas de catégorie PUB. Le détecteur
local `mailing-1` ne diminue jamais le score spam et n’ajoute aucun appel réseau.

## Détection et limites

Les en-têtes `List-Unsubscribe`, `List-ID` et `Precedence: bulk/list`, ou une mention
de désinscription dans le corps, indiquent une diffusion collective. Ces indices
corrélés comptent comme une seule famille. Une publicité exige aussi plusieurs
indices de contenu commercial : offres/remises, appel à l’achat, code promotionnel
ou livraison offerte. Une newsletter exige un indice de diffusion et un contenu de
lettre d’information. L’administrateur peut exclure les newsletters éditoriales.

Les en-têtes seuls, HTML seul et les préfixes reçus ne suffisent pas. Des indices
de facture, reçu, commande, code de connexion, alerte de sécurité, calendrier,
réponse automatique ou conversation écartent la catégorie PUB. Les correspondances
sont des heuristiques FR/EN avec quelques termes d’autres langues ; elles ne prouvent
ni un abonnement ni l’innocuité d’un message. Un fraudeur peut les imiter, mais le
classement de sécurité reste prioritaire. Aucun taux de capture PUB ou de faux
positifs n’a encore été mesuré sur une population récente indépendante.

Le traitement porte sur l’original MIME décodé. Limites : au plus 2 Mio (ou la
limite d’analyse configurée), 200 parties, 20 corps texte et 20 HTML ; toute
troncature des 32 000 caractères de texte ou 500 caractères d’objet rend la
catégorisation limitée. Les en-têtes de liste ambigus ou excessifs ont le même
effet. Dans ces cas, aucun classement ni préfixe PUB n’est appliqué. Le rapport
contient seulement les raisons prédéfinies, indicateurs booléens, version et durée.

Les syntaxes observées sont documentées dans [RFC 2919](https://www.rfc-editor.org/rfc/rfc2919),
[RFC 8058](https://www.rfc-editor.org/rfc/rfc8058) et
[RFC 3834](https://www.rfc-editor.org/rfc/rfc3834). La présence de la syntaxe de
désinscription en un clic ne constitue pas une validation de sa couverture DKIM.
NoiseFence n’ouvre aucun lien et ne déclenche aucune désinscription.

## Configuration

Installer le module dans le fichier serveur, au niveau racine :

```toml
[mailing]
# Nécessaire seulement pour le préfixe, avec le mode global tag :
# proton_report = "/etc/noisefence/proton-validation-pub.json"

[mailing.policy]
include_newsletters = true
tag_subject = true
```

Après redémarrage, activer **Filtres → Publicités et newsletters** dans la console
et appliquer la modification si une révision existante désactive encore le module.
Les paramètres sont globaux ; la consultation et les corrections suivent les
permissions par destinataire et domaine, y compris les copies cachées.

En mode global `observe`, les nouveaux messages PUB apparaissent dans l’historique
et les statistiques, sans changement d’objet à la livraison. En mode `tag`,
`tag_subject=true` ajoute `[PUB]` seulement après validation du préfixe propre à
Proton et configuration ARC. Un rapport `[SPAM]` ne remplace pas un rapport `[PUB]` :
il faut refaire les mêmes cas de livraison avec ce préfixe exact, les domaines et
le nom d’hôte actuels, depuis moins de 30 jours. On peut désactiver `tag_subject`
pour conserver le classement PUB sans son préfixe. Ne jamais fabriquer un rapport
pour contourner cette validation.

Le marquage conserve le corps octet pour octet, traite les objets RFC 2047, évite
les préfixes répétés et remplace un ancien préfixe géré lorsque la décision l’exige.
Les résultats `X-NoiseFence-*` entrants sont retirés ; le résultat local
`X-NoiseFence-Category` est couvert par ARC. Modifier l’objet peut invalider DKIM ;
ARC ne garantit pas l’acceptation par Proton. Une erreur d’analyse ou de scellement
transmet le message sans nouveau préfixe.

## Console, API et corrections

- Historique : filtre **PUB**, compteur dédié, distinction entre PUB détecté et
  `[PUB]` effectivement ajouté ; le score affiché reste le score spam.
- Détail : raisons de la catégorie et corrections **Légitime**, **Spam**, **PUB**.
- API : `GET /api/v1/messages?filter=publicity` et champ `publicity` des statistiques.
  `POST /api/v1/messages/{id}/feedback` accepte `{"category":"publicity"}`
  (ou `spam` / `legitimate`). L’ancien corps `{"spam":false}` reste accepté.
- Les corrections ne modifient ni la décision historique ni le message dans Proton.
  PUB signifie non-spam pour l’entraînement binaire existant. Les exports ajoutent
  la catégorie explicite et le rapport PUB pour préparer une calibration dédiée.
  Le détecteur PUB à règles n’est pas réentraîné automatiquement par ces corrections.
- Des avis contradictoires PUB/légitime conservent le label binaire non-spam mais
  écartent le sous-type. Un ancien vote non-spam ne devient pas automatiquement
  une étiquette « non publicitaire ». Un client ancien qui met à jour son vote
  invalide son éventuelle ancienne catégorie explicite.

L’historique existant n’est pas réanalysé : les corps déjà supprimés ne sont plus
disponibles. Les nouvelles métadonnées suivent la conservation de 30 jours.
La migration SQLite est additive ; elle conserve les messages, la file et les votes.

## Vérification locale

`cargo test --test mailing --test authentication --test gates --test console --test learning`
couvre les indices concordants et isolés, les exclusions, MIME/UTF-8, l’idempotence
du préfixe, le corps inchangé, ARC et sa falsification, la priorité spam, les limites,
les autorisations et les exports compatibles. Le fuzzing MIME inclut le détecteur
et le préfixe PUB. Ces tests logiciels ne constituent pas une mesure de qualité
sur de vrais messages ni une validation de livraison Proton.

Pour préparer les essais de livraison, `proton-report-template rapport-pub.json
--category publicity` crée un rapport `[PUB]` vierge, avec tous les essais non
validés. `proton-prepare` accepte également `--category publicity` : le fichier
de test doit être une publicité/newsletter reconnue et non classée spam, avec
les vérifications et ARC complets. Il produit uniquement des fichiers locaux ;
il n’active pas le marquage et n’envoie aucun e-mail. Voir les autres paramètres
et la matrice d’essais dans [la procédure Proton](proton-validation.md).
