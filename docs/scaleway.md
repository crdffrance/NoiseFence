# Analyse facultative avec Scaleway

Le client Rust est implémenté, testé contre un serveur HTTPS local et confronté à
l'API réelle de Scaleway. Les essais synthétiques ont confirmé l'accès dans le
projet dédié et un refus HTTP 403 dans un autre projet. Aucun compte, identifiant
de projet déployé ni clé de production n'est intégré au dépôt.

La réponse réelle contient `tool_calls: []` en l'absence d'appel d'outil. Cette
forme est acceptée depuis 0.2.0-dev.2, au même titre qu'un champ absent ou nul.
Une liste non vide, un autre type ou un `function_call` non nul reste refusé.
Ces essais valident l'intégration, pas un taux de détection sur un corpus réel.

## Isolation et activation

Avec `scw`, créer un projet `noisefence-llm` dans l'organisation autorisée, puis une
application IAM dédiée. Ajouter une politique associée seulement à cette application
avec `GenerativeApisModelAccess` et `rules.0.project-ids.0` égal au nouveau projet.
Ne pas remplacer cette portée par `rules.0.organization-id`. Vérifier aussi les
politiques héritées par toutes les applications : une autre attribution peut
élargir les droits effectifs. Les API serverless ne nécessitent pas de GPU permanent.

Exemples de commandes de création, avec des identifiants déjà vérifiés :

```sh
scw account project create organization-id="$NF_ORG_ID" name=noisefence-llm
scw iam application create organization-id="$NF_ORG_ID" name=noisefence-llm
scw iam policy create organization-id="$NF_ORG_ID" name=noisefence-model-access \
  application-id="$NF_APP_ID" rules.0.project-ids.0="$NF_PROJECT_ID" \
  rules.0.permission-set-names.0=GenerativeApisModelAccess
```

Créer ensuite une clé pour cette application et enregistrer sa réponse directement
dans un fichier privé, sans imprimer le secret dans le terminal ou les journaux.
La clé doit expirer et être renouvelée avant cette échéance. Tester avec elle l'accès
au modèle du nouveau projet et le refus d'accès à un autre projet avant activation.
Conserver les identifiants des ressources créées pour les audits et la révocation.

Sur le serveur, placer le secret dans `NOISEFENCE_SCALEWAY_API_KEY` du fichier
`/etc/noisefence/secrets.env`, appartenant à root, mode 0600. La clé d'administration
de l'organisation ne doit pas être utilisée par NoiseFence. Renseigner la section
`[llm]` du modèle TOML avec l'identifiant du projet isolé, le modèle, des prix vérifiés
et un budget explicite. Avec `monthly_budget_micro_eur = 0`, aucun appel n'est émis.

Le client utilise exclusivement l'endpoint HTTPS
`https://api.scaleway.ai/PROJECT_ID/v1/chat/completions`, vérifie le certificat et
refuse les redirections. Commencer avec des messages synthétiques autorisés, vérifier
le schéma JSON, la comptabilité et les délais, puis observer les messages ambigus.

## Données et décision

La requête contient l'objet, le domaine expéditeur, le nombre de pièces jointes et
un extrait de texte/HTML rendu limité à 12 000 octets par défaut. Les champs To/Bcc,
l'adresse complète de l'expéditeur, les noms de pièces jointes et leur contenu
binaire ne sont pas sérialisés. Le texte du message peut néanmoins contenir des
données personnelles : il ne s'agit pas d'une anonymisation. L'activation autorise
donc un traitement externe d'extraits textuels, différent du mode entièrement local.

Le modèle reçoit une consigne de classification et aucun outil. Seul un JSON fermé
contenant catégorie, estimation, confiance et courte raison est accepté. Les champs
supplémentaires, actions, appels d'outils, sorties tronquées et réponses trop grandes
sont refusés. La confiance déclarée par le modèle n'est pas une mesure calibrée.

Les préfixes de filtres antérieurs (`[SPAM]`, `[JUNK]`, `[PHISHING]`, `[BULK]`)
au début de l'objet sont retirés de l'extrait, comme pour le modèle local. L'objet
livré et les citations dans le corps restent intacts. Ces étiquettes ne constituent
pas des preuves de spam.

Le verdict ajoute au plus un faible signal au score local. Il ne commande aucune
livraison, suppression, quarantaine ou modification de configuration. Les messages
incomplets ou déjà détectés comme malveillants ne sont pas soumis au LLM. Une panne,
un délai dépassé ou une réponse invalide rend l'analyse incomplète et empêche le
préfixe. Un budget atteint ou un tarif expiré laisse fonctionner les moteurs locaux.

## Budget et rapidité

Les prix de l'exemple correspondent, au 6 septembre 2026, à 0,15 €/million de jetons
entrants et 0,35 €/million sortants pour `mistral-small-3.2-24b-instruct-2506`.
Les revérifier sur la [page tarifaire Scaleway](https://www.scaleway.com/en/pricing/model-as-a-service/).
Les montants de configuration sont exprimés en micro-euros : 20 000 000 = 20 €.
Les appels s'arrêtent si la date de vérification des prix dépasse 30 jours.

Une réservation durable SQLite précède chaque appel. Les appels concurrents et
les redémarrages conservent ce plafond local ; une réponse dont la facturation est
incertaine garde sa réservation maximale. Une réponse valide ajuste le montant selon
l'usage déclaré. Le client ne relance pas automatiquement les requêtes HTTP.
Ce plafond estimé ne remplace pas les alertes de facturation du fournisseur.
L'API administrateur `/api/v1/metrics` expose réservations, requêtes et plafond.

Deux appels au plus tournent en parallèle par défaut, dans l'intervalle
de scores configuré. L'option `review_unconfirmed_high = true` ajoute les scores
supérieurs à `score_high` sans corroboration au sens de `confirmation-3` : un score
élevé seul ne doit pas empêcher le second avis de rechercher un faux positif.
Cette option est désactivée par défaut et peut augmenter le nombre d'extraits
transmis. Elle conserve les limites de budget, concurrence et durée. Les preuves
de malware et les analyses incomplètes restent exclues. La sélection est enregistrée
dans `scan.llm.selection`, y compris en cas de quota ou d'annulation ; les anciens
enregistrements peuvent ne pas posséder ce champ. Aucun score n'est abaissé par la
seule demande de vérification. Les pondérations consultatives restent inchangées.

Le délai LLM de 2,5 secondes fait partie des cinq secondes
partagées avec les vérifications DNS. Mesurer le p95 global avec cette option : un
LLM ne garantit pas l'objectif de 500 ms. Le prix par message et la proportion
soumise au LLM doivent figurer dans les comparaisons de qualité.

Références : [Generative APIs](https://www.scaleway.com/en/docs/generative-apis/api-cli/using-generative-apis/),
[sorties structurées](https://www.scaleway.com/en/docs/generative-apis/how-to/use-structured-outputs),
[politiques IAM](https://www.scaleway.com/en/docs/iam/reference-content/policy/).
