# Limiter les classements Spam insuffisamment étayés

L’option `filter.require_corroboration = true`, également disponible dans les
réglages de la console, ajoute une abstention au score historique. Lorsque ce
score dépasse le seuil mais ne dispose d’aucune confirmation ci-dessous, la
décision devient **À vérifier** (`undetermined`). Le message est transmis sans
préfixe. Son score, ses caractéristiques et son statut d’analyse restent conservés.
Ce n’est ni une preuve de légitimité ni une catégorie PUB.

Les confirmations prises en compte par `confirmation-2` sont :

- une détection de malware par l’antivirus principal ;
- un avis LLM terminé, spam/phishing, avec confiance et probabilité déclarées
  d’au moins 0,9 chacune, selon les seuils consultatifs déjà utilisés ;
- un échec DMARC vérifié sur les deux possibilités d’alignement ;
- une réponse DQS vérifiée indiquant une réputation défavorable pour une IP (ZEN 2, 3, 4, 9) ou
  un domaine (DBL 2, 4, 5, 6).

Les réponses indisponibles, codes d’erreur, listes de politique IP (PBL), domaines
légitimes compromis, SPF seul, incohérences SMTP, signatures consultatives et
indices HTML/OCR ne suffisent pas. Le lexical et le sémantique constituent déjà
le score de contenu : ils ne sont pas comptés comme deux confirmations.
Une réussite SPF/DKIM/DMARC ne dispense pas des contrôles : des messages malveillants
peuvent être correctement authentifiés. Les en-têtes du message ne peuvent pas
fournir ces résultats internes.

Les sources peuvent être corrélées. Les nombres déclarés par le LLM ne sont pas
des probabilités validées. Cette règle de prudence **peut réduire le rappel**,
notamment pour les spams reconnus uniquement par le modèle. Mesurer les spams
placés « À vérifier », ainsi que les faux positifs, avant d’activer le marquage.
Le compteur de faux positifs doit être accompagné des abstentions : déplacer
une erreur vers « À vérifier » n’équivaut pas à bien classer ce message.

La fusion apprise, lorsqu’elle est activée avec son propre rapport de validation,
conserve sa politique de confirmation. La [priorité antivirus](filter-policy.md)
s’applique après la fusion comme après le score historique. Une analyse incomplète
reste incomplète. Aucun contrôle
supplémentaire ni appel réseau n’est déclenché par cette option, qui ne change
pas les seuils ou les poids du modèle chargé. Son état et sa version font partie
de l’empreinte de politique ; les artefacts de fusion doivent correspondre.

Les anciens fichiers et révisions gardent la valeur `false` par défaut. Le
modèle de configuration de production propose `true`. L’administrateur peut
l’activer explicitement avec une nouvelle révision. Les décisions historiques
et les messages déjà livrés ne sont pas réécrits. Le filtre **À vérifier** de
l’historique sélectionne les nouvelles analyses complètes dont la décision est
indéterminée ; **Analyse incomplète** conserve son sens opérationnel.

Le prompt LLM `noisefence-classify-2` précise également que brièveté, fournisseur
gratuit, transfert et notification de service ne constituent pas des preuves de
spam. Le préfixe de transfert ne garantit pas non plus la sûreté du contenu.
Ce changement de consignes n’a pas, à lui seul, de gain de qualité mesuré.

## Vérification

`cargo test --test confirmation --test console` couvre les décisions sans
confirmation, avis faibles/forts, malware, contrôles indisponibles, réputation,
SPF/DMARC, en-têtes falsifiés, corps conservé, filtres et droits par destinataire.
Les fixtures sont synthétiques et ne publient aucun message de production.
Les corrections réelles doivent rester privées et être évaluées sans modifier
les labels ni les poids sur le lot servant à mesurer le résultat.

`noisefence audit-confirmation /var/lib/noisefence/state.sqlite3` compare les
décisions historiques à cette règle en réutilisant les observations enregistrées.
Il ouvre SQLite en lecture seule, n’accède pas aux corps, ne charge aucun modèle
et ne fait aucun appel externe. La sortie contient uniquement des compteurs,
y compris les abstentions sur légitimes et sur spams. Les droits des annotateurs,
leur désactivation, les conflits et la rétention de trente jours sont vérifiés.
Les décisions absentes, incomplètes ou issues d’une fusion sont comptées à part.
Un lot de corrections est biaisé ; ce bilan ne mesure pas le taux de faux
positifs sur l’ensemble du trafic. Il ne rejoue pas le nouveau prompt LLM.
Depuis dev.21, `with_decision_policy` mesure aussi l’effet de la priorité antivirus
sur ces mêmes observations, sans recalculer le score ni les recherches DQS.

La distinction des codes DQS suit la [table des zones Spamhaus](https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/040-zones.html).
