# Règles locales inspirées de Rspamd

NoiseFence 0.9.0 transpose en Rust douze contrôles structurés et deux composites.
Ils complètent la banque de motifs existante et les contrôles d’authentification,
réputation, liens trompeurs, Bayes et similarité déjà présents.

Le module natif reste en **observation**. Les nouvelles règles ne changent ni le
score décisionnel, ni les actions SMTP, ni la sélection LLM. Un symbole signale
une caractéristique à examiner : il ne prouve pas seul qu’un message est du spam.
Les poids ci-dessous sont des valeurs initiales à mesurer sur des annotations
humaines récentes, pas les scores de Rspamd ni des probabilités calibrées.

## Banque et portée

| Symbole | Contrôle | Poids initial |
|---|---|---:|
| `NF_HTML_PASSWORD_FORM` | Champ de type password associé à un formulaire | 0,3 |
| `NF_HTML_REMOTE_PASSWORD_FORM` | Ce même formulaire envoie vers un domaine différent de celui du From | 0,9 |
| `NF_HTML_INSECURE_PASSWORD_FORM` | Ce même formulaire envoie par HTTP | 0,5 |
| `NF_HTML_HIDDEN_TEXT` | Au moins 200 caractères significatifs masqués, plus nombreux que les caractères visibles | 0,15 |
| `NF_HTML_LINK_SCHEME` | Texte d’ancre HTTPS, destination HTTP | 0,3 |
| `NF_HTML_DATA_LINK` | Ancre vers une URL data HTML/XHTML/SVG | 0,4 |
| `NF_HTML_META_REFRESH` | Balise meta refresh vers une URL HTTP(S) absolue | 0,3 |
| `NF_MIME_EXECUTABLE_EXTENSION` | Extension de programme, script ou raccourci exécutable | 0,2 |
| `NF_MIME_DOUBLE_EXTENSION` | Extension de document ou d’image suivie d’une extension exécutable | 0,8 |
| `NF_MIME_EXECUTABLE_DISGUISED` | En-tête PE/ELF dans une pièce jointe nommée ou déclarée document/média | 1,0 |
| `NF_MIME_FILENAME_BIDI` | Contrôle Unicode d’override LTR/RTL dans le nom de pièce jointe | 0,3 |
| `NF_HEADER_DISPLAY_DOMAIN` | Nom From constitué d’une adresse complète d’un autre domaine | 0,4 |

`NF_REMOTE_LOGIN_FORM` remplace les contributions du champ password et de son
formulaire externe par 1,2 point. `NF_DISGUISED_ATTACHMENT` remplace les
contributions du binaire déguisé et de sa double extension par 1,5 point.
Les symboles absorbés restent visibles. Répéter un formulaire ou une pièce jointe
ne multiplie pas un symbole. Le plafond de la famille contenu reste 1,5 point par
défaut dans le calcul comparatif natif.

Les formulaires externes peuvent être légitimes, notamment avec un fournisseur
d’identité distinct. La comparaison emploie IDNA et les domaines enregistrables
de la Public Suffix List, y compris ses suffixes privés. Un sous-domaine du même
domaine enregistré est accepté ; deux sites distincts sous `github.io` restent
distincts. Un From ou un nom affiché n’est jamais traité comme une identité
authentifiée. Une simple différence de nom de personne ne déclenche pas le contrôle.

Les aperçus courts de newsletters, les espaces de remplissage invisibles et les
contenus de script/style/template ne comptent pas comme un volume suspect de texte
masqué. Seuls les attributs `hidden` et certains styles intégrés explicites sont
interprétés ; aucune feuille CSS distante, cascade complète, JavaScript ou requête
réseau n’est exécutée. Les exemples HTML échappés et commentaires ne sont pas des
formulaires. L’association `form=id` doit désigner un formulaire unique ; des
formulaires différents ne sont pas combinés pour fabriquer une destination suspecte.

Les URL de formulaires et de redirection doivent être absolues en HTTP(S).
Les chemins relatifs, attributs base, actions JavaScript, boutons `formaction`
et pages distantes ne sont pas résolus par ces règles. Le moteur de réputation
et de redirection existant reste indépendant. Les liens data sont observés sans
décoder leur charge utile ; les images PNG incorporées ne déclenchent pas ce contrôle.

Les noms de pièces jointes sont décodés par le parseur MIME (RFC 2231/2047).
`rapport.2026.pdf` n’est pas une double extension exécutable ; les `%2e` littéraux
dans un nom ne sont pas transformés arbitrairement. Un fichier source JavaScript
ou un exécutable correctement déclaré peut être légitime. Les contrôles PE/ELF
vérifient uniquement des en-têtes bornés, sans désassemblage ni exécution. Ils ne
remplacent pas l’antivirus. Les archives, contenus de pièces jointes HTML et macros
Office ne sont pas explorés par cette banque.

## Configuration et inspection

La banque s’active avec `[native_filter]`, avec les limites du module et sans
nouvelle dépendance. Pour désactiver une règle ou changer un poids :

```toml
[native_filter]
mode = "observe"

[native_filter.content_rules]
enabled = true
disabled = ["NF_HTML_HIDDEN_TEXT"]

[native_filter.content_rules.weights]
NF_MIME_DOUBLE_EXTENSION = 0.8
```

Les poids autorisés sont finis et compris entre 0 et 2. Un poids nul conserve le
symbole pour l’observation et les composites ; `disabled` supprime son émission.
Les composites peuvent être personnalisés séparément comme décrit dans
[le guide du moteur natif](native-filtering.md). Les identifiants inconnus et les
collisions avec les motifs personnalisés sont refusés. Les nouveaux symboles ne
sont pas autorisés dans une condition négative `none` : une règle désactivée ou
un contrôle incomplet ne devient pas une preuve d’absence de risque.

```sh
noisefence --config /etc/noisefence/config.toml native-rules
noisefence --config /etc/noisefence/config.toml native-rules exemple.eml
```

Ces commandes montrent les identifiants, libellés, poids et références d’origine.
La seconde inspecte un fichier local sans livraison, DNS ou appel LLM. Elle ne
charge pas les modèles. Le diagnostic par message affiche les symboles sous
« Moteur natif » ; ni nom de fichier, domaine privé, URL ou texte source n’est
ajouté à ces libellés.

## Ressources et compatibilité

Les règles sont exécutées dans le travailleur natif Tokio bloquant, sous son
sémaphore et son délai partagé. Limites supplémentaires : 200 parties MIME,
128 Kio cumulés de HTML décodé, 8 192 nœuds DOM par partie, 64 ancêtres et
4 096 octets par nom de fichier. Les formulaires sont indexés une fois, les styles
analysés une fois et les textes comptés une fois. Un dépassement rend le module
natif `limited`, sans score comparatif ; il ne bloque pas la livraison.

Le rapport devient `native-filter-2`. Les empreintes de code et de politique
séparent les observations. Les caractéristiques lexicales, OSB, MinHash et les
seize entrées du classifieur adaptatif ne changent pas ; les douze nouveaux
symboles ne sont pas ajoutés automatiquement aux modèles déjà entraînés.
La base conserve le schéma SQLite 2 et les anciens rapports restent lisibles.
Les candidats qualité optionnels liés à l’empreinte de code doivent être
réentraînés et validés avant activation avec cette version.

Pour revenir à 0.8.0, retirer seulement les éventuelles tables
`native_filter.content_rules` ajoutées à la configuration avant de relancer
l’ancien binaire. Conserver la base courante pour préserver les messages acceptés.
L’absence de ces tables permet un retour sans édition de configuration.

Les tests couvrent les contre-exemples légitimes, MIME encodé, suffixes privés,
styles masqués, formulaires distincts, entrées adverses, limites, pondérations,
absorption des contributions et invariance du score de livraison. Le harnais de
fuzzing MIME exerce aussi cette banque. Cela vérifie le comportement logiciel,
sans démontrer un taux de capture sur le trafic réel.

## Sources examinées

Révision Rspamd épinglée :
[`e2de26d28ce857d5c48ac82703cf26b681bd1d89`](https://github.com/rspamd/rspamd/tree/e2de26d28ce857d5c48ac82703cf26b681bd1d89).

- [HTML](https://github.com/rspamd/rspamd/blob/e2de26d28ce857d5c48ac82703cf26b681bd1d89/rules/html.lua) : visibilité, faux HTTPS et inspection structurelle.
- [MIME](https://github.com/rspamd/rspamd/blob/e2de26d28ce857d5c48ac82703cf26b681bd1d89/src/plugins/lua/mime_types.lua) : extensions, incohérences de type et Unicode obfusqué.
- [En-têtes](https://github.com/rspamd/rspamd/blob/e2de26d28ce857d5c48ac82703cf26b681bd1d89/rules/headers_checks.lua) et [phishing](https://github.com/rspamd/rspamd/blob/e2de26d28ce857d5c48ac82703cf26b681bd1d89/src/plugins/lua/phishing.lua) : identité affichée et domaines des destinations.
- [GPT](https://github.com/rspamd/rspamd/blob/e2de26d28ce857d5c48ac82703cf26b681bd1d89/src/plugins/lua/gpt.lua) : consulté pour comparer l’architecture ; aucun prompt, auto-apprentissage sur verdict LLM, contexte externe ou appel supplémentaire n’a été importé.

Les contrôles de formulaires, URL data, meta refresh et noms affichés sont des
adaptations NoiseFence de ces familles de techniques, sans équivalence annoncée
avec un symbole Rspamd précis. Le code Rust, les paramètres et tests sont propres
au projet. La licence amont Apache-2.0 est conservée avec les [notices tierces](../THIRD_PARTY.md).
