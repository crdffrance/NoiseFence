# En-têtes des messages transmis

Depuis **0.11.0**, les nouveaux messages analysés utilisent
`X-NoiseFence-Header-Version: 2`. Les messages déjà transmis et ceux déjà préparés
dans la file gardent leurs en-têtes d’origine : aucune réanalyse ni réexpédition.

## Score, décision et classement

`X-NoiseFence-Score` affiche le même indice que la console : score de décision
exploitable en priorité, sinon score brut conservé. Le résultat antivirus ne
devient pas un score artificiel. La plage est 0–100 ; une valeur réellement absente,
non finie ou hors plage reste `unavailable`, jamais zéro.

| En-tête | Signification |
| --- | --- |
| `X-NoiseFence-Score` | Valeur affichable, avec une décimale |
| `X-NoiseFence-Score-Scale` | `0-100` |
| `X-NoiseFence-Score-Type` | `content`, `decision`, `advisory`, `partial`, `internal` ou `unavailable` |
| `X-NoiseFence-Score-Source` | `decision`, `raw` ou `unavailable` |
| `X-NoiseFence-Model` | Version du modèle correspondant au score sélectionné |
| `X-NoiseFence-Raw-Score` | Indice brut du moteur historique |
| `X-NoiseFence-Decision-Score` | Score de la décision, ou `unavailable` si elle s’abstient |
| `X-NoiseFence-Decision` | `legitimate`, `unwanted` ou `undetermined` |
| `X-NoiseFence-Decision-Source` | `legacy`, `fusion` ou `antivirus` |
| `X-NoiseFence-Category` | Catégorie appliquée au message ; les règles du destinataire peuvent intervenir |
| `X-NoiseFence-Status` | `incomplete`, `spam`, `pub` ou `observed` ; `spam`/`pub` décrivent le préfixe effectivement ajouté |
| `X-NoiseFence-Mode` | Mode global `observe`, `tag` ou `enforce` |
| `X-NoiseFence-Id` / `X-NoiseFence-Version` | Identifiant de suivi / version de NoiseFence |

`partial` conserve une analyse incomplète. `advisory` accompagne l’incertitude ou
la priorité antivirus. Ces indices ne sont pas des probabilités calibrées de spam.
Un score fusion `decision` concerne uniquement la population de validation de ce
modèle. `internal` désigne une valeur interne de notification, pas un email entrant.

**Migration des consommateurs d’en-têtes :** avant 0.11.0, `Score: unavailable`
pouvait traduire une abstention malgré un indice brut disponible. Avec le schéma 2,
consulter `Decision`, `Decision-Score`, `Score-Type` et `Status` pour cette distinction.
Ne pas classer ou bloquer un message à partir du seul `Score`. Le champ numérique
peut être élevé lorsque `Decision` reste `undetermined`.

## Détail des contrôles

| En-tête | Contenu |
| --- | --- |
| `X-NoiseFence-Analysis` | Complétude globale et durée en millisecondes avant génération des en-têtes/ARC |
| `X-NoiseFence-Checks` | Disponibilité de l’extraction, SPF/DKIM/DMARC/ARC, DNSBL, sémantique, antivirus, signatures, SMTP, LLM, vision et fusion |
| `X-NoiseFence-Authentication` | Résultats SPF, DKIM, alignements DMARC SPF/DKIM et ARC enregistrés ; complète `Authentication-Results` standard |
| `X-NoiseFence-Incomplete-Reasons` | Codes des causes connues, `none` si complète, `unspecified` si la cause n’a pas été identifiée |
| `X-NoiseFence-Arbitration` | Accord, désaccord ou ambiguïté entre décision initiale et avis consultatif |
| `X-NoiseFence-Rules` | Identifiants des signaux et poids en **logits**, avec compteurs `total`, `shown`, `omitted` |
| `X-NoiseFence-LLM` | État, catégorie consultative, code d’erreur et durée ; aucune explication libre du fournisseur |
| `X-NoiseFence-Antivirus` | Résultats et durées de l’antivirus principal et des signatures consultatives |
| `X-NoiseFence-Vision` | État OCR, pièces/pages examinées, nombres de QR/autres codes, erreurs et durée |
| `X-NoiseFence-Vision-Errors` | Codes OCR/QR connus (limite de pixels/pages/texte, délai, décodeur, etc.), limités à 16 entrées |
| `X-NoiseFence-Reputation` | CRDF/VirusTotal : état, cibles contrôlées, résultats malveillants/suspects/inconnus, cache, omissions et erreur |
| `X-NoiseFence-RBL` | Résumé des vérifications IP avant DATA et action effective, sans noms de fournisseurs privés ni domaines de requêtes |
| `X-NoiseFence-Native` | État/mode du moteur natif, indication de calibration et effet sur la livraison |
| `X-NoiseFence-Native-Rules` | Symboles natifs non absorbés et poids **avant plafonds de famille**, distincts du moteur historique |

Les états `disabled`, `not_run`, `skipped`, `limited`, `busy` ou `unavailable`
ne signifient pas « sain ». Dans `Checks`, `complete` signifie que le contrôle
a abouti, pas que le résultat est favorable. `not_recorded`/`unknown` signalent
l’absence d’observation ; les erreurs de réputation ne deviennent pas des preuves
de spam. Les contrôles consultatifs peuvent échouer sans rendre toute l’analyse
incomplète. `LLM: not_needed` décrit un message non sélectionné pour ce contrôle.

Exemple **synthétique** d’une analyse limitée par l’OCR (champs abrégés) :

```text
X-NoiseFence-Header-Version: 2
X-NoiseFence-Score: 87.4
X-NoiseFence-Score-Type: partial
X-NoiseFence-Score-Source: raw
X-NoiseFence-Score-Scale: 0-100
X-NoiseFence-Raw-Score: 87.4
X-NoiseFence-Decision-Score: unavailable
X-NoiseFence-Status: incomplete
X-NoiseFence-Decision: undetermined
X-NoiseFence-Incomplete-Reasons: vision_incomplete
X-NoiseFence-Vision: status=limited; parts=2; pages=1; qr-codes=1;
 other-codes=0; errors=1; elapsed-ms=450;
```

## Bornes et authenticité

Les champs sont ASCII, repliés entre atomes en visant 78 caractères par ligne ;
aucun atome ne dépasse 256 caractères. Chaque liste de règles est limitée à
24 entrées, et chaque identifiant à 64 caractères, avec omissions explicites.
Les poids ne s’additionnent pas en points sur 100. Les détails complets restent
dans la console, avec ses contrôles d’accès.

Les détails n’exposent ni corps, ni objet, ni URL, ni destinataire/Bcc, ni profil
de destinataire, ni secret de fournisseur. Les textes libres des règles,
des modèles et des réponses externes sont exclus. Les résultats reçus sous
`X-NoiseFence-*` sont supprimés avant ajout des résultats locaux.

Tous les champs ajoutés sont inclus dans l’inventaire ARC signé lorsque la chaîne
peut être scellée. Si l’analyse emprunte le repli sans ARC, les détails sont tout
de même ajoutés sans prétendre être signés. Une signature ne garantit pas la
confiance du destinataire : vérifier la chaîne et l’intermédiaire. Voir
[RFC 5322, format et repliement](https://www.rfc-editor.org/rfc/rfc5322.html#section-2.2.3)
et [RFC 8617, ARC](https://www.rfc-editor.org/rfc/rfc8617.html).

Cette évolution n’active aucun filtrage, aucune modification d’objet, aucun
fournisseur et ne change pas les actions de livraison.
