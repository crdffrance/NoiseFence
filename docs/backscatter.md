# Protection contre les notifications de spam (0.15.2)

Un expéditeur SMTP peut usurper l’adresse d’une victime. Si NoiseFence accepte
le message puis que le fournisseur le refuse, un avis de non-livraison (DSN)
retourné à cet expéditeur peut atteindre la victime : c’est le backscatter.

La politique native `backscatter-1` est active pour les **nouveaux traitements de
notifications** sur chaque MX, y compris en observation. Elle ne change ni le
classement, ni les actions de filtrage, ni la réponse SMTP à la réception.
Elle ne rappelle pas les avis déjà livrés et ne purge pas les DSN déjà en file.

## Conditions cumulatives

La notification est bloquée uniquement après un refus permanent de contenu
`550/554 5.7.1 rejected by rspamd filter` après DATA, sur une connexion TLS dont
le certificat a été vérifié. Le dernier journal de la tentative et le motif
persisté doivent correspondre. Un refus de destinataire, un délai expiré,
une réponse générique 5.7.1 ou une transcription tronquée ne suffisent pas.

Il faut aussi une analyse complète, une décision `unwanted` et des observations
d’authentification issues de la session SMTP réelle : SPF `fail`/`soft_fail`,
authentification achevée, aucun succès ni résultat indéterminé DKIM/DMARC/ARC.
Un message authentifié ou importé pour analyse ne bénéficie pas de cette exception.

Enfin, il faut **soit** une détection de malware de l’antivirus principal,
**soit** tous les éléments suivants :

- indice local d’au moins 99/100 ;
- signature consultative `Sanesecurity.Phishing.*` ;
- analyse LLM achevée concluant à du phishing, avec probabilité et confiance
  déclarées d’au moins 0,9.

Ces nombres ne constituent pas une garantie statistique ; le LLM contribue déjà
au score. La combinaison est volontairement étroite : signature spécialisée,
refus distant authentifié et indices d’usurpation viennent compléter le contenu.
Les analyses incomplètes et les preuves insuffisantes conservent les DSN normaux.
La politique ne bloque donc pas nécessairement tous les retours de spam.

## Conservation, interface et redémarrage

La livraison passe à `dsn_suppressed`, présentée comme « Avis bloqué
(anti-backscatter) ». Le motif de la politique et le refus restent visibles dans
les diagnostics du destinataire autorisé. Ce statut est disponible dans la
recherche et remonte à la console centrale depuis les workers. L’état et l’audit
`dsn_suppressed` sont enregistrés dans une seule transaction. Aucun message DSN
n’est créé. Une reprise ne peut pas recréer cet avis ni remplacer un DSN existant.

Le corps original suit la conservation habituelle : suppression après résolution
de tous les destinataires, conservation si une autre livraison est encore en file
ou en quarantaine. Les métadonnées restent disponibles pendant 30 jours. Aucune
conservation supplémentaire de contenu n’est ajoutée.

Les véritables DSN indiquent maintenant `Status` et `Diagnostic-Code` provenant
de la dernière tentative, ou `5.4.7` pour une expiration de file. Les diagnostics
sont bornés, convertis en ASCII, expurgés des adresses et protégés contre les
injections de champs. Les erreurs sans code exploitable gardent `5.0.0`.

## Exploitation

Déployer le coordinateur 0.15.2 avant les workers. Aucun changement de schéma SQL,
de clé, de compte ou de budget. Le nouveau statut requiert un coordinateur 0.15.2
pour la remontée d’historique ; ne pas revenir à un ancien coordinateur tant que
des workers lui transmettent cet état. Le retour arrière ne doit jamais restaurer
une ancienne file par-dessus les messages acceptés depuis.

Les tests couvrent la conservation des notifications légitimes, les preuves
manquantes/contradictoires, l’authentification, les réponses temporaires, les
injections, les destinataires multiples, la reprise et la synchronisation.

Référence : [RFC 5321, §6.2](https://www.rfc-editor.org/rfc/rfc5321.html#section-6.2),
qui recommande d’éviter les notifications pour les contenus hostiles quand elles
ne peuvent pas être utilement délivrées, et impose une grande prudence pour les
exceptions à la notification normale.
