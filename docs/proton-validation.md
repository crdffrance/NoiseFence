# Valider le relais devant Proton

La passerelle conserve Proton comme destination. Sa mise en production dépend des essais ci-dessous, et non du seul succès d’un dialogue SMTP.

## Préparer l’environnement

1. Utiliser une adresse ou un sous-domaine de test contrôlé dans Proton, et un expéditeur de test contrôlé. Renseigner les adresses et le serveur de test dans une configuration locale exclue de Git.
2. Confirmer auprès de l’hébergeur que TCP/25 est disponible dans les deux sens. Contrôler A/AAAA, reverse DNS et certificat de la passerelle. Ne publier AAAA que si le routage IPv6 fonctionne.
3. Copier `config/crdf.example.toml`, renseigner les destinataires réels et les certificats, conserver `mode = "observe"`.
4. Préparer une clé RSA ARC et publier la clé publique sous `SELECTEUR._domainkey.example.org`. Fournir la clé privée, le domaine et le sélecteur dans la configuration. Les clés PKCS#1 et PKCS#8 PEM sont acceptées. La clé reste lisible uniquement par le service.
5. Vérifier le support actuel du relais avec Proton. [Proton décrit une confiance ARC limitée à certains intermédiaires](https://proton.me/blog/what-is-authenticated-received-chain-arc) ; une chaîne ARC valide ne suffit pas à nous ajouter à cette liste. ARC reste implémenté pour l’interopérabilité Proton ; le protocole historique n’est pas présenté comme une garantie de délivrabilité.

## Comparaison contrôlée

Pour chaque famille de messages, conserver trois exemplaires et leur résultat : livraison directe, livraison relayée sans préfixe, livraison relayée avec préfixe. Vérifier arrivée, délai, dossier, objet et `Authentication-Results` dans Proton. Une acceptation SMTP `250` ne garantit pas une arrivée en boîte principale.

Préparer les variantes d’un message de test contrôlé, en fournissant l’IP réelle de son expéditeur SMTP et son enveloppe. Cette commande écrit des fichiers et effectue les vérifications DNS ; elle n’envoie aucun email et n’active pas le marquage de la passerelle :

```sh
noisefence --config config/local.toml proton-prepare test.eml \
  --source-ip IP_REELLE_EMETTEUR \
  --helo HOTE_EMETTEUR \
  --mail-from EXPEDITEUR_DE_TEST \
  --output reports/probe
```

Le répertoire reçoit `direct.eml`, `relay-untagged.eml`, `relay-tagged.eml` et `analysis.json`. Pour la comparaison directe, soumettre l’original depuis l’infrastructure de l’expéditeur de test afin de conserver son contexte SPF. Soumettre les exemplaires relayés depuis la passerelle vers les MX Proton. L’outil de soumission exige TLS validé et un destinataire explicite :

```sh
python3 scripts/send_probe.py reports/probe/relay-tagged.eml \
  --host mail.protonmail.ch --helo mx.example.org \
  --mail-from EXPEDITEUR_DE_TEST --recipient DESTINATAIRE_DE_TEST
```

Sans `--send`, aucun envoi n’a lieu. Après contrôle des paramètres, ajouter ce drapeau pour envoyer exactement un message. N’utiliser que des comptes destinataires contrôlés.

| Cas dans le rapport | Vérification |
|---|---|
| `dkim` | Original DKIM valide ; observer la différence quand Subject est modifié |
| `spf_only` | Message légitime sans DKIM ; mesurer l’impact du changement d’IP |
| `dmarc_reject` | Domaine de test avec politique stricte et identifiants alignés à l’origine |
| `mailing_list` | En-têtes et signatures d’une vraie liste de test |
| `forwarded` | Chaîne ARC préexistante et transfert légitime |
| `international_subject` | Objets UTF-8 encodés RFC 2047, repliés, vides et déjà préfixés |
| `bypass` | Livraison directement aux MX Proton malgré les MX publics de passerelle |
| `proton_internal` | Messages issus de Proton et susceptibles d’être routés en interne |

Pour `bypass` et `proton_internal`, `passed` signifie que la couverture réelle a été mesurée et documentée. Cela ne signifie pas que ces chemins ont été bloqués. Renseigner `bypass_limit_accepted` seulement après acceptation explicite de cette limite par l’exploitant. Le produit filtre le trafic qui traverse son SMTP ; il ne contrôle pas les flux internes à Proton.

## Décision de bascule

```sh
noisefence --config config/local.toml proton-report-template reports/proton-validation.json
```

Le modèle de rapport est volontairement non validé. Après les essais, y inscrire la date Unix, le résultat de chaque cas et une référence d’évidence détaillée (identifiants de messages, résultats d’authentification, emplacement des captures ou exports). Ne pas y mettre de secrets. Un rapport doit correspondre au hostname et aux domaines, porter sur `[SPAM]` et dater de moins de 30 jours pour permettre le démarrage en mode `tag`.

Si le préfixe dégrade la livraison, laisser le mode observation et les MX actuels. Un libellé Proton via Sieve peut être étudié ensuite comme changement de comportement, mais ce projet n’effectue pas cette substitution automatiquement.

La bascule DNS reste manuelle : publier uniquement les MX des passerelles filtrantes, et conserver une procédure de retour vers les deux MX Proton actuels. Ajouter Proton comme MX secondaire pendant le filtrage créerait un chemin de contournement. Après rollback, laisser le relais drainer les messages déjà acceptés avant de l’arrêter.
