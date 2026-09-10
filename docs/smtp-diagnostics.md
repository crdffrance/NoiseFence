# Comprendre les diagnostics SMTP et les filtres

Dans la console, ouvrir un message puis consulter **Filtres et indices déclenchés** et **Diagnostics du message**.

- Les filtres affichent leur identifiant, leur explication et leur contribution enregistrée. Un poids nul indique une observation consultative. Les contributions du modèle ne sont pas additionnées une seconde fois.
- Les diagnostics conservent la durée, les résultats SPF/DKIM/DMARC/ARC, le seuil et les poids réellement utilisés lors de l’analyse. Une information historique absente reste absente.
- **Transmission SMTP par destinataire** montre les serveurs essayés, l’IP jointe, DNS/TCP, EHLO, STARTTLS et TLS vérifié, MAIL FROM, RCPT TO, DATA, la réponse finale et les réessais. Le bouton d’actualisation recharge les nouvelles tentatives.

Un `250` final signifie que le serveur distant a accepté le transfert. Il ne garantit pas le classement en boîte de réception. Un `451` est temporaire et entraîne un réessai ; un `550` est définitif pour cette tentative/destination. Les codes étendus, par exemple `4.7.1` ou `5.1.1`, et les motifs du serveur restent visibles.

## Journaux du service

```sh
sudo journalctl -u noisefence --since '30 min ago' -o cat
sudo journalctl -u noisefence -f -o cat
```

L’identifiant de file affiché dans la console relie les événements `message analyzed`, `message durably accepted` et `outbound SMTP event`. Les traces de relais portent aussi l’identifiant de livraison, l’identifiant de tentative, la route, la phase et la durée.

## Confidentialité et limites

Les droits sont vérifiés pour chaque destinataire : connaître l’identifiant de file ne donne pas accès aux copies d’un autre compte. Les commandes sortantes sont représentées par leur phase, sans leurs arguments ; DATA n’est pas journalisé.

Depuis 0.4.2, les adresses reconnaissables dans les réponses distantes sont masquées avant troncature, y compris certaines représentations encodées. Ce traitement s’applique aussi à la lecture des anciennes réponses et erreurs dans la console. Il ne réécrit pas rétroactivement les fichiers du journal système. La reconnaissance d’adresses n’est pas un outil de suppression de tout contenu privé : une phrase arbitraire ou un encodage opaque renvoyé par un serveur peut rester visible.

Les traces sont bornées : 32 événements par route, 2 048 octets par champ affiché, au plus 50 journaux chargés pour un destinataire et 100 dans la vue globale. Les omissions sont signalées. Les transcriptions absentes sur les anciens messages ne sont pas reconstituées. Les métadonnées suivent la conservation du message et sont supprimées par la maintenance.
