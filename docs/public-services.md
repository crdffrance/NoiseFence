# SMTP et console HTTPS

Le serveur SMTP écoute sur le port 25 avec STARTTLS et un certificat validé pour
son nom DNS. La console Axum reste sur loopback ; Nginx publie HTTPS sur le port 443
et redirige HTTP 80. Adapter `deploy/nginx.conf` au nom DNS et aux certificats de
l'opérateur. Définir `web.public_origin` en HTTPS et `web.secure_cookies = true`.
Seuls les domaines configurés sont acceptés, avec une liste de destinataires par
défaut ou l'option explicite `accept_all_recipients = true` par domaine. ClamD
utilise des sockets Unix privées, sans service TCP public.

Lorsque Certbot était configuré en mode standalone, migrer sa validation avant
les renouvellements :

```sh
sudo certbot reconfigure --cert-name mx.example.org --webroot \
  --webroot-path /var/www/letsencrypt --non-interactive
```

Cette commande teste la nouvelle méthode avec le serveur de staging. Installer
`deploy/certbot-nginx.sh` comme hook exécutable de déploiement dans
`/etc/letsencrypt/renewal-hooks/deploy/`, en plus du hook SMTP existant. Nginx lit
le certificat Let’s Encrypt ; NoiseFence utilise sa copie privée validée et
renouvelée atomiquement. Vérifier les deux connexions après toute modification.

Créer les comptes via `noisefence user-add` avec leurs destinataires autorisés.
Les mots de passe sont saisis sans écho, jamais inclus dans Git. Contrôler une
connexion HTTPS réelle, les cookies Secure/HttpOnly, le refus sans session et
les accès entre utilisateurs. Le proxy limite les tentatives sur la route de connexion.

L'exposition des services ne valide pas automatiquement le relais Proton.
Conserver le mode observation et les MX actuels tant que les essais de livraison
authentifiée et de modification de Subject ne passent pas. Les scans antivirus
sont consultatifs ; les objectifs de capture et de faux positifs restent à mesurer.
