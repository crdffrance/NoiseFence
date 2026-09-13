# SMTP and the HTTPS console

The SMTP server listens on port 25 with STARTTLS and a certificate validated for its DNS name. The Axum console remains on loopback; Nginx publishes HTTPS on port 443 and redirects HTTP 80. Adapt `deploy/nginx.conf` to the DNS name and operator certificates. Set `web.public_origin` to HTTPS and `web.secure_cookies = true`. Only configured domains are accepted, with a default recipient list or the explicit `accept_all_recipients = true` option per domain. ClamD uses private Unix sockets, without public TCP service.

When Certbot was configured in standalone mode, migrate its validation before renewals:

```sh
sudo certbot reconfigure --cert-name mx.example.org --webroot \
  --webroot-path /var/www/letsencrypt --non-interactive
```

This command tests the new method with the staging server. Install `deploy/certbot-nginx.sh` as an executable deployment hook in `/etc/letsencrypt/renewal-hooks/deploy/`, in addition to the existing SMTP hook. Nginx reads the Lets Encrypt certificate; NoiseFence uses its validated and renewed private copy atomically. Check both connections after any modification.

Create accounts via `noisefence user-add` with their authorized recipients. Passwords are entered without echo, never included in Git. Control a real HTTPS connection, Secure/HttpOnly cookies, sessionless refusal and user access. The proxy limits attempts on the connection route.

The display of services does not automatically validate the Proton relay. Keep the current observation mode and MX as long as the authenticated delivery and modification testing of Subject does not pass. Primary antivirus malware detection has priority; complementary signatures remain advisory. Capture and false-positive objectives must still be measured.
