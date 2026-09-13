# Deux copies et console de secours (0.17.1)

## Garanties et limites

L'option locale `[replication]` forme une paire de MX indépendants. Avant `250`, le récepteur copie chaque variante finale du message et son enveloppe sur l'autre machine par HTTPS authentifié. Le pair vérifie SHA-256, taille et identité, synchronise le fichier et son répertoire puis confirme la transaction SQLite durable. La transaction locale suit. Chaque destinataire conserve sa progression ; le pair ne prend aucune livraison automatiquement.

Si une copie est impossible (réseau, certificat, disque ou capacité), NoiseFence répond **451**, y compris si le pair tombe pendant DATA. Le serveur expéditeur conserve la responsabilité et réessaie. Il n'existe pas de mode automatique à une seule copie. Deux MX ne constituent pas un quorum permettant de départager une partition réseau.

L'intention d'envoi est répliquée avant de contacter le relais. La suppression locale du corps attend la confirmation des états terminaux par le pair ; un tombstone durable autorise ensuite la suppression distante. Les anciens messages en file sont protégés avant toute nouvelle tentative. Les copies reçues avant confirmation de la transaction locale restent inertes et sont conservées pour résolution manuelle. Elles ne sont pas assimilées à des messages acceptés.

SMTP ne garantit pas l'envoi exactement une fois : une réponse perdue peut laisser l'expéditeur ou le relais dans l'incertitude. À la restauration, un destinataire déjà livré n'est pas relancé ; une acceptation non confirmée ou un état `sending` est mis en quarantaine sans expiration automatique. Vérifier la trace distante avant toute libération. Voir [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321.html#section-6.1).

La console dispose d'instantanés cohérents, **pas d'une base partagée**. L'intervalle recommandé est 60 secondes plus le temps de copie. Les instantanés utilisent l'[API SQLite Online Backup](https://www.sqlite.org/backup.html) et contiennent comptes, MFA, réglages, modèles et budgets ; les corps de la file passent par la réplication dédiée. Ils sont privés sur disque et chiffrés en transit par SSH. Ce dispositif ne remplace pas une sauvegarde indépendante et chiffrée contre la compromission des deux machines.

## Installation

1. Installer la même release 0.17.1 ou suivante sur les deux MX, coordinateur d'abord. Conserver les files, paramètres d'observation, identités et budgets.
2. Créer une clé de paire aléatoire de 32 octets, encodée en 64 caractères hexadécimaux, dans `/etc/noisefence/replication.key`, propriétaire `noisefence`, mode `0600`, identique sur les deux machines. Ne jamais réutiliser un secret Web ou publier cette clé.
3. Installer une route Nginx `/api/v1/replication/` vers `127.0.0.1:18080`, sans réécriture du chemin, `proxy_request_buffering off`, délai borné et taille maximale SMTP + 256 Kio. Conserver la vérification TLS. Autoriser la lecture AppArmor de `/etc/machine-id`. Aucun port API public supplémentaire.
4. Ajouter la section de `config/replication.example.toml` avec des identités inversées sur le second MX. Redémarrer les deux : jusqu'à la première confirmation, l'admission SMTP reste différée. Vérifier « Infrastructure » : heartbeat, copies et confirmations en attente. Une fois activée, retirer la section fait refuser le démarrage ; ne pas contourner le marqueur `ha_required`.
5. Installer les scripts `deploy/ha/*.py` dans `/usr/local/libexec/noisefence-ha`, root:root, non modifiables par le service ; installer les unités et le profil AppArmor de console. Créer `/var/lib/noisefence-standby` mode `0700` sur chaque hôte.
6. Sur le coordinateur, créer une clé SSH dédiée `transport.key` dans ce répertoire et épingler la clé d'hôte du pair dans `known_hosts` à partir d'un canal déjà authentifié. Sur le pair, utiliser un compte sans accès général avec `restrict,from="IP_DU_COORDINATEUR",command="/usr/local/libexec/noisefence-ha/receiver.py"`. Le seul sudo autorisé est `/usr/bin/python3 /usr/local/libexec/noisefence-ha/standby.py receive`. Conserver l'accès SSH administrateur existant.
7. Configurer `settings.json` privé : sur les deux, `owner` (identité du coordinateur), `hostname` (nom TLS du pair) et `console_url` (origine HTTPS de secours) ; ajouter `receiver` (`noisefence-standby@adresse-du-pair`) sur le coordinateur. Activer `noisefence-standby-push.timer` sur le coordinateur uniquement. Vérifier `current/manifest.json`, le hash des fichiers et `status.json` sur le pair.
8. Préparer sur le pair `/etc/nginx/noisefence-console-upstream.conf` contenant exactement `set $noisefence_console 127.0.0.1:18080;` avec un saut de ligne. Les routes de console/cluster utiliseront cette variable après promotion ; **réplication et healthz restent sur le worker 18080**. En attente, la racine redirige vers le coordinateur. Conserver les limites d'authentification et les protections TLS.

Les paramètres de réplication sont locaux à l'hôte et ne sont jamais écrasés par la politique Web distribuée. `allow_loopback_http` est exclusivement réservé aux tests sur une adresse IP de boucle locale. Le quota de copies sature en erreur temporaire ; surveiller aussi les candidats non confirmés.

## Bascule planifiée

Opération administrateur, jamais déclenchée par un ping manquant :

1. Sur le coordinateur, exécuter `sudo python3 /usr/local/libexec/noisefence-ha/fence.py`. Le reçu `/var/lib/noisefence-standby/fenced.json` atteste l'arrêt des processus et empêche leur redémarrage par une condition systemd persistante. Ne pas le supprimer pendant la reprise.
2. Toujours sur cette machine désormais arrêtée, lancer `sudo python3 /usr/local/libexec/noisefence-ha/standby.py push`. L'instantané final doit avoir commencé après le fencing et porter son identifiant d'opération.
3. Copier le reçu par le canal d'administration authentifié sur le pair, mode `0600`. Lancer `sudo python3 /usr/local/libexec/noisefence-ha/promote.py --fence-receipt /chemin/prive/fence.json` dans l'heure qui suit.
4. La restauration utilise un répertoire séparé `active`, vérifie chaque corps, préserve les identifiants et ouvre **uniquement la console** sur `127.0.0.1:18081`. Le proxy HTTPS et l'URL de coordination du worker sont mis à jour. La file propre au worker n'est jamais remplacée. Se reconnecter ; les anciennes sessions sont révoquées.

Si la promotion échoue, le coordinateur reste fenced. Inspecter `active`, `promoted.json`, le journal systemd et le proxy avant toute reprise ; l'outil refuse d'écraser un état déjà restauré. Ne pas retirer ces protections pour relancer aveuglément la commande.

## Sinistre du coordinateur

Faire arrêter physiquement l'ancien hôte via la console du fournisseur. Documenter un reçu privé avec `owner`, `operation` (UUID), `created` (Unix), `fenced: true`, `method: "provider-poweroff"` et `reference` (opération réellement vérifiée). Une panne réseau seule n'est jamais une preuve. Puis utiliser `promote.py --disaster --fence-receipt ...`.

Ce mode accepte un instantané âgé d'au plus 24 heures. Il désactive tous les comptes restaurés et les invitations, crée un compte de récupération dont le mot de passe reste dans le fichier root `recovery-admin.json`, et suspend les nouvelles allocations fournisseurs. Vérifier les droits actuels et réactiver les comptes via la console. Rapprocher les crédits encore présents sur chaque worker avant de retirer le marqueur `ha-recovery-budget-hold`. Les clés de fournisseurs restaurées doivent également être comparées à leur état actuel.

## Revenir à deux machines

La console de secours n'exécute **aucun relais SMTP**. Tant que le pair requis manque, les nouvelles réceptions et tentatives restent différées, conformément au choix de deux copies obligatoires. Ne pas supprimer `[replication]` pour rendre le service artificiellement disponible.

Avant de reprendre le courrier du coordinateur sur un serveur remplacé : arrêter sa console de secours et tous ses auteurs de modifications, prendre un nouvel instantané cohérent de `active/data`, conserver les copies d'origine et leurs journaux, transférer cet état courant (pas l'ancien instantané) vers le remplaçant arrêté avec l'identité du coordinateur, adapter les chemins et rétablir la paire HTTPS. Vérifier les empreintes, les destinataires terminaux et les générations de réplication ; les générations restaurées sont supérieures au journal d'origine. Remettre l'autorité du worker vers le nouveau coordinateur, puis redémarrer après les contrôles. L'ancien hôte reste éteint/fenced jusqu'à réconciliation complète. La commande `ha-restore` refuse d'écraser une file appartenant à un autre nœud.

Cette réintégration est une procédure contrôlée, pas un failback automatique. Ne jamais lancer deux coordinateurs avec la même identité, ni réinstaller une sauvegarde ancienne sur une file en cours. Vérifier les envois incertains manuellement. Garder une copie privée des reçus d'opération.

## Contrôles d'exploitation

- Vue « Infrastructure » : deux copies obligatoires, confirmations initiales, mises à jour en attente, heartbeat et âge du dernier instantané.
- `journalctl -u noisefence -u noisefence-standby-push` : erreurs bornées sans secrets ; surveiller place libre, quota des copies et stagnation des générations.
- `healthz.smtp_ready` devient faux quand le pair requis manque. La console de reprise signale toujours `smtp_ready: false`.
- Exercer périodiquement une restauration dans un répertoire séparé avec réseau isolé, sans SMTP ni comptes de production utilisés pour des essais.
- Schéma 5 après activation : un binaire antérieur à 0.17.1 ne doit pas être utilisé sur cette file. Les scripts de rollback vérifient le schéma.
