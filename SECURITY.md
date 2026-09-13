# Signaler une vulnérabilité

Les corrections de sécurité visent la dernière release finale disponible,
actuellement la série **0.15.x**. Les préversions `-dev` et les séries antérieures
ne bénéficient pas d’une maintenance séparée. Le projet reste en 0.x et les
changements incompatibles sont accompagnés d’instructions de migration.

Utiliser [le signalement privé GitHub](https://github.com/crdffrance/NoiseFence/security/advisories/new)
pour une faille exploitable, notamment un relais ouvert, un accès entre utilisateurs,
une perte de message accepté ou une ambiguïté SMTP. Décrire les versions concernées,
la configuration minimale et une reproduction avec des messages synthétiques.
Ne pas publier de clé, de contenu privé ou d’identifiant de session.

Si le signalement privé GitHub n’est pas disponible, ouvrir une issue demandant
un canal privé, sans détail d’exploitation ni données sensibles. Aucune durée
de réponse contractuelle n’est annoncée.

Les limites déjà connues figurent dans [le périmètre de sécurité](docs/security.md)
et [les résultats de validation](docs/validation-results.md).

Le [guide de durcissement Linux](deploy/hardening/README.md) décrit les profils, les sauvegardes, les accès et la récupération MFA. Le second facteur doit être enrôlé par le titulaire du compte ; il ne protège pas un compte qui ne l’a pas activé.
