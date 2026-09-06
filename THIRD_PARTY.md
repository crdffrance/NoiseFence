# Composants tiers

Le code propre à NoiseFence est distribué sous GPL-3.0-only. Les dépendances conservent
leurs licences respectives. `Cargo.lock` et `web/package-lock.json` identifient les
versions exactes et permettent de retrouver leurs sources dans les registres officiels.

Le serveur utilise notamment Tokio, rustls/ring, mail-auth, mail-parser, Axum,
rusqlite/SQLite et Argon2. Les composants graphiques proviennent de shadcn/ui (MIT)
et Base UI (MIT), avec React (MIT) et Lucide (ISC). Les composants générés conservés
dans `web/components/ui` dérivent de shadcn/ui ; leurs notices sont reproduites dans
`licenses/shadcn-ui-MIT.txt`.

Les builds de release collectent les textes de licence disponibles dans les sources
des crates et paquets npm installés sous `third-party-licenses`. Le manifeste JSON de
ce dossier associe chaque dépendance à sa déclaration de licence et à ses notices.

Le corpus public SpamAssassin se télécharge séparément à la demande de l’exploitant.
Les emails du corpus, les modèles entraînés et les annotations utilisateurs ne sont
pas distribués comme code du projet.
