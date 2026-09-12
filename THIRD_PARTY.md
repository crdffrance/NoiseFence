# Composants tiers

Le code propre à NoiseFence est distribué sous GPL-3.0-only. Les dépendances conservent
leurs licences respectives. `Cargo.lock` et `web/package-lock.json` identifient les
versions exactes et permettent de retrouver leurs sources dans les registres officiels.

Le serveur utilise notamment Tokio, rustls/ring, mail-auth, mail-parser, Axum,
rusqlite/SQLite, Argon2 et reqwest (MIT/Apache-2.0). Les composants graphiques proviennent de shadcn/ui (MIT)
et Base UI (MIT), avec React (MIT) et Lucide (ISC). Les composants générés conservés
dans `web/components/ui` dérivent de shadcn/ui ; leurs notices sont reproduites dans
`licenses/shadcn-ui-MIT.txt`.

Les builds de release collectent les textes de licence disponibles dans les sources
des crates et paquets npm installés sous `third-party-licenses`. Le manifeste JSON de
ce dossier associe chaque dépendance à sa déclaration de licence et à ses notices.

Le corpus public SpamAssassin se télécharge séparément à la demande de l’exploitant.
Les emails du corpus, les modèles entraînés et les annotations utilisateurs ne sont
pas distribués comme code du projet.

ClamAV s'installe séparément et conserve sa licence GPL. Le programme facultatif
clamav-unofficial-sigs conserve sa licence BSD-3-Clause et ses mentions d'origine ;
le téléchargeur récupère aussi son fichier LICENSE, à installer avec le programme.
Les bases de signatures ont leurs propres conditions d'utilisation et ne sont pas
redistribuées dans les archives NoiseFence. Le manifeste épingle les sources du
programme, pas une copie perpétuelle des bases. L'accès Scaleway relève du compte
et des conditions du fournisseur ; aucun modèle LLM ni secret n'est distribué.

Le worker OCR facultatif utilise les paquets système Tesseract et ses données
françaises/anglaises, ZBar, Pillow et Poppler. Ils s'installent séparément via les
dépôts Debian/Ubuntu ; aucun binaire ni fichier de modèle OCR tiers n'est inclus
dans les archives NoiseFence. Leurs notices et licences sont fournies par les
paquets sous `/usr/share/doc`. `vision-worker.py --capabilities` relève les versions
effectives et les empreintes des données OCR pour tracer le backend utilisé.

La protection des liens utilise scraper (ISC) et html5ever (MIT/Apache-2.0),
ainsi que psl (MIT/Apache-2.0) et sa Public Suffix List embarquée. IDNA conserve
sa licence MIT/Apache-2.0. Les notices présentes dans les crates sont collectées
avec celles des autres dépendances. Les API CRDF et VirusTotal et les flux de
phishing sont facultatifs, soumis aux licences des fournisseurs ; aucun jeu
de données, secret ou droit de redistribution n’est inclus dans NoiseFence.

Les règles structurées Rust de `src/native_filter/content_rules.rs` sont une
implémentation indépendante, inspirée des contrôles HTML, MIME et d’en-têtes de
Rspamd (Apache-2.0). Les sources consultées sont épinglées à la révision
`e2de26d28ce857d5c48ac82703cf26b681bd1d89` ; leurs correspondances et les différences
sont documentées dans `docs/rspamd-rules.md`. La notice amont est conservée dans
`licenses/rspamd-Apache-2.0.md`. Aucun code Lua/C, liste distante, prompt GPT ni poids
d’un modèle Rspamd n’est embarqué ou exécuté.
