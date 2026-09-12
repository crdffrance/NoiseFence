# Versionner et publier NoiseFence

`Cargo.toml` est la source de vérité pour la version du produit. Le frontend,
`Cargo.lock`, le verrou du fuzzing et `web/package-lock.json` portent la même version
pour NoiseFence. Le modèle possède sa propre version : un entraînement n’est pas
une nouvelle version du logiciel.

Le dépôt utilise `main`, des commits descriptifs et des tags annotés `vMAJOR.MINOR.PATCH`.
Les tags sans suffixe sont les releases finales ; `-dev.N` et `-rc.N` sont des
préversions. Le projet reste en 0.x. Un changement incompatible
demande une version mineure tant que le projet reste en 0.x ; une correction compatible
demande une version patch. Le changelog précise les migrations et limites.

```sh
python3 scripts/version.py --set 0.4.0
# Renseigner la section correspondante de CHANGELOG.md.
python3 scripts/version.py --check
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Vérifier aussi la console comme indiqué dans CONTRIBUTING.md. Committer les changements,
attendre le succès de la CI, puis créer et pousser le tag annoté correspondant. La commande
`scripts/version.py --check --tag v0.4.0` refuse un tag différent de la version des manifests.

Le workflow `release.yml` compile dans une image Rust Bookworm identifiée par son digest,
sur x86-64 et ARM64. Il assemble les binaires, le frontend statique, les licences, les
exemples et la documentation, puis prépare une GitHub Release avec les sommes SHA-256.
Le workflow appelle aussi la suite complète `check.yml` sur le même tag ; un échec
interdit la publication.
Les tests utilisent `cargo test --release`, avec le même profil que le binaire
distribué. Ce profil évite aussi le [défaut de compilation debug ARM64 de gemm-f16](https://github.com/sarah-quinones/gemm/issues/31).
La CI principale vérifie également le moteur multilingue sur un runner ARM64.
Les sources exactes sont accessibles depuis le tag de la release. Les rapports, les
modèles entraînés, les clés et les configurations propres au serveur restent hors Git,
à l’exception des rapports de recherche agrégés explicitement versionnés.

Les notes sont extraites de la seule section du changelog correspondant au tag par
`scripts/release_notes.py`. Une section absente, vide ou dupliquée bloque la release.
Les préversions sont publiées avec l’indicateur GitHub « Pre-release » ; les versions
finales sont préparées en brouillon pour vérifier les deux archives avant publication.
Contrôler les sommes SHA-256, `build.json` (version, commit et architecture),
les licences et l’absence de données privées. Publier ensuite le brouillon :

```sh
gh release edit v0.4.0 --repo crdffrance/NoiseFence --draft=false --prerelease=false --latest
```

Ne jamais déplacer un tag publié ou remplacer ses archives par une construction
différente. Une correction demande une nouvelle version. Avant la première ouverture
du dépôt, contrôler également les branches, tags et objets de l’historique pour éviter
de publier des secrets supprimés du seul arbre courant.

Une release ne change ni la configuration du serveur, ni les MX, ni le mode de filtrage.
Le déploiement et la validation Proton restent des étapes distinctes. Conserver la
version précédente et son répertoire de configuration pour permettre un retour arrière.

Depuis 0.14, les archives portent `storage_schema: 3` dans `build.json` (schéma 2 avant 0.14). Le stockage est marqué 3 à l’activation du cluster ; voir [multi-MX](multi-mx.md). Un retour automatique vers une archive de schéma incompatible est refusé. Voir [la migration](actions.md#migration-de-stockage) avant toute restauration.
