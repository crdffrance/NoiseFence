# Versionner et publier NoiseFence

`Cargo.toml` est la source de vérité pour la version du produit. Le frontend,
`Cargo.lock`, le verrou du fuzzing et `web/package-lock.json` portent la même version
pour NoiseFence. Le modèle possède sa propre version : un entraînement n’est pas
une nouvelle version du logiciel.

Le dépôt utilise `main`, des commits descriptifs et des tags annotés `vMAJOR.MINOR.PATCH`.
Les versions 0.x sont annoncées comme expérimentales. Un changement incompatible
demande une version mineure tant que le projet reste en 0.x ; une correction compatible
demande une version patch. Le changelog précise les migrations et limites.

```sh
python3 scripts/version.py --set 0.1.1
# Renseigner la section correspondante de CHANGELOG.md.
python3 scripts/version.py --check
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Vérifier aussi la console comme indiqué dans CONTRIBUTING.md. Committer les changements,
attendre le succès de la CI, puis créer et pousser le tag annoté correspondant. La commande
`scripts/version.py --check --tag v0.1.1` refuse un tag différent de la version des manifests.

Le workflow `release.yml` compile dans une image Rust Bookworm identifiée par son digest,
sur x86-64 et ARM64. Il assemble les binaires, le frontend statique, les licences, les
exemples et la documentation, puis publie une GitHub Release avec les sommes SHA-256.
Les tests utilisent `cargo test --release`, avec le même profil que le binaire
distribué. Ce profil évite aussi le [défaut de compilation debug ARM64 de gemm-f16](https://github.com/sarah-quinones/gemm/issues/31).
La CI principale vérifie également le moteur multilingue sur un runner ARM64.
Les sources exactes sont accessibles depuis le tag de la release. Les rapports, les
modèles entraînés, les clés et les configurations propres au serveur restent hors Git.

Une release ne change ni la configuration du serveur, ni les MX, ni le mode de filtrage.
Le déploiement et la validation Proton restent des étapes distinctes. Conserver la
version précédente et son répertoire de configuration pour permettre un retour arrière.
