# Contribuer à NoiseFence

NoiseFence est développé sous GPL-3.0-only. Les contributions au projet sont proposées
sous cette même licence, en conservant les notices des composants tiers.

Créer une branche à partir de `main` et proposer une pull request décrivant le problème,
le comportement obtenu et les vérifications effectuées. Pour un changement SMTP,
de persistance ou d’autorisation, ajouter un test de régression ciblé. Ne jamais
inclure de messages réels, d’adresses privées, de bases SQLite, de corpus, de clés de
production ou de configurations de serveur dans une contribution.

```sh
python3 scripts/version.py --check
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cd web
npm ci
npx tsc --noEmit
npm run lint
npm run build
```

Les tests utilisent des adresses réservées et des sockets loopback. La clé sous
`tests/fixtures/public-test-key.txt` est publique et dédiée aux tests. Le corpus Apache
se télécharge séparément ; les données d’entraînement et les exports ne font pas partie
du dépôt. Voir [le versionnement](docs/releasing.md) pour les livraisons.
