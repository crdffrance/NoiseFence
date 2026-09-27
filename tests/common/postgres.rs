//! Disposable, per-test databases. This helper never accepts a remote host.
use noisefence::central::{Central, Settings};

pub struct Fixture {
    pub central: Central,
    pub settings: Settings,
    admin: tokio_postgres::Client,
    config: tokio_postgres::Config,
}
impl Fixture {
    pub async fn new() -> Self {
        let password_file = std::env::var_os("NOISEFENCE_TEST_PG_PASSWORD_FILE")
            .expect("explicit test credential path required");
        let password = std::fs::read_to_string(&password_file).unwrap();
        let mut config = tokio_postgres::Config::new();
        config
            .host("127.0.0.1")
            .port(15432)
            .user("postgres")
            .dbname("noisefence_test")
            .password(password.trim());
        let (admin, connection) = config.connect(tokio_postgres::NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let database = format!("nf_test_{}", uuid::Uuid::new_v4().simple());
        admin
            .batch_execute(&format!("CREATE DATABASE {database}"))
            .await
            .unwrap();
        config.dbname(&database);
        let settings = Settings {
            host: "127.0.0.1".into(),
            port: 15432,
            database,
            username: "postgres".into(),
            password_file: Some(password_file.into()),
            ca_file: None,
            max_connections: 2,
            allow_loopback_plaintext: true,
        };
        let central = Central::new(&settings).unwrap();
        central.migrate().await.unwrap();
        Self {
            central,
            settings,
            admin,
            config,
        }
    }
    pub async fn connect(&self) -> tokio_postgres::Client {
        let (client, connection) = self.config.connect(tokio_postgres::NoTls).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
    }
    pub async fn finish(self) {
        let database = self.settings.database;
        assert!(
            database.starts_with("nf_test_")
                && database
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
        drop(self.central);
        self.admin
            .batch_execute(&format!("DROP DATABASE {database} WITH (FORCE)"))
            .await
            .unwrap();
    }
    #[allow(dead_code)]
    pub async fn suspend(&self) {
        self.admin
            .batch_execute(&format!(
                "ALTER DATABASE {} ALLOW_CONNECTIONS false",
                self.settings.database
            ))
            .await
            .unwrap();
        self.admin
            .query(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1",
                &[&self.settings.database],
            )
            .await
            .unwrap();
    }
    #[allow(dead_code)]
    pub async fn resume(&self) {
        self.admin
            .batch_execute(&format!(
                "ALTER DATABASE {} ALLOW_CONNECTIONS true",
                self.settings.database
            ))
            .await
            .unwrap();
    }
}
