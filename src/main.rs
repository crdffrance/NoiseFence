use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use noisefence::{
    config::{CompatibilityCase, CompatibilityReport, Config, PROTON_CASES},
    engine::Engine,
    store::Store,
};
use std::{path::PathBuf, sync::Arc};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(short, long, default_value = "config/local.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve,
    CheckConfig,
    Init,
    UserAdd {
        username: String,
        #[arg(long)]
        admin: bool,
        #[arg(long,num_args=1..)]
        addresses: Vec<String>,
    },
    UserDisable {
        username: String,
    },
    UserResetPassword {
        username: String,
    },
    Scan {
        message: PathBuf,
    },
    Queue,
    Retry {
        message_id: String,
    },
    CorpusImport {
        #[arg(long)]
        ham: PathBuf,
        #[arg(long)]
        spam: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Train {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 95.0)]
        threshold: f64,
    },
    ModelActivate {
        candidate: PathBuf,
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    ExportFeedback {
        output: PathBuf,
    },
    Benchmark {
        message: PathBuf,
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
    },
    ProtonReportTemplate {
        output: PathBuf,
    },
    /// Prepare signed test variants on disk; never sends mail or enables live tagging.
    ProtonPrepare {
        message: PathBuf,
        #[arg(long)]
        source_ip: std::net::IpAddr,
        #[arg(long)]
        helo: String,
        #[arg(long)]
        mail_from: String,
        #[arg(long)]
        output: PathBuf,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "noisefence=info".into()),
        )
        .init();
    let cli = Cli::parse();
    match &cli.command {
        Command::CorpusImport { ham, spam, output } => {
            println!(
                "{} examples imported",
                noisefence::corpus::import(ham, spam, output)?
            );
            return Ok(());
        }
        Command::Train {
            input,
            output,
            threshold,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&noisefence::corpus::train(
                    input, output, *threshold
                )?)?
            );
            return Ok(());
        }
        Command::ModelActivate {
            candidate,
            report,
            destination,
        } => {
            noisefence::corpus::activate(candidate, report, destination)?;
            println!("Model activated. Restart the service to load it.");
            return Ok(());
        }
        Command::Benchmark {
            message,
            iterations,
        } => {
            println!("{}", noisefence::corpus::benchmark(message, *iterations)?);
            return Ok(());
        }
        _ => {}
    }
    let config = Arc::new(Config::load(&cli.config)?);
    if let Command::CheckConfig = cli.command {
        println!(
            "Configuration valid ({:?}); no network connection or DNS change performed.",
            config.filter.mode
        );
        return Ok(());
    }
    if let Command::ProtonReportTemplate { output } = cli.command {
        let report = CompatibilityReport {
            hostname: config.hostname.clone(),
            domains: config.domains.iter().map(|d| d.name.clone()).collect(),
            tested_at: 0,
            prefix: "[SPAM]".into(),
            cases: PROTON_CASES
                .iter()
                .map(|name| {
                    (
                        name.to_string(),
                        CompatibilityCase {
                            passed: false,
                            evidence: String::new(),
                        },
                    )
                })
                .collect(),
            bypass_limit_accepted: false,
        };
        std::fs::write(output, serde_json::to_vec_pretty(&report)?)?;
        return Ok(());
    }
    if let Command::ProtonPrepare {
        message,
        source_ip,
        helo,
        mail_from,
        output,
    } = cli.command
    {
        ensure!(
            config.filter.arc_key.is_some() && config.filter.authentication,
            "probe preparation requires configured ARC key and authentication"
        );
        ensure!(
            noisefence::config::valid_address(&mail_from)
                && noisefence::config::valid_domain(&helo),
            "invalid test sender or greeting"
        );
        let raw = std::fs::read(message)?;
        noisefence::message::validate(&raw)?;
        let mut probe = (*config).clone();
        probe.filter.mode = noisefence::config::Mode::Observe;
        let original_engine = Engine::new(Arc::new(probe.clone()))?;
        let (original_scan, untagged) = original_engine
            .process(
                &raw,
                source_ip,
                &helo,
                &mail_from,
                &uuid::Uuid::new_v4().to_string(),
            )
            .await?;
        probe.filter.mode = noisefence::config::Mode::Tag;
        probe.filter.threshold = 0.0;
        let tag_engine = Engine::new(Arc::new(probe))?;
        let (tagged_scan, tagged) = tag_engine
            .process(
                &raw,
                source_ip,
                &helo,
                &mail_from,
                &uuid::Uuid::new_v4().to_string(),
            )
            .await?;
        ensure!(
            original_scan.complete && tagged_scan.complete && tagged_scan.tagged,
            "probe checks incomplete; no tagged variant produced"
        );
        std::fs::create_dir_all(&output)?;
        std::fs::write(output.join("direct.eml"), raw)?;
        std::fs::write(output.join("relay-untagged.eml"), untagged)?;
        std::fs::write(output.join("relay-tagged.eml"), tagged)?;
        std::fs::write(
            output.join("analysis.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"source_ip":source_ip,"helo":helo,"mail_from":mail_from,"untagged":original_scan,"tagged":tagged_scan}),
            )?,
        )?;
        println!(
            "Three probe files prepared. No message sent. Use only controlled test recipients."
        );
        return Ok(());
    }
    let store = Store::open(&config.data_dir)?;
    match cli.command {
        Command::Init => println!("Database initialized; create users with user-add."),
        Command::UserAdd {
            username,
            admin,
            addresses,
        } => {
            for address in &addresses {
                ensure!(
                    config
                        .recipient(address)
                        .is_some_and(|r| r.destination == *address),
                    "grant must name a configured canonical destination: {address}"
                );
            }
            let password = rpassword::prompt_password("Console password (12+ characters): ")?;
            ensure!(
                password == rpassword::prompt_password("Repeat password: ")?,
                "passwords do not match"
            );
            noisefence::api::create_user(&store, username, password, addresses, admin).await?;
            println!("User created.");
        }
        Command::UserDisable { username } => {
            store
                .run(move |db| {
                    let tx = db.transaction()?;
                    ensure!(
                        tx.execute("UPDATE users SET disabled=1 WHERE username=?1", [&username])?
                            == 1,
                        "unknown user"
                    );
                    tx.execute("DELETE FROM sessions WHERE username=?1", [username])?;
                    tx.commit()?;
                    Ok(())
                })
                .await?;
            println!("User disabled; sessions revoked.");
        }
        Command::UserResetPassword { username } => {
            let password = rpassword::prompt_password("New console password: ")?;
            let hash = noisefence::api::hash_password(&password)?;
            store
                .run(move |db| {
                    let tx = db.transaction()?;
                    ensure!(
                        tx.execute(
                            "UPDATE users SET password=?2 WHERE username=?1",
                            rusqlite::params![username, hash]
                        )? == 1,
                        "unknown user"
                    );
                    tx.execute("DELETE FROM sessions WHERE username=?1", [username])?;
                    tx.commit()?;
                    Ok(())
                })
                .await?;
            println!("Password reset; sessions revoked.");
        }
        Command::Scan { message } => {
            let engine = Engine::new(config)?;
            let bytes = std::fs::read(message)?;
            println!("{}", serde_json::to_string_pretty(&engine.offline(&bytes))?);
        }
        Command::Queue => {
            let rows=store.run(|db|{let mut q=db.prepare("SELECT message_id,destination,status,attempts,next_attempt,error FROM deliveries WHERE status!='delivered' ORDER BY next_attempt LIMIT 1000")?;Ok(q.query_map([],|r|Ok(serde_json::json!({"id":r.get::<_,String>(0)?,"destination":r.get::<_,String>(1)?,"status":r.get::<_,String>(2)?,"attempts":r.get::<_,i64>(3)?,"next_attempt":r.get::<_,i64>(4)?,"error":r.get::<_,Option<String>>(5)?})))?.collect::<rusqlite::Result<Vec<_>>>()?)}).await?;
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        Command::Retry { message_id } => {
            ensure!(
                uuid::Uuid::parse_str(&message_id).is_ok(),
                "invalid message id"
            );
            let count=store.run(move|db|Ok(db.execute("UPDATE deliveries SET next_attempt=?2 WHERE message_id=?1 AND status='pending'",rusqlite::params![message_id,noisefence::now()])?)).await?;
            println!("{count} pending deliveries scheduled.");
        }
        Command::ExportFeedback { output } => {
            println!(
                "{} labeled examples exported",
                noisefence::corpus::export_feedback(&store, &output).await?
            );
        }
        Command::Serve => {
            let _lock = store.daemon_lock()?;
            store.recover().await?;
            let engine = Arc::new(Engine::new(config.clone())?);
            let listener = tokio::net::TcpListener::bind(config.smtp.listen).await?;
            let web = tokio::net::TcpListener::bind(config.web.listen).await?;
            let (stop, rx) = tokio::sync::watch::channel(false);
            tracing::info!(smtp=%listener.local_addr()?,web=%web.local_addr()?,mode=?config.filter.mode,"gateway started");
            let state = noisefence::smtp::State {
                config: config.clone(),
                store: store.clone(),
                engine: engine.clone(),
                processing: Arc::new(tokio::sync::Semaphore::new(4)),
            };
            let mut smtp = tokio::spawn(noisefence::smtp::serve(listener, state, rx.clone()));
            let mut relay = tokio::spawn(noisefence::relay::worker(
                config.clone(),
                store.clone(),
                engine,
                rx.clone(),
            ));
            let mut api = tokio::spawn(noisefence::api::serve(web, config, store, rx));
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            tokio::select! {
                _=tokio::signal::ctrl_c()=>{},_ = term.recv()=>{},
                r=&mut smtp=>{r??;anyhow::bail!("SMTP stopped unexpectedly");},
                r=&mut relay=>{r??;anyhow::bail!("relay stopped unexpectedly");},
                r=&mut api=>{r??;anyhow::bail!("API stopped unexpectedly");}
            }
            stop.send(true)?;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(35), async {
                let _ = tokio::join!(smtp, relay, api);
            })
            .await;
        }
        _ => unreachable!(),
    }
    Ok(())
}
