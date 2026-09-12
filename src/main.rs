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
#[derive(Clone, Copy, clap::ValueEnum)]
enum ProbeCategory {
    Spam,
    Publicity,
}
impl ProbeCategory {
    fn prefix(self) -> &'static str {
        match self {
            Self::Spam => "[SPAM]",
            Self::Publicity => "[PUB]",
        }
    }
}
#[derive(Subcommand)]
enum Command {
    /// Inspect local adaptive candidates for a supplied domain; no DNS or delivery.
    AdaptiveCheck {
        message: PathBuf,
        #[arg(long)]
        domain: String,
        #[arg(long, default_value_t = 1)]
        iterations: usize,
    },
    /// Export explicit five-class annotations and private features from one domain.
    AdaptiveExport {
        #[arg(long)]
        username: String,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Train local multiclass Bayes and neural candidates; never activates delivery.
    AdaptiveTrain {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        train_until: i64,
        #[arg(long)]
        validation_until: i64,
    },
    /// Evaluate the frozen candidate on later independent human annotations.
    AdaptiveEvaluate {
        input: PathBuf,
        #[arg(long)]
        model: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        training_report: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Measure native Rust filtering with concurrent local tasks; no network or database.
    NativeBenchmark {
        message: PathBuf,
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
    },
    /// Audit recipient-scoped observations and human corrections; never changes delivery.
    ReliabilityAudit {
        #[arg(long)]
        username: String,
        #[arg(long, default_value_t = 7)]
        days: u32,
        #[arg(long, default_value = "")]
        domain: String,
    },
    /// Inspect the existing Proton compatibility evidence without activating tagging.
    ProtonCheck,
    /// Export authorized human labels and private native features; no message bodies.
    NativeExport {
        #[arg(long)]
        username: String,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Train OSB Bayes in Rust with chronological, campaign-separated evaluation.
    NativeTrain {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        version: String,
        #[arg(long)]
        train_until: i64,
        #[arg(long)]
        validation_until: i64,
    },
    /// Evaluate a frozen OSB candidate on new, independent human labels.
    NativeEvaluate {
        input: PathBuf,
        #[arg(long)]
        model: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        training_report: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Serve,
    CheckConfig,
    /// Restore the bootstrap policy; requires the daemon to be stopped.
    ConsoleReset,
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
    /// Read image/PDF text and barcodes locally; no delivery, database, DNS or LLM.
    VisionInspect {
        message: PathBuf,
    },
    /// Inspect SMTP identity via DNS only; no message, delivery, model or paid call.
    SmtpCheck {
        #[arg(long)]
        source_ip: std::net::IpAddr,
        #[arg(long)]
        helo: String,
        #[arg(long, default_value = "")]
        mail_from: String,
        #[arg(long, default_value_t = 1)]
        iterations: usize,
    },
    /// Query configured IP DNSBLs without a message, model, queue or SMTP delivery.
    RblCheck {
        #[arg(long)]
        source_ip: std::net::IpAddr,
        #[arg(long, default_value_t = 1)]
        iterations: usize,
    },
    /// Run configured analysis once without queueing or delivering the message.
    Analyze {
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
    /// Export versioned features from a local research manifest; no message delivery.
    FeaturesExport {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 3)]
        feature_version: u32,
    },
    Train {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 95.0)]
        threshold: f64,
        #[arg(long, value_enum, default_value_t = noisefence::engine::Algorithm::Logistic)]
        algorithm: noisefence::engine::Algorithm,
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
    /// Draw a frozen, recipient-scoped evaluation sample without reading bodies.
    QualitySample {
        #[arg(long)]
        username: String,
        #[arg(long)]
        since: i64,
        #[arg(long)]
        until: i64,
        #[arg(long, default_value_t = 100)]
        count: usize,
        #[arg(long, default_value = "")]
        domain: String,
    },
    /// Export an annotated sample privately on the server; no content or delivery.
    QualityExport {
        #[arg(long)]
        username: String,
        #[arg(long)]
        batch: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Check a data-only joint candidate against one recorded observation.
    QualityPredict {
        #[arg(long)]
        model: PathBuf,
        #[arg(long)]
        observation: PathBuf,
    },
    /// Aggregate human feedback and replay confirmation, read-only and without external calls.
    AuditConfirmation {
        database: PathBuf,
    },
    /// Export private schema-3 learning vectors; never queues or delivers mail.
    ExportLearning {
        output: PathBuf,
        #[arg(long)]
        require_semantic: bool,
    },
    /// Snapshot all retained accepted messages, including missing/limited analysis.
    ExportPopulation {
        output: PathBuf,
        /// Inclusive Unix time, within the last 30 days.
        #[arg(long)]
        since: i64,
        /// Exclusive Unix time; defaults to now + 1 second.
        #[arg(long)]
        until: Option<i64>,
    },
    /// Encode trusted detector observations from a private learning export, offline.
    FusionExport {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Evaluate a research fusion model offline; never activates or delivers mail.
    FusionPredict {
        input: PathBuf,
        #[arg(long)]
        model: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Predict every retained population row offline, including unassessable cases.
    FusionPopulationPredict {
        input: PathBuf,
        #[arg(long)]
        model: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Benchmark {
        message: PathBuf,
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
    },
    /// Measure native feature extraction plus model inference, excluding connectors.
    ModelBenchmark {
        message: PathBuf,
        #[arg(long)]
        model: PathBuf,
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
        #[arg(long, requires = "encoder")]
        semantic_combination: Option<PathBuf>,
        #[arg(long, requires = "semantic_combination")]
        encoder: Option<PathBuf>,
    },
    ProtonReportTemplate {
        output: PathBuf,
        #[arg(long, value_enum, default_value_t = ProbeCategory::Spam)]
        category: ProbeCategory,
    },
    /// Prepare signed test variants on disk; never sends mail or enables live tagging.
    ProtonPrepare {
        message: PathBuf,
        #[arg(long, value_enum, default_value_t = ProbeCategory::Spam)]
        category: ProbeCategory,
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
        Command::AdaptiveCheck {
            message,
            domain,
            iterations,
        } => {
            ensure!(
                (1..=10000).contains(iterations),
                "adaptive iterations must be 1..10000"
            );
            let config = Config::load(&cli.config)?;
            let settings = config
                .native_filter
                .clone()
                .ok_or_else(|| anyhow::anyhow!("native_filter is not configured"))?;
            ensure!(
                settings
                    .adaptive
                    .as_ref()
                    .is_some_and(|a| a.domains.contains_key(domain)),
                "adaptive domain is not configured"
            );
            let raw = noisefence::native_filter::read_bounded(message, settings.max_bytes)?;
            let runtime = noisefence::native_filter::Runtime::new(settings)?;
            let mut elapsed = Vec::new();
            let mut last = None;
            for _ in 0..*iterations {
                let started = std::time::Instant::now();
                let observation = runtime.offline(&raw, std::slice::from_ref(domain));
                elapsed.push(started.elapsed().as_micros() as u64);
                last = observation.report.adaptive;
            }
            elapsed.sort_unstable();
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"report":last,"iterations":iterations,"source":"supplied_domain","p95_microseconds":elapsed[(elapsed.len()*95).div_ceil(100)-1],"affects_delivery":false})
                )?
            );
            return Ok(());
        }
        Command::AdaptiveTrain {
            input,
            output,
            version,
            train_until,
            validation_until,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&noisefence::adaptive::training::train(
                    input,
                    output,
                    version,
                    *train_until,
                    *validation_until
                )?)?
            );
            return Ok(());
        }
        Command::AdaptiveEvaluate {
            input,
            model,
            manifest,
            training_report,
            output,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&noisefence::adaptive::training::evaluate(
                    input,
                    model,
                    manifest,
                    training_report,
                    output
                )?)?
            );
            return Ok(());
        }
        Command::NativeBenchmark {
            message,
            iterations,
            concurrency,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &noisefence::native_filter::benchmark::run(message, *iterations, *concurrency)
                        .await?
                )?
            );
            return Ok(());
        }
        Command::NativeTrain {
            input,
            output,
            version,
            train_until,
            validation_until,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&noisefence::native_filter::learning::train(
                    input,
                    output,
                    version,
                    *train_until,
                    *validation_until
                )?)?
            );
            return Ok(());
        }
        Command::NativeEvaluate {
            input,
            model,
            manifest,
            training_report,
            output,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&noisefence::native_filter::learning::evaluate(
                    input,
                    model,
                    manifest,
                    training_report,
                    output
                )?)?
            );
            return Ok(());
        }
        Command::QualityPredict { model, observation } => {
            use std::io::Read;
            let model = noisefence::quality::Model::load(model)?;
            let mut bytes = vec![];
            std::fs::File::open(observation)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 1024 * 1024, "oversized quality observation");
            let observation = serde_json::from_slice(&bytes)?;
            println!("{}", serde_json::to_string(&model.predict(&observation)?)?);
            return Ok(());
        }
        Command::AuditConfirmation { database } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&noisefence::confirmation::audit(database)?)?
            );
            return Ok(());
        }
        Command::FusionPopulationPredict {
            input,
            model,
            output,
        } => {
            println!(
                "{}",
                serde_json::to_string(&noisefence::fusion::population::predict(
                    input, model, output
                )?)?
            );
            return Ok(());
        }
        Command::FusionExport { input, output } => {
            println!(
                "{}",
                serde_json::to_string(&noisefence::fusion::io::convert(input, output, None)?)?
            );
            return Ok(());
        }
        Command::FusionPredict {
            input,
            model,
            output,
        } => {
            let model = noisefence::fusion::Model::load(model)?;
            println!(
                "{}",
                serde_json::to_string(&noisefence::fusion::io::convert(
                    input,
                    output,
                    Some(&model)
                )?)?
            );
            return Ok(());
        }
        Command::ModelBenchmark {
            message,
            model,
            iterations,
            semantic_combination,
            encoder,
        } => {
            let semantic = semantic_combination.as_ref().zip(encoder.as_ref()).map(
                |(combination, encoder_dir)| noisefence::config::SemanticFilter {
                    combination: combination.clone(),
                    encoder_dir: encoder_dir.clone(),
                    max_parallel: 1,
                    timeout_ms: 500,
                },
            );
            println!(
                "{}",
                noisefence::research::benchmark(model, message, *iterations, semantic.as_ref())?
            );
            return Ok(());
        }
        Command::FeaturesExport {
            manifest,
            root,
            output,
            feature_version,
        } => {
            println!(
                "{}",
                noisefence::research::export(manifest, root, output, *feature_version)?
            );
            return Ok(());
        }
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
            algorithm,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&noisefence::corpus::train_with_algorithm(
                    input, output, *threshold, *algorithm
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
    let bootstrap = Arc::new(Config::load(&cli.config)?);
    let config = if matches!(cli.command, Command::Serve | Command::ConsoleReset) {
        bootstrap
    } else {
        noisefence::control::effective_from_disk(bootstrap)?
    };
    if matches!(cli.command, Command::ConsoleReset) {
        let store = Store::open(&config.data_dir)?;
        let _lock = store.daemon_lock()?;
        let settings = serde_json::to_string(&noisefence::control::Settings::from_config(&config))?;
        let revision = store.run(move |db| {
            let tx = db.transaction()?;
            tx.execute("INSERT INTO console_revisions(created,username,settings) VALUES(?1,'local-administrator',?2)", rusqlite::params![noisefence::now(),settings])?;
            let id = tx.last_insert_rowid();
            tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,'local-administrator','configuration',?2)",rusqlite::params![noisefence::now(),id.to_string()])?;
            tx.commit()?; Ok(id)
        }).await?;
        println!(
            "Bootstrap settings restored as revision {revision}. Start the daemon to apply them."
        );
        return Ok(());
    }
    if let Command::VisionInspect { message } = &cli.command {
        use std::io::Read;
        let mut raw = Vec::new();
        std::fs::File::open(message)?
            .take(config.smtp.max_message_bytes as u64 + 1)
            .read_to_end(&mut raw)?;
        ensure!(
            raw.len() <= config.smtp.max_message_bytes,
            "message exceeds configured size limit"
        );
        let client = noisefence::vision::Client::new(
            config
                .vision
                .clone()
                .ok_or_else(|| anyhow::anyhow!("configure [vision] first"))?,
        )?;
        println!(
            "{}",
            serde_json::to_string_pretty(&client.inspect(&raw).await)?
        );
        return Ok(());
    }
    if let Command::RblCheck {
        source_ip,
        iterations,
    } = &cli.command
    {
        ensure!((1..=100).contains(iterations), "iterations must be 1..100");
        let rbl = noisefence::rbl::Runtime::new(
            config.rbl.as_ref(),
            config.filter.spamhaus_key_env.as_deref(),
        )?;
        for _ in 0..*iterations {
            println!(
                "{}",
                serde_json::to_string(
                    &rbl.check(
                        *source_ip,
                        config.filter.mode,
                        config.filter.spamhaus_key_env.is_some()
                    )
                    .await
                )?
            );
        }
        return Ok(());
    }
    if let Command::SmtpCheck {
        source_ip,
        helo,
        mail_from,
        iterations,
    } = &cli.command
    {
        ensure!(
            helo.len() <= 255 && helo.is_ascii() && !helo.bytes().any(|b| b.is_ascii_control()),
            "invalid SMTP greeting input"
        );
        ensure!(
            mail_from.is_empty() || noisefence::config::valid_address(mail_from),
            "invalid SMTP envelope input"
        );
        ensure!((1..=100).contains(iterations), "iterations must be 1..100");
        let policy = noisefence::smtp_policy::Policy::new(
            config
                .smtp_policy
                .clone()
                .ok_or_else(|| anyhow::anyhow!("configure [smtp_policy] first"))?,
        )?;
        for _ in 0..*iterations {
            println!(
                "{}",
                serde_json::to_string(
                    &policy
                        .check(*source_ip, helo, mail_from, &config.hostname)
                        .await
                )?
            );
        }
        return Ok(());
    }
    if let Command::Analyze {
        message,
        source_ip,
        helo,
        mail_from,
        output,
    } = &cli.command
    {
        ensure!(!output.exists(), "analysis output already exists");
        ensure!(
            noisefence::config::valid_address(mail_from) && noisefence::config::valid_domain(helo),
            "invalid analysis envelope or greeting"
        );
        let raw = std::fs::read(message)?;
        noisefence::message::validate(&raw)?;
        let engine = Engine::new(config.clone())?;
        let (analysis, _) = engine
            .process(
                &raw,
                *source_ip,
                helo,
                mail_from,
                &uuid::Uuid::new_v4().to_string(),
            )
            .await?;
        let payload = serde_json::to_vec_pretty(&analysis)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(output)?;
        std::io::Write::write_all(&mut file, &payload)?;
        file.sync_all()?;
        println!(
            "{}",
            serde_json::json!({"output":output,"complete":analysis.complete,"score":analysis.score,"model":analysis.model,"elapsed_ms":analysis.elapsed_ms,"sent":false})
        );
        return Ok(());
    }
    if let Command::CheckConfig = cli.command {
        println!(
            "Configuration valid ({:?}); no network connection or DNS change performed.",
            config.filter.mode
        );
        return Ok(());
    }
    if let Command::ProtonReportTemplate { output, category } = cli.command {
        let report = CompatibilityReport {
            hostname: config.hostname.clone(),
            domains: config.domains.iter().map(|d| d.name.clone()).collect(),
            tested_at: 0,
            prefix: category.prefix().into(),
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
        category,
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
        probe.actions = None;
        probe.filter.mode = noisefence::config::Mode::Observe;
        if matches!(category, ProbeCategory::Publicity) {
            probe.mailing = Some(Default::default());
        }
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
        if matches!(category, ProbeCategory::Spam) {
            probe.filter.threshold = 0.0;
        }
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
        std::fs::create_dir_all(&output)?;
        std::fs::write(
            output.join("analysis.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"source_ip":source_ip,"helo":helo,"mail_from":mail_from,"prefix":category.prefix(),"untagged":original_scan,"tagged":tagged_scan}),
            )?,
        )?;
        ensure!(
            original_scan.complete
                && tagged_scan.complete
                && match category {
                    ProbeCategory::Spam => tagged_scan.tagged,
                    ProbeCategory::Publicity => tagged_scan.pub_tagged,
                },
            "probe checks incomplete or requested category not detected; see analysis.json; no tagged variant produced"
        );
        std::fs::write(output.join("direct.eml"), raw)?;
        std::fs::write(output.join("relay-untagged.eml"), untagged)?;
        std::fs::write(output.join("relay-tagged.eml"), tagged)?;
        println!(
            "Three probe files prepared. No message sent. Use only controlled test recipients."
        );
        return Ok(());
    }
    let store = Store::open(&config.data_dir)?;
    match cli.command {
        Command::ReliabilityAudit {
            username,
            days,
            domain,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &noisefence::reliability::audit(
                        &store,
                        username,
                        noisefence::reliability::Options { days, domain }
                    )
                    .await?
                )?
            );
        }
        Command::ProtonCheck => {
            println!(
                "{}",
                serde_json::to_string_pretty(&noisefence::reliability::proton::checklist(&config))?
            );
        }
        Command::NativeExport {
            username,
            domain,
            output,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &noisefence::native_filter::learning::export(&store, username, domain, &output)
                        .await?
                )?
            );
        }
        Command::AdaptiveExport {
            username,
            domain,
            output,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &noisefence::adaptive::data::export(&store, username, domain, &output).await?
                )?
            );
        }
        Command::Init => println!("Database initialized; create users with user-add."),
        Command::UserAdd {
            username,
            admin,
            addresses,
        } => {
            for address in &addresses {
                ensure!(
                    (address
                        .strip_prefix("*@")
                        .is_some_and(|domain| config.domains.iter().any(|d| d.name == domain)))
                        || config
                            .recipient(address)
                            .is_some_and(|r| r.destination == *address),
                    "grant must name a configured canonical destination or *@domain: {address}"
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
                    let admins:i64=tx.query_row("SELECT COUNT(*) FROM users WHERE admin=1 AND disabled=0",[],|r|r.get(0))?;
                    ensure!(admins>0,"the last active administrator cannot be disabled");
                    tx.execute("DELETE FROM sessions WHERE username=?1", [&username])?;
                    tx.execute("INSERT INTO console_user_versions(username,version) VALUES(?1,1) ON CONFLICT(username) DO UPDATE SET version=version+1",[&username])?;
                    tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,'local-administrator','account',?2)",rusqlite::params![noisefence::now(),username])?;
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
                    tx.execute("DELETE FROM sessions WHERE username=?1", [&username])?;
                    tx.execute("INSERT INTO console_user_versions(username,version) VALUES(?1,1) ON CONFLICT(username) DO UPDATE SET version=version+1",[&username])?;
                    tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,'local-administrator','account',?2)",rusqlite::params![noisefence::now(),username])?;
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
        Command::ExportLearning {
            output,
            require_semantic,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &noisefence::learning::export(&store, &output, require_semantic).await?
                )?
            );
        }
        Command::ExportFeedback { output } => {
            println!(
                "{} labeled examples exported",
                noisefence::corpus::export_feedback(&store, &output).await?
            );
        }
        Command::QualitySample {
            username,
            since,
            until,
            count,
            domain,
        } => {
            println!(
                "{}",
                noisefence::quality::evaluation::sample(
                    &store, username, since, until, count, domain
                )
                .await?
            );
        }
        Command::QualityExport {
            username,
            batch,
            output,
        } => {
            println!(
                "{}",
                noisefence::quality::evaluation::export(&store, username, batch, &output).await?
            );
        }
        Command::ExportPopulation {
            output,
            since,
            until,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &noisefence::population::export(
                        &store,
                        &output,
                        since,
                        until.unwrap_or_else(|| noisefence::now() + 1)
                    )
                    .await?
                )?
            );
        }
        Command::Serve => {
            let _lock = store.daemon_lock()?;
            store.recover().await?;
            let control =
                noisefence::control::Controller::load(config.clone(), store.clone()).await?;
            let engine = control.snapshot().engine.clone();
            let listener = tokio::net::TcpListener::bind(config.smtp.listen).await?;
            let web = tokio::net::TcpListener::bind(config.web.listen).await?;
            let (stop, rx) = tokio::sync::watch::channel(false);
            tracing::info!(smtp=%listener.local_addr()?,web=%web.local_addr()?,mode=?config.filter.mode,processing=config.smtp.max_processing,relay_workers=config.relay.workers,"gateway started");
            let state = noisefence::smtp::State {
                config: config.clone(),
                store: store.clone(),
                engine: engine.clone(),
                processing: Arc::new(tokio::sync::Semaphore::new(config.smtp.max_processing)),
            };
            let mut smtp = tokio::spawn(noisefence::smtp::serve_controlled(
                listener,
                state,
                Some(control.clone()),
                rx.clone(),
            ));
            let mut relay = tokio::spawn(noisefence::relay::worker_controlled(
                config.clone(),
                store.clone(),
                engine,
                Some(control.clone()),
                rx.clone(),
            ));
            let mut api = tokio::spawn(noisefence::api::serve_controlled(
                web,
                config,
                store,
                Some(control),
                rx,
            ));
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
