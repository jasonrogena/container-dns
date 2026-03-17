use clap::{Parser, Subcommand, ValueEnum};
use container_dns::{config::Config, dns::server::Server};
use tokio::task::LocalSet;
use tracing::Level;

/// A dedicated DNS server for exposing services running inside containers
#[derive(Debug, Parser)]
#[clap(name = "container-dns")]
#[clap(author, version, about = "A dedicated DNS server for exposing services running inside containers", long_about = None)]
struct Cli {
    /// How verbose the log should be
    #[clap(short, long, default_value = "info")]
    log_level: LogLevel,
    /// Path to the configuration file to use
    #[clap(required = true)]
    config_path: String,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the DNS server
    Serve,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
#[clap(rename_all = "kebab-case")]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for Level {
    fn from(l: LogLevel) -> Self {
        match l {
            LogLevel::Error => Level::ERROR,
            LogLevel::Warn => Level::WARN,
            LogLevel::Info => Level::INFO,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Trace => Level::TRACE,
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args = Cli::parse();
    tracing_subscriber::fmt()
        .with_max_level(Level::from(args.log_level))
        .init();
    match args.command {
        Commands::Serve => serve(args.config_path).await,
    };
}

async fn serve(config_path: String) {
    let config = Config::new(&config_path).unwrap();
    let server = Server::new(config.dns_server).await.unwrap();
    let local_set = LocalSet::new();
    server.start(local_set).await;
}
