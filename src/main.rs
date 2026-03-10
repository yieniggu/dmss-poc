use anyhow::Result;
use clap::{Parser, Subcommand};
use dmss_poc::{
    analyze::{
        analyze_capture_dir, compare_capture_with_references, render_analysis_report,
        render_reference_comparison_report,
    },
    bootstrap::bootstrap_flow,
    ptcp_flow::perform_ptcp_sync_with_credentials,
    traversal::perform_stun,
};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "dmss_poc")]
#[command(about = "PoC Rust del flujo remoto DMSS fuera de la app movil")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Bootstrap {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        device_user: String,
        #[arg(long)]
        device_password: String,
    },
    Stun {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        device_user: String,
        #[arg(long)]
        device_password: String,
    },
    PtcpSync {
        #[arg(long)]
        serial: String,
        #[arg(long)]
        device_user: String,
        #[arg(long)]
        device_password: String,
    },
    AnalyzeCapture {
        #[arg(long)]
        dir: PathBuf,
    },
    CompareReference {
        #[arg(long)]
        capture_dir: PathBuf,
        #[arg(long)]
        reference_h264: PathBuf,
        #[arg(long)]
        reference_raw: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Bootstrap {
            serial,
            device_user,
            device_password,
        } => run_bootstrap(&serial, &device_user, &device_password).await,
        Command::Stun {
            serial,
            device_user,
            device_password,
        } => run_stun(&serial, &device_user, &device_password).await,
        Command::PtcpSync {
            serial,
            device_user,
            device_password,
        } => run_ptcp_sync(&serial, &device_user, &device_password).await,
        Command::AnalyzeCapture { dir } => run_analyze_capture(&dir),
        Command::CompareReference {
            capture_dir,
            reference_h264,
            reference_raw,
        } => run_compare_reference(&capture_dir, &reference_h264, &reference_raw),
    }
}

async fn run_bootstrap(serial: &str, device_user: &str, device_password: &str) -> Result<()> {
    let _ = bootstrap_flow(serial, device_user, device_password).await?;
    Ok(())
}

async fn run_stun(serial: &str, device_user: &str, device_password: &str) -> Result<()> {
    let context = bootstrap_flow(serial, device_user, device_password).await?;
    let _ = perform_stun(context).await?;
    Ok(())
}

async fn run_ptcp_sync(serial: &str, device_user: &str, device_password: &str) -> Result<()> {
    let context = bootstrap_flow(serial, device_user, device_password).await?;
    let context = perform_stun(context).await?;
    perform_ptcp_sync_with_credentials(context, device_user, device_password).await
}

fn run_analyze_capture(dir: &PathBuf) -> Result<()> {
    let analysis = analyze_capture_dir(dir)?;
    print!("{}", render_analysis_report(&analysis));
    println!("[analysis] report={}", analysis.report_path.display());
    Ok(())
}

fn run_compare_reference(
    capture_dir: &PathBuf,
    reference_h264: &PathBuf,
    reference_raw: &PathBuf,
) -> Result<()> {
    let comparison = compare_capture_with_references(capture_dir, reference_h264, reference_raw)?;
    print!("{}", render_reference_comparison_report(&comparison));
    println!("[reference] report={}", comparison.report_path.display());
    Ok(())
}
