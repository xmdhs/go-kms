// go-kms (Rust port) — CLI entry point.
//
// Subcommands mirror the original Go binary:
//   go-kms server [-ip IP] [-port N] [-epid EPID] [-lcid N] [-count N] [-activation N] [-renewal N] [-hwid HEX]
//   go-kms client [-ip IP] [-port N] [-mode MODE] [-cmid UUID] [-name MACHINE]

use std::process::ExitCode;

use kms_rs::client::{lookup_product, product_names, run as run_client, ClientConfig};
use kms_rs::kms::base::ServerConfig;
use kms_rs::kms::uuid::KmsUuid;
use kms_rs::logger;
use kms_rs::server::KmsServer;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return ExitCode::from(1);
    }
    match args[1].as_str() {
        "server" => match run_server(&args[2..]).await {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("server error: {}", e);
                ExitCode::from(1)
            }
        },
        "client" => match run_client_cmd(&args[2..]).await {
            Ok(_) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("client error: {}", e);
                ExitCode::from(1)
            }
        },
        _ => {
            print_usage();
            ExitCode::from(1)
        }
    }
}

fn print_usage() {
    println!("go-kms (Rust port): KMS Server/Client Emulator");
    println!();
    println!("Usage:");
    println!("  go-kms server [options]    Start KMS server");
    println!("  go-kms client [options]    Run KMS client");
}

async fn run_server(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = ServerConfig::default();
    let mut hwid_str = "364F463A8863D35F".to_string();
    let mut client_count: Option<u32> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let next = || -> Result<&str, String> {
            args.get(i + 1)
                .map(|s| s.as_str())
                .ok_or_else(|| format!("missing value for {}", a))
        };
        match a {
            "-ip" => {
                config.ip = next()?.to_string();
                i += 2;
            }
            "-port" => {
                config.port = next()?.parse()?;
                i += 2;
            }
            "-epid" => {
                config.epid = next()?.to_string();
                i += 2;
            }
            "-lcid" => {
                config.lcid = next()?.parse()?;
                i += 2;
            }
            "-count" => {
                let n: u32 = next()?.parse()?;
                if n > 0 {
                    client_count = Some(n);
                }
                i += 2;
            }
            "-activation" => {
                config.activation = next()?.parse()?;
                i += 2;
            }
            "-renewal" => {
                config.renewal = next()?.parse()?;
                i += 2;
            }
            "-hwid" => {
                hwid_str = next()?.to_string();
                i += 2;
            }
            "-h" | "--help" => {
                println!("server options: -ip -port -epid -lcid -count -activation -renewal -hwid");
                return Ok(());
            }
            _ => return Err(format!("unknown flag: {}", a).into()),
        }
    }
    config.client_count = client_count;

    let trimmed = hwid_str
        .strip_prefix("0x")
        .or_else(|| hwid_str.strip_prefix("0X"))
        .unwrap_or(&hwid_str);
    if trimmed.eq_ignore_ascii_case("RANDOM") {
        config.hwid = KmsUuid::random().as_bytes()[..8].to_vec();
    } else {
        let bytes = decode_hex(trimmed)
            .ok_or_else(|| "HWID must be 16 hex characters".to_string())?;
        if bytes.len() != 8 {
            return Err("HWID must be 16 hex characters".into());
        }
        config.hwid = bytes;
    }

    logger::init(&config.log_level);
    let server = KmsServer::new(config);
    server.listen_and_serve().await?;
    Ok(())
}

async fn run_client_cmd(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = ClientConfig::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let next = || -> Result<&str, String> {
            args.get(i + 1)
                .map(|s| s.as_str())
                .ok_or_else(|| format!("missing value for {}", a))
        };
        match a {
            "-ip" => {
                config.ip = next()?.to_string();
                i += 2;
            }
            "-port" => {
                config.port = next()?.parse()?;
                i += 2;
            }
            "-mode" => {
                config.mode = next()?.to_string();
                i += 2;
            }
            "-cmid" => {
                config.cmid = next()?.to_string();
                i += 2;
            }
            "-name" => {
                config.machine = next()?.to_string();
                i += 2;
            }
            "-h" | "--help" => {
                println!("client options: -ip -port -mode -cmid -name");
                return Ok(());
            }
            _ => return Err(format!("unknown flag: {}", a).into()),
        }
    }
    if config.mode == "list" {
        println!("Available product modes:");
        for name in product_names() {
            println!("  {}", name);
        }
        return Ok(());
    }
    if lookup_product(&config.mode).is_none() {
        return Err(format!("unknown product mode: {}", config.mode).into());
    }
    logger::init("INFO");
    run_client(&config).await?;
    Ok(())
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
