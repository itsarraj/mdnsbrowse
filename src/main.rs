use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use hickory_proto::rr::RecordType;
use mdnsbrowse::mdns::{browse_raw, build_query};
use mdnsbrowse::records::aggregate;

#[derive(Parser)]
#[command(
    name = "mdnsbrowse",
    about = "Browses mDNS/Bonjour services on the local network — a dns-sd/avahi-browse alternative"
)]
struct Cli {
    /// Service type to browse, e.g. `_http._tcp.local.` or a specific hostname like `myhost.local.`.
    /// Defaults to the mDNS service-type enumeration meta-query.
    #[arg(default_value = "_services._dns-sd._udp.local.")]
    service: String,
    #[arg(long, default_value_t = 3)]
    timeout_secs: u64,
    /// Local interface IP to send/join the multicast query on (default: let the OS pick).
    /// Useful on a multi-homed host where the default choice isn't the LAN-facing NIC.
    #[arg(long)]
    iface: Option<Ipv4Addr>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let record_type = if cli.service.ends_with(".local.") && !cli.service.starts_with('_') {
        RecordType::A
    } else {
        RecordType::PTR
    };

    let query_bytes = match build_query(&cli.service, record_type) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("mdnsbrowse: building query: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "mdnsbrowse: querying '{}' ({record_type:?}), listening {}s...",
        cli.service, cli.timeout_secs
    );

    let records = match browse_raw(
        &query_bytes,
        Duration::from_secs(cli.timeout_secs),
        cli.iface,
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("mdnsbrowse: {e}");
            return ExitCode::FAILURE;
        }
    };

    if records.is_empty() {
        println!("mdnsbrowse: no responses received");
        return ExitCode::SUCCESS;
    }

    if record_type == RecordType::PTR && cli.service.starts_with('_') {
        let instances = aggregate(&records);
        if instances.is_empty() {
            println!("mdnsbrowse: no service instances found");
        }
        for inst in &instances {
            let host = inst.host.as_deref().unwrap_or("?");
            let port = inst
                .port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".to_string());
            println!("{}", inst.name);
            println!("  host: {host}:{port}");
            if !inst.addrs.is_empty() {
                let addrs: Vec<String> = inst.addrs.iter().map(|a| a.to_string()).collect();
                println!("  addrs: {}", addrs.join(", "));
            }
            if !inst.txt.is_empty() {
                println!("  txt: {}", inst.txt.join(", "));
            }
        }
    } else {
        for record in &records {
            println!("{record:?}");
        }
    }

    ExitCode::SUCCESS
}
