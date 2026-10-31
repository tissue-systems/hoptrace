//! An mtr-style report.
//!
//! ```text
//! cargo run --example report -- [-4|-6] [-c CYCLES] HOST
//! ```

use std::net::{IpAddr, ToSocketAddrs};
use std::process::exit;
use std::time::Duration;

use hoptrace::Tracer;

fn main() {
    let mut family = None;
    let mut cycles = 10;
    let mut host = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-4" => family = Some(4),
            "-6" => family = Some(6),
            "-c" => {
                cycles = args
                    .next()
                    .and_then(|c| c.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            _ if host.is_none() && !arg.starts_with('-') => host = Some(arg),
            _ => usage(),
        }
    }
    let host = host.unwrap_or_else(|| usage());

    let to = match (host.as_str(), 0).to_socket_addrs() {
        Ok(addrs) => addrs.map(|a| a.ip()).find(|ip| match family {
            Some(4) => ip.is_ipv4(),
            Some(6) => ip.is_ipv6(),
            _ => true,
        }),
        Err(e) => {
            eprintln!("{host}: {e}");
            exit(1);
        }
    };
    let Some(to) = to else {
        eprintln!("{host} has no address in that family");
        exit(1);
    };

    let trace = match Tracer::new().cycles(cycles).trace(to) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    };

    println!("HOST: {host} ({to})");
    println!(
        "{:<44} {:>6} {:>4} {:>7} {:>7} {:>7}",
        "", "Loss%", "Snt", "Avg", "Best", "Wrst"
    );
    for hop in &trace.hops {
        let name = hop
            .addr
            .as_ref()
            .map_or("???".to_string(), IpAddr::to_string);
        println!(
            "{:>3}.|-- {:<36} {:>5.1}% {:>4} {:>7} {:>7} {:>7}",
            hop.ttl,
            name,
            hop.loss(),
            hop.sent,
            ms(hop.avg),
            ms(hop.best),
            ms(hop.worst),
        );
    }
    if !trace.reached {
        println!("{host} did not answer");
    }
}

fn ms(d: Option<Duration>) -> String {
    d.map_or(String::new(), |d| {
        format!("{:.1}", d.as_secs_f64() * 1000.0)
    })
}

fn usage() -> ! {
    eprintln!("usage: report [-4|-6] [-c CYCLES] HOST");
    exit(2);
}
