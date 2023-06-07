use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs, UdpSocket};

use clap::{command, Args, Parser, Subcommand};
use color_eyre::{eyre::Context, owo_colors::OwoColorize};
use dns::{build_query, QueryType, Record, Response};
use rand::{random, seq::SliceRandom, thread_rng};

mod dns;

static ROOT_SERVERS: [(Ipv4Addr, Ipv6Addr); 13] = [
    (
        Ipv4Addr::new(198, 41, 0, 4),
        Ipv6Addr::new(0x2001, 0x0503, 0xba3e, 0x0, 0x0, 0x0, 0x0002, 0x0030),
    ),
    (
        Ipv4Addr::new(199, 9, 14, 201),
        Ipv6Addr::new(0x2001, 0x500, 0x200, 0x0, 0x0, 0x0, 0x0, 0xb),
    ),
    (
        Ipv4Addr::new(192, 33, 4, 12),
        Ipv6Addr::new(0x2001, 0x500, 0x2, 0x0, 0x0, 0x0, 0x0, 0xc),
    ),
    (
        Ipv4Addr::new(199, 7, 91, 13),
        Ipv6Addr::new(0x2001, 0x500, 0x2d, 0x0, 0x0, 0x0, 0x0, 0xd),
    ),
    (
        Ipv4Addr::new(192, 203, 230, 10),
        Ipv6Addr::new(0x2001, 0x500, 0xa8, 0x0, 0x0, 0x0, 0x0, 0xe),
    ),
    (
        Ipv4Addr::new(192, 5, 5, 241),
        Ipv6Addr::new(0x2001, 0x500, 0x2f, 0x0, 0x0, 0x0, 0x0, 0xf),
    ),
    (
        Ipv4Addr::new(192, 112, 36, 4),
        Ipv6Addr::new(0x2001, 0x500, 0x12, 0x0, 0x0, 0x0, 0x0, 0xd0d),
    ),
    (
        Ipv4Addr::new(198, 97, 190, 53),
        Ipv6Addr::new(0x2001, 0x500, 0x1, 0x0, 0x0, 0x0, 0x0, 0x53),
    ),
    (
        Ipv4Addr::new(192, 36, 148, 17),
        Ipv6Addr::new(0x2001, 0x7fe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x53),
    ),
    (
        Ipv4Addr::new(192, 58, 128, 30),
        Ipv6Addr::new(0x2001, 0x503, 0xc27, 0x0, 0x0, 0x0, 0x2, 0x30),
    ),
    (
        Ipv4Addr::new(193, 0, 14, 129),
        Ipv6Addr::new(0x2001, 0x7fd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1),
    ),
    (
        Ipv4Addr::new(199, 7, 83, 42),
        Ipv6Addr::new(0x2001, 0x500, 0x9f, 0x0, 0x0, 0x0, 0x0, 0x42),
    ),
    (
        Ipv4Addr::new(202, 12, 27, 33),
        Ipv6Addr::new(0x2001, 0xdc3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x35),
    ),
];

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct App {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a query to a server
    Query(QueryArgs),

    /// Recursively resolve a query
    Resolve(ResolveArgs),
}

#[derive(Args)]
struct QueryArgs {
    /// Domain name to look up records for
    domain_name: String,

    /// Dns server to query
    #[arg(short, long)]
    dns_server_address: Option<Ipv4Addr>,

    /// Query type to perform
    #[arg(value_enum, short, long)]
    record_type: dns::QueryType,
}

impl QueryArgs {
    fn exec(&self) -> color_eyre::Result<()> {
        let dns_server_addr = self
            .dns_server_address
            .unwrap_or_else(|| ROOT_SERVERS.choose(&mut thread_rng()).unwrap().0);
        let response = query((dns_server_addr, 53), &self.domain_name, self.record_type)
            .context("Failed to retrieve response")?;

        fn fetch_data(record: &dns::Record) -> (&dns::Record, &'static str, String) {
            // let fetch_data = |record: &dns::Record| {
            let data = record.data();
            (record, record.ty.name(), data)
        }
        let print_output = |(record, response_type, data): (&dns::Record, &'static str, String),
                            type_width: usize,
                            data_width: usize| {
            println!(
                "{}: {:>type_width$}|{:<data_width$} ({})",
                record.name.purple(),
                response_type.yellow(),
                data.red(),
                record.ttl.white().bold(),
                type_width = type_width,
                data_width = data_width,
            );
        };
        // Answers
        if response.answers().count() > 0 {
            println!("Answers:");
            let longest_data = response
                .answers()
                .map(fetch_data)
                .map(|x| x.2.len())
                .max()
                .unwrap_or_default();
            let longest_type = response
                .answers()
                .map(fetch_data)
                .map(|x| x.1.len())
                .max()
                .unwrap_or_default();
            response
                .answers()
                .map(fetch_data)
                .for_each(|x| print_output(x, longest_type, longest_data));
        }

        // Authorities
        if response.authorities().count() > 0 {
            println!("Authorities:");
            let longest_data = response
                .authorities()
                .map(fetch_data)
                .map(|x| x.2.len())
                .max()
                .unwrap_or_default();
            let longest_type = response
                .authorities()
                .map(fetch_data)
                .map(|x| x.1.len())
                .max()
                .unwrap_or_default();
            response
                .authorities()
                .map(fetch_data)
                .for_each(|x| print_output(x, longest_type, longest_data));
        }

        // Additionals
        if response.additionals().count() > 0 {
            println!("Additionals:");
            let longest_data = response
                .additionals()
                .map(fetch_data)
                .map(|x| x.2.len())
                .max()
                .unwrap_or_default();
            let longest_type = response
                .additionals()
                .map(fetch_data)
                .map(|x| x.1.len())
                .max()
                .unwrap_or_default();
            response
                .additionals()
                .map(fetch_data)
                .for_each(|x| print_output(x, longest_type, longest_data));
        }

        Ok(())
    }
}

#[derive(Args)]
struct ResolveArgs {
    /// the hostname to resolve
    domain_name: String,

    /// the record type to query
    #[arg(short)]
    record_type: QueryType,
}

fn resolve(domain_name: &str, record_type: dns::QueryType) -> color_eyre::Result<Record> {
    let mut rng = thread_rng();
    let mut nameserver = ROOT_SERVERS.choose(&mut rng).unwrap().0;
    let mut query_result: Option<dns::Record> = None;
    loop {
        println!("Querying {nameserver} for {}", domain_name);
        let response = query((nameserver, 53), domain_name, record_type)?;
        if let Some(result) = response.answers().find_map(|record| {
            if <&dns::QueryResponse as Into<dns::QueryType>>::into(&record.ty) == record_type {
                return Some(record.clone());
            }
            None
        }) {
            query_result = Some(result);
            break;
        } else if let Some(ns_ip) = response.additionals().find_map(|record| match record.ty {
            dns::QueryResponse::A(ip_addr) => Some(ip_addr),
            _ => None,
        }) {
            nameserver = ns_ip;
        } else if let Some(ns_domain) = response.authorities().find_map(|record| match &record.ty {
            dns::QueryResponse::Ns(ref name) => Some(name.as_str()),
            _ => None,
        }) {
            let record = resolve(ns_domain, QueryType::A)?;
            nameserver = match record.ty {
                dns::QueryResponse::A(x) => x,
                _ => {
                    let ty: QueryType = (&record.ty).into();
                    color_eyre::eyre::bail!("Expected {:?} record, got {:?}", QueryType::A, ty);
                }
            };
        } else {
            break;
        };
    }
    let Some(record) = query_result else {
            color_eyre::eyre::bail!("Unable to resolve query!")
        };
    Ok(record)
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let app = App::parse();
    match app.command {
        Commands::Query(q) => return q.exec(),
        Commands::Resolve(r) => {
            let record = resolve(&r.domain_name, r.record_type)?;
            println!(
                "{}: {}|{} ({})",
                record.name.purple(),
                record.ty.name(),
                record.data().red(),
                record.ttl.white()
            );
        }
    }
    Ok(())
}

fn query<A>(
    address: A,
    domain_name: &str,
    record_type: dns::QueryType,
) -> color_eyre::Result<dns::Response>
where
    A: ToSocketAddrs,
{
    let query = build_query(domain_name, record_type, random());
    let connection = UdpSocket::bind("0.0.0.0:0").context("Unable to bind to socket")?;

    connection
        .send_to(&query, address)
        .context("Failed to send query to server")?;

    let mut buf = [0u8; 1024];
    let (size, _) = connection
        .recv_from(&mut buf)
        .context("No response received")?;
    Response::parse(&buf[..size]).context("Failed to parse response")
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        App::command().debug_assert()
    }
}
