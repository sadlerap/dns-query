use std::net::Ipv4Addr;

use clap::{command, Args, Parser, Subcommand};
use color_eyre::{eyre::Context, owo_colors::OwoColorize};
use dns_query::{query, resolve, QueryType, ROOT_SERVERS};
use rand::{seq::SliceRandom, thread_rng};

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
    record_type: dns_query::QueryType,
}

impl QueryArgs {
    fn exec(&self) -> color_eyre::Result<()> {
        let dns_server_addr = self
            .dns_server_address
            .unwrap_or_else(|| ROOT_SERVERS.choose(&mut thread_rng()).unwrap().0);
        let response = query((dns_server_addr, 53), &self.domain_name, self.record_type)
            .context("Failed to retrieve response")?;

        fn fetch_data(record: &dns_query::Record) -> (&dns_query::Record, &'static str, String) {
            // let fetch_data = |record: &dns::Record| {
            let data = record.data();
            (record, record.ty.name(), data)
        }
        let print_output =
            |(record, response_type, data): (&dns_query::Record, &'static str, String),
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

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        App::command().debug_assert()
    }
}
