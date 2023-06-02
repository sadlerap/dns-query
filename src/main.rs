use std::net::UdpSocket;

use clap::{command, Parser};
use color_eyre::eyre::Context;
use dns::{build_query, Response};

mod dns;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct App {
    // domain name to look up records for
    domain_name: String,

    // query type to perform
    #[arg(value_enum, short, long)]
    query_type: dns::QueryType,
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let app = App::parse();

    let query = build_query(&app.domain_name, app.query_type, 1);
    let connection = UdpSocket::bind("0.0.0.0:12345")?;
    let remote_address = ("192.168.2.102", 53);
    connection
        .send_to(&query, remote_address)
        .context("Failed to connect to DNS server")?;
    let mut response = [0u8; 1024];
    let (size, _) = connection
        .recv_from(&mut response)
        .context("Did not receive a response!")?;

    let buf = &response[..size];
    let response = Response::parse(buf)?;
    println!("{:?}", response);

    Ok(())
}
