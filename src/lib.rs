mod dns;
use color_eyre::eyre::Context;
pub use dns::*;
use rand::{random, seq::SliceRandom, thread_rng};
use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs, UdpSocket};

pub static ROOT_SERVERS: [(Ipv4Addr, Ipv6Addr); 13] = [
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

/// resolve a dns query
pub fn resolve(domain_name: &str, record_type: dns::QueryType) -> color_eyre::Result<Record> {
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

pub fn query<A>(
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
