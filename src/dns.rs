use std::io::Write;

use clap::ValueEnum;

/// A query type, as defined by [RFC 1035 section
/// 3.2.2](https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2)
#[derive(Default, Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "UPPER")]
#[repr(u16)]
pub enum QueryType {
    /// host address record
    #[default]
    A = 1,

    /// authoratative name server record
    NS = 2,

    /// mail destination record (obsolete, use MX)
    MD = 3,

    /// mail forwarder record (obsolete, use MX)
    MF = 4,

    /// canonical name for an alias
    CNAME = 5,

    /// start of a zone of authority
    SOA = 6,

    /// mailbox domain name (EXPERIMENTAL)
    MB = 7,

    /// mail group member (EXPERIMENTAL)
    MG = 8,

    /// mail rename domain name (EXPERIMENTAL)
    MR = 9,

    /// null RR (EXPERIMENTAL)
    NULL = 10,

    /// well-known service description
    WKS = 11,

    /// domain name pointer
    PTR = 12,

    /// host information
    HINFO = 13,

    /// mailbox or mail list information
    MINFO = 14,

    /// mail exchange
    MX = 15,

    /// text strings
    TXT = 16,
}

/// A class type, as defined by [RFC 1035 section
/// 3.2.4](https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4)
#[derive(Default, Debug, Clone, Copy)]
#[repr(u16)]
#[allow(unused)]
pub enum ClassType {
    #[default]
    IN = 1u16,
    CS = 2u16,
    CH = 3u16,
    HS = 4u16,
}

pub trait AsBytes {
    fn as_bytes<T>(&self, dest: &mut T)
    where
        T: std::io::Write;
}

/// A DNS Header.  Can be converted to wire format using the `AsBytes` trait impl.
#[derive(Default, Debug, Clone)]
pub struct Header {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl AsBytes for Header {
    fn as_bytes<T: std::io::Write>(&self, dest: &mut T) {
        for x in [
            self.id,
            self.flags,
            self.num_questions,
            self.num_answers,
            self.num_authorities,
            self.num_additionals,
        ] {
            let _ = dest.write_all(&x.to_be_bytes());
        }
    }
}

/// A DNS Question.  Can be converted to wire format using the `AsBytes` trait impl.
#[derive(Default, Debug, Clone)]
pub struct Question {
    name: Vec<u8>,
    ty: QueryType,
    class: ClassType,
}

impl Question {
    pub fn new(name: &str, ty: QueryType, class: ClassType) -> Self {
        Self {
            name: encode_dns_name(name),
            ty,
            class,
        }
    }
}

fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut output = vec![];
    for substr in name.split('.') {
        output.push(substr.len() as u8);
        let _ = output.write_all(substr.as_bytes());
    }
    output.push(0u8);
    output
}

impl AsBytes for Question {
    fn as_bytes<T>(&self, dest: &mut T)
    where
        T: std::io::Write,
    {
        let _ = dest.write_all(&self.name);
        let _ = dest.write_all(&(self.ty as u16).to_be_bytes());
        let _ = dest.write_all(&(self.class as u16).to_be_bytes());
    }
}

pub fn build_query(domain_name: &str, record_type: QueryType, id: u16) -> Vec<u8> {
    let mut output = vec![];
    let header = Header {
        id,
        flags: 0x0100,
        num_questions: 1,
        ..Default::default()
    };
    let question = Question::new(domain_name, record_type, ClassType::IN);
    header.as_bytes(&mut output);
    question.as_bytes(&mut output);
    output
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pack_header() {
        let header = Header {
            id: 0x1314,
            flags: 0,
            num_questions: 1,
            num_additionals: 0,
            num_authorities: 0,
            num_answers: 0,
        };
        let mut output = vec![];
        header.as_bytes(&mut output);

        assert_eq!(output, b"\x13\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00");
    }

    #[test]
    fn test_pack_question() {
        let question = Question::new("google.com", QueryType::A, ClassType::IN);
        let mut output = vec![];
        question.as_bytes(&mut output);

        assert_eq!(output, b"\x06google\x03com\x00\x00\x01\x00\x01");
    }
    #[test]
    fn test_encode_dns_name() {
        let output = encode_dns_name("google.com");
        assert_eq!(output, b"\x06google\x03com\x00");
    }

    #[test]
    fn test_build_query() {
        let query = build_query("google.com", QueryType::A, 1);

        assert_eq!(query, b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01")
    }
}
