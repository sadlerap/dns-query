use clap::ValueEnum;
use thiserror::Error;

/// A query type, as defined by [RFC 1035 section
/// 3.2.2](https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2)
#[derive(Default, Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
#[clap(rename_all = "UPPER")]
#[repr(u16)]
pub enum QueryType {
    /// host address record
    #[default]
    A = 1,

    /// authoratative name server record
    Ns = 2,

    /// mail destination record (obsolete, use MX)
    Md = 3,

    /// mail forwarder record (obsolete, use MX)
    Mf = 4,

    /// canonical name for an alias
    Cname = 5,

    /// start of a zone of authority
    Soa = 6,

    /// mailbox domain name (EXPERIMENTAL)
    Mb = 7,

    /// mail group member (EXPERIMENTAL)
    Mg = 8,

    /// mail rename domain name (EXPERIMENTAL)
    Mr = 9,

    /// null RR (EXPERIMENTAL)
    Null = 10,

    /// well-known service description
    Wks = 11,

    /// domain name pointer
    Ptr = 12,

    /// host information
    Hinfo = 13,

    /// mailbox or mail list information
    Minfo = 14,

    /// mail exchange
    Mx = 15,

    /// text strings
    Txt = 16,
}

#[derive(Error, Debug)]
pub enum TryFromQueryTypeError {
    #[error("Received {0}, which is an unknown query type")]
    Unknown(u16),
}

impl TryFrom<u16> for QueryType {
    type Error = TryFromQueryTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let x = match value {
            1 => Self::A,
            2 => Self::Ns,
            3 => Self::Md,
            4 => Self::Mf,
            5 => Self::Cname,
            6 => Self::Soa,
            7 => Self::Mb,
            8 => Self::Mg,
            9 => Self::Mr,
            10 => Self::Null,
            11 => Self::Wks,
            12 => Self::Ptr,
            13 => Self::Hinfo,
            14 => Self::Minfo,
            15 => Self::Mx,
            16 => Self::Txt,
            _ => return Err(TryFromQueryTypeError::Unknown(value)),
        };
        Ok(x)
    }
}

/// A class type, as defined by [RFC 1035 section
/// 3.2.4](https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4)
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
#[allow(unused)]
pub enum ClassType {
    #[default]
    IN = 1u16,
    CS = 2u16,
    CH = 3u16,
    HS = 4u16,
}

#[derive(Error, Debug)]
pub enum TryFromClassTypeError {
    #[error("Received {0}, which is an unknown class type")]
    Unknown(u16),
}

impl TryFrom<u16> for ClassType {
    type Error = TryFromClassTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            _ => return Err(TryFromClassTypeError::Unknown(value)),
        })
    }
}
