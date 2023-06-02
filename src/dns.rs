use std::io::Write;

mod types;
pub use types::*;
use winnow::{
    binary::{be_u16, be_u32, u8},
    combinator::repeat,
    multi::length_data,
    IResult, Parser, token::take,
};

pub trait AsBytes {
    fn as_bytes<T>(&self, dest: &mut T)
    where
        T: std::io::Write;
}

/// A DNS Header.  Can be converted to wire format using the `AsBytes` trait impl.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Header {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl Header {
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        (be_u16, be_u16, be_u16, be_u16, be_u16, be_u16)
            .map(|x| Header {
                id: x.0,
                flags: x.1,
                num_questions: x.2,
                num_answers: x.3,
                num_authorities: x.4,
                num_additionals: x.5,
            })
            .parse_next(input)
    }
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
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Question {
    name: String,
    ty: QueryType,
    class: ClassType,
}

impl Question {
    pub fn new(name: &str, ty: QueryType, class: ClassType) -> Self {
        Self {
            name: name.into(),
            ty,
            class,
        }
    }

    fn parse<'a, 'b>(input: &'a [u8], full_input: &'b [u8]) -> IResult<&'a [u8], Self>
    where
        'b: 'a,
    {
        (
            |x: &'a [u8]| -> IResult<&[u8], String> { decode_dns_name(x, full_input) },
            be_u16.try_map(QueryType::try_from),
            be_u16.try_map(ClassType::try_from),
        )
            .map(|x| Question {
                name: x.0,
                ty: x.1,
                class: x.2,
            })
            .parse_next(input)
    }
}

#[allow(clippy::let_and_return)]
fn decode_dns_name<'a, 'b>(bytes: &'a [u8], full_input: &'b [u8]) -> IResult<&'a [u8], String>
where
    'b: 'a,
{
    let (remaining, head) = u8.parse_next(bytes)?;
    if head & 0b1100_0000 == 0b11000000 {
        // pointer
        let (remaining, next) = u8.parse_next(remaining)?;
        let index = ((((head & 0b0011_1111) as u16) << 8) | (next as u16)) as usize;
        let (_, output) = decode_dns_name(&full_input[index..], full_input)?;
        Ok((remaining, output))
    } else if head == 0 {
        // end of input
        Ok((remaining, "".into()))
    } else {
        // sequence of labels
        let (remaining, x) = take(head as usize)
            .map(|x| String::from_utf8_lossy(x))
            .parse_next(remaining)?;
        let (remaining, other) = decode_dns_name(remaining, full_input)?;
        if other.len() != 0 {
            let output = format!("{x}.{other}");
            Ok((remaining, output))
        } else {
            Ok((remaining, x.into()))
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
        let _ = dest.write_all(&encode_dns_name(&self.name));
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

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Record {
    name: String,
    ty: QueryType,
    class: ClassType,
    ttl: u32,
    data: Vec<u8>,
}

impl Record {
    fn parse<'a, 'b>(input: &'a [u8], full_input: &'b [u8]) -> IResult<&'a [u8], Self>
    where
        'b: 'a,
    {
        (
            |x| -> IResult<&'a [u8], String> { return decode_dns_name(x, full_input) },
            be_u16.try_map(|x| QueryType::try_from(x)),
            be_u16.try_map(|x| ClassType::try_from(x)),
            be_u32,
            length_data(be_u16),
        )
            .map(|x| Self {
                name: x.0,
                ty: x.1,
                class: x.2,
                ttl: x.3,
                data: x.4.to_owned(),
            })
            .parse_next(input)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
}

impl Response {
    pub fn parse(input: &[u8]) -> color_eyre::Result<Self> {
        let (remaining, header) = Header::parse(input).map_err(|e| {
            color_eyre::eyre::eyre!("Failed to parse header").wrap_err(format!("{:?}", e))
        })?;

        let (questions, answers, authorities, additionals) = (
            repeat(
                header.num_questions as usize,
                |x| -> IResult<&[u8], Question> { Question::parse(x, input) },
            ),
            repeat(header.num_answers as usize, |x| -> IResult<&[u8], Record> {
                Record::parse(x, input)
            }),
            repeat(
                header.num_authorities as usize,
                |x| -> IResult<&[u8], Record> { Record::parse(x, input) },
            ),
            repeat(
                header.num_additionals as usize,
                |x| -> IResult<&[u8], Record> { Record::parse(x, input) },
            ),
        )
            .parse(remaining)
            .map_err(|e| {
                color_eyre::eyre::eyre!("Failed to parse body").wrap_err(format!("{:?}", e))
            })?;

        Ok(Response {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
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

    #[test]
    fn test_parse_header() {
        let header = Header {
            id: 0xa,
            flags: 0xb,
            num_questions: 0xc,
            num_additionals: 0xd,
            num_authorities: 0xe,
            num_answers: 0xf,
        };
        let mut output = vec![];
        header.as_bytes(&mut output);

        assert_eq!(Header::parse(&output).unwrap().1, header);
    }

    #[test]
    fn test_decode_name() {
        let input = b"\x02pi\x00";
        let result = decode_dns_name(input, input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().1, "pi");
    }

    #[test]
    fn test_parse_question() {
        let question = Question::new("pi.hole", QueryType::A, ClassType::IN);
        let input = b"\x02\x70\x69\x04\x68\x6f\x6c\x65\x00\x00\x01\x00\x01";

        let new_question = Question::parse(input, input);
        assert!(new_question.is_ok());
        assert_eq!(new_question.unwrap().1, question)
    }

    #[test]
    fn test_parse_response() {
        let response = b"\x00\x01\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x02\x70\x69\x04\x68\x6f\x6c\x65\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\xc0\xa8\x02\x66";
        let response = Response::parse(response);
        assert!(response.is_ok());

        let response = response.unwrap();
        assert_eq!(
            response.header,
            Header {
                id: 0x01,
                flags: 0x8580,
                num_questions: 1,
                num_answers: 1,
                num_authorities: 0,
                num_additionals: 0,
            }
        );

        assert_eq!(
            response.questions,
            [Question::new("pi.hole", QueryType::A, ClassType::IN)]
        );

        assert_eq!(
            response.answers,
            [Record {
                name: "pi.hole".into(),
                ty: QueryType::A,
                class: ClassType::IN,
                ttl: 0,
                data: vec![192, 168, 2, 102]
            }]
        )
    }
}
