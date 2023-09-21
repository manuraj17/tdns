use rand::Rng;
use std::net::{Ipv4Addr, UdpSocket};

// The header contains the following fields:
//
//                               1  1  1  1  1  1
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       | -> id
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   | -> flags
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    | -> num_questions
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    | -> num_answers
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    | -> num_authorities
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    | -> num_additionals
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[repr(C)]
struct DNSHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

//                               1  1  1  1  1  1
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                     QNAME                     / -> name
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QTYPE                     | -> _type
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QCLASS                    | -> _class
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[repr(C)]
struct DNSQuestion {
    name: Vec<u8>,
    _type: u16,
    _class: u16,
}

impl DNSHeader {
    pub fn decode() {}

    pub fn encode(&self) -> Vec<u8> {
        [
            self.id.to_be_bytes(),
            self.flags.to_be_bytes(),
            self.num_questions.to_be_bytes(),
            self.num_answers.to_be_bytes(),
            self.num_authorities.to_be_bytes(),
            self.num_additionals.to_be_bytes(),
        ]
            .concat()
    }
}

impl DNSQuestion {
    pub fn encode(&self) -> Vec<u8> {
        let mut result = self.name.clone();
        result.append(&mut self._type.to_be_bytes().to_vec());
        result.append(&mut self._class.to_be_bytes().to_vec());

        result
    }
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut c = Vec::new();

    for w in name.split(".") {
        let len_bytes = w.len().to_be_bytes().to_vec();
        c.extend(len_bytes.last());
        // let s_bytes : Vec<u8>= w.as_bytes().try_into().unwrap();
        let s = w.as_bytes().try_into();

        let s_bytes : Vec<u8> = match s {
           Ok(value)  => value,
            Err(error) => panic!("Size to bytes failed: {:?}", error)
        };
        c.extend(s_bytes);
    }

    c.push(0u8);

    c
}

const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

fn build_query(name: &str, record_type: u16) -> Vec<u8> {
    let encoded_name = encode_name(name);
    let id = rand::thread_rng().gen_range(0..65535);
    let recursion_desired = 128;

    let header = DNSHeader {
        id,
        num_questions: 1,
        flags: recursion_desired,
        num_answers: 0,
        num_authorities: 0,
        num_additionals: 0,
    };

    let question = DNSQuestion {
        name: encoded_name,
        _type: record_type,
        _class: CLASS_IN,
    };

    [header.encode(), question.encode()].concat()
}


fn main()  {
    let name = "www.google.com";
    let query = build_query(name, CLASS_IN);

    // let mut socket = UdpSocket::bind("0.0.0.0:8000").expect("Couldn't bind address");
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        // .expect("Couldn't bind address");
    let result = socket.send_to(&query, "8.8.8.8:53").expect("Couldn't send data");


    println!("{:?}", result);

    let mut buf = [0; 1024];
    println!("Waiting for data");
    // let (number_of_bytes, src) = socket.recv_from(&mut buf).expect("Didn't receive data");
    let (number_of_bytes, src) = socket.recv_from(&mut buf).unwrap();
    let filled_buf = &mut buf[..number_of_bytes];
    println!("Converting data");
    let ss = String::from_utf8(filled_buf.to_vec());
    let o = match ss {
        Ok(s) => s,
        Err(error) => panic!("Result error: {:?}", error)
    };

    println!("{:?}", o);
}

#[cfg(test)]
mod tests {
    // use crate::encode_name;

    use crate::{build_query, encode_name, TYPE_A};

    #[test]
    fn test_encode_name() {
        let name = "google.com";
        let result = encode_name(name);
        // [6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0]
        // [6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0]
        println!("Result: {:?}", result);
    }

    #[test]
    fn test_build_query() {
        // let bytes : Vec<u8> = "привет".to_string().as_bytes().to_vec();
        let bytes = build_query("www.example.com", TYPE_A);

        let mut c = Vec::new();
        for b in bytes {
            c.push(format!("{:b}", b))
        }

    }
}