// https://datatracker.ietf.org/doc/html/rfc1035
use rand::Rng;
use std::{
    net::{Ipv4Addr, UdpSocket},
    usize,
};
use std::fs::read;
use std::net::{IpAddr, Ipv6Addr};

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_TXT: u16 = 16;
const CLASS_IN: u16 = 1;
const TYPE_AAAA: u16 = 28;

// Whenever an octet represents a numeric quantity, the left most bit in
// the diagram is the high order or most significant bit.  That is, the bit
// labeled 0 is the most significant bit.  For example, the following
// diagram represents the value 170 (decimal).
//
// 0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |1 0 1 0 1 0 1 0|
// +-+-+-+-+-+-+-+-+

// All communications inside of the domain protocol are carried in a single
// format called a message.  The top level format of message is divided
// into 5 sections (some of which are empty in certain cases) shown below:
//
// +---------------------+
// |        Header       |
// +---------------------+
// |       Question      | the question for the name server
// +---------------------+
// |        Answer       | RRs answering the question
// +---------------------+
// |      Authority      | RRs pointing toward an authority
// +---------------------+
// |      Additional     | RRs holding additional information
// +---------------------+

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
//
// A total of 12 bytes
// u16 -> 2 bytes
#[repr(C)]
#[derive(Debug)]
struct DNSHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl DNSHeader {
    pub fn decode(reader: &mut BuffReader) -> DNSHeader {
        DNSHeader {
            id: u16::from_be_bytes(reader.read(2).try_into().unwrap()),
            flags: u16::from_be_bytes(reader.read(2).try_into().unwrap()),
            num_questions: u16::from_be_bytes(reader.read(2).try_into().unwrap()),
            num_answers: u16::from_be_bytes(reader.read(2).try_into().unwrap()),
            num_authorities: u16::from_be_bytes(reader.read(2).try_into().unwrap()),
            num_additionals: u16::from_be_bytes(reader.read(2).try_into().unwrap()),
        }
    }

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
#[derive(Debug)]
struct DNSQuestion {
    name: Vec<u8>,
    _type: u16,
    _class: u16,
    name_s: String,
}

impl DNSQuestion {
    fn name_to_string(&self) -> String {
        String::from_utf8(self.name.clone()).unwrap()
    }
    fn decode(reader: &mut BuffReader) -> DNSQuestion {
        let name_s = decode_simple_question_name(reader);

        let _type = u16::from_be_bytes(reader.read(2).try_into().unwrap());
        let _class = u16::from_be_bytes(reader.read(2).try_into().unwrap());

        DNSQuestion {
            name: name_s.as_bytes().to_vec(),
            _type,
            _class,
            name_s,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut result = self.name.clone();
        result.append(&mut self._type.to_be_bytes().to_vec());
        result.append(&mut self._class.to_be_bytes().to_vec());

        result
    }
}

//  Resource Record
//
// The answer, authority, and additional sections all share the same
// format: a variable number of resource records, where the number of
// records is specified in the corresponding count field in the header.
// Each resource record has the following format:
// 1  1  1  1  1  1
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                                               /
// /                      NAME                     /
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     CLASS                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TTL                      |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   RDLENGTH                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
// /                     RDATA                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#[repr(C)]
#[derive(Debug)]
struct DNSRecord {
    name: String,
    _type: u16,
    _class: u16,
    ttl: u32,
    data: Vec<u8>,
    parsed_data: String,
}

impl DNSRecord {
    fn decode(reader: &mut BuffReader) -> DNSRecord {
        // println!("Parsing DNSRecord");
        // println!("{:?}", reader.peek(2));
        let name = decode_compressed_question_name(reader);
        // println!("Name: {name}");
        let _type = u16::from_be_bytes(reader.read(2).try_into().unwrap());
        let _class = u16::from_be_bytes(reader.read(2).try_into().unwrap());
        let ttl = u32::from_be_bytes(reader.read(4).try_into().unwrap());
        let data_len = u16::from_be_bytes(reader.read(2).try_into().unwrap());
        // println!("Data length: {:?}", data_len);
        // println!("TYPE: {:?}", _type);
        // println!("Data Length: {:?}", data_len);
        // TODO: Be careful here, the data_len is 2 bytes we are passing only 1
        // u16 -> usize
        let data: Vec<u8> = Vec::new();
        // let data : Vec<u8>;
        // let data: Vec<u8> = reader.read(data_len as usize);
        // let parsed_data = String::from("");

        let data =
            if _type == TYPE_NS {
                // println!("TYPE IS NS");
                decode_compressed_question_name(reader).as_bytes().to_vec()
            } else if _type == TYPE_A {
                let data = reader.read(data_len as usize);
                ip_to_string(data).as_bytes().to_vec()
            } else if _type == TYPE_AAAA {
                // println!("TYPE_AAAA: {:?}", data_len);
                let data = reader.read(data_len as usize);
                data
                // String::from_utf8(data.clone()).unwrap()
            } else {
                String::from("").as_bytes().to_vec()
            };
        let parsed_data = if _type == TYPE_A {
            String::from_utf8(data.clone()).unwrap()
        } else {
            String::from("")
        };

        // println!("Final parsed data: {:?}", parsed_data);

        DNSRecord {
            name,
            _type,
            _class,
            ttl,
            data,
            parsed_data,
        }
    }

    fn ip_to_string(&self) -> String {
        self
            .data
            .iter()
            .map(|i| format!("{:?}", i))
            .collect::<Vec<String>>()
            .join(".")
    }
}


#[repr(C)]
#[derive(Debug)]
struct DNSPacket {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSRecord>,
    authorities: Vec<DNSRecord>,
    additionals: Vec<DNSRecord>,
}

impl DNSPacket {
    fn decode(reader: &mut BuffReader) -> DNSPacket {
        let header = DNSHeader::decode(reader);
        let mut questions: Vec<DNSQuestion> = Vec::new();
        // println!("Number of questions: {:?}", header.num_questions);
        for _ in 0..header.num_questions {
            // println!("Parsing Question");
            let q = DNSQuestion::decode(reader);
            // println!("Question {:?}", q);
            questions.push(q);
        }

        // println!("Parsing Answers");
        // println!("Number of answers: {:?}", header.num_answers);
        let mut answers: Vec<DNSRecord> = Vec::new();
        for _ in 0..header.num_answers {
            let a = DNSRecord::decode(reader);
            answers.push(a);
        }

        // println!("Parsing Authorities");
        // println!("Number of authorities: {:?}", header.num_authorities);
        let mut authorities: Vec<DNSRecord> = Vec::new();
        for _ in 0..header.num_authorities {
            let a = DNSRecord::decode(reader);
            authorities.push(a);
        }
        // println!("Authorities: {:?}", authorities);

        // println!("Parsing Additionals: {:?}", header.num_additionals);
        let mut additionals: Vec<DNSRecord> = Vec::new();
        for _ in 0..header.num_additionals {
            let a = DNSRecord::decode(reader);
            // println!("{:?}", a);
            additionals.push(a);
        }

        DNSPacket {
            header,
            questions,
            answers,
            authorities,
            additionals,
        }
    }
}


struct BuffReader {
    buff: [u8; 1024],
    pos: usize,
    count: usize,
}

impl BuffReader {
    ///
    /// Arguments
    /// * `count` - The amount of bytes to read
    fn read(&mut self, count: usize) -> Vec<u8> {
        let end_pos = self.pos + count;

        let result = self.buff[self.pos..end_pos].to_owned();

        self.pos += count;
        self.count += count;

        result
    }

    fn peek(&self, count: usize) -> Vec<u8> {
        self.buff[self.pos..self.pos + count].to_vec()
    }

    fn seek(&mut self, pos: usize) -> () {
        self.pos = pos;
    }
}


fn ip_to_string(buff: Vec<u8>) -> String {
    buff
        .iter()
        .map(|i| format!("{:?}", i))
        .collect::<Vec<String>>()
        .join(".")
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut c = Vec::new();

    for w in name.split(".") {
        let len_bytes = w.len().to_be_bytes().to_vec();
        c.extend(len_bytes.last());
        let s_bytes: Vec<u8> = w.as_bytes().try_into().unwrap();
        c.extend(s_bytes);
    }

    c.push(0u8);

    c
}

fn build_query(name: &str, record_type: u16) -> Vec<u8> {
    let encoded_name = encode_name(name);
    let id = rand::thread_rng().gen_range(0..65535);
    // let recursion_desired = 128;
    let flags = 0;

    let header = DNSHeader {
        id,
        num_questions: 1,
        flags,
        num_answers: 0,
        num_authorities: 0,
        num_additionals: 0,
    };

    let question = DNSQuestion {
        name: encoded_name,
        _type: record_type,
        _class: CLASS_IN,
        name_s: String::from(name),
    };

    [header.encode(), question.encode()].concat()
}

fn send_query(ip_address: &str, domain_name: &str, record_type: u16) -> DNSPacket {
    let query = build_query(domain_name, record_type);
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    // .expect("Couldn't bind address");
    let _result = socket
        .send_to(&query, ip_address)
        .expect("Couldn't send data");


    let mut buf = [0; 1024];
    // let (number_of_bytes, src) = socket.recv_from(&mut buf).expect("Didn't receive data");
    let (_number_of_bytes, _src) = socket.recv_from(&mut buf).unwrap();
    // let filled_buf = &mut buf[..number_of_bytes];
    let mut reader = BuffReader { buff: buf, pos: 0usize, count: 1usize };

    DNSPacket::decode(&mut reader)
}

/// Decode without compression
fn decode_simple_question_name(reader: &mut BuffReader) -> String {
    let mut parts: Vec<Vec<u8>> = Vec::new();

    loop {
        let d = reader.read(1);
        let mut t: Vec<u8> = Vec::new();

        if d[0] != 0 {
            let v = reader.read(d[0] as usize).to_owned();
            t.append(&mut v.to_vec());
            parts.push(t);
        } else {
            break;
        }
    }

    let mut s: Vec<String> = Vec::new();

    for p in parts {
        let t = String::from_utf8(p).unwrap();
        s.push(t);
    }

    s.join(".")
}

/// Decode with compression
fn decode_compressed_question_name(reader: &mut BuffReader) -> String {
    // println!("Decode compressed question name");
    let mut parts: Vec<String> = Vec::new();

    loop {
        let length = reader.read(1)[0];
        if length == 0 {
            break;
        }

        // Magic Octet = 11000000 => 192
        if ((length) & 0b11000000) != 0 {
            let r = decode_compressed_name(length, reader);
            // println!("Decompressed : {:?}", r);
            parts.push(r);
            break;
        } else {
            let t = reader.read(length as usize);
            parts.push(String::from_utf8(t).unwrap());
        }
    }
    // Magic Octet = 11000000 => 192
    // while let Some(length) = Some(reader.read(1)[0]) {
    //     println!("Length: {length}");
    //     if length != 0 {
    //         if ((length) & 0b11000000) != 0 {
    //             let r = decode_compressed_name(length, reader);
    //             println!("Decompressed : {:?}", r);
    //             parts.push(r);
    //             break;
    //         } else {
    //             let t = reader.read(length as usize);
    //             println!("t: {:?}", t);
    //             // parts.push(String::from_utf8(t).unwrap());
    //             // if t[0] == 0 {
    //             //     println!("Adding 0 and breaking");
    //             //     // parts.push(String::from("0"));
    //             //     break;
    //             // } else {
    //             //     println!("T: {:?}", t);
    //             //     println!("String: {:?}", String::from_utf8(t.clone()).unwrap());
    //             //     parts.push(String::from_utf8(t).unwrap());
    //             // }
    //         }
    //     } else {
    //         break;
    //     }
    // }

    // reader.read(1);

    // println!("Returning parts: {:?}", parts);
    parts.join(".")
}

// The pointer takes the form of a two octet sequence:
//
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// | 1  1|                OFFSET                   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// Pointers
// - The first two bits are ones
// Labels
// - label must begin with two zero bits because
// - labels are restricted to 63 octets or less
//
// For example, a datagram might need to use the domain names F.ISI.ARPA,
// FOO.F.ISI.ARPA, ARPA, and the root.  Ignoring the other fields of the
// message, these domain names might be represented as:
//
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     20 |           1           |           F           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     22 |           3           |           I           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     24 |           S           |           I           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     26 |           4           |           A           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     28 |           R           |           P           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     30 |           A           |           0           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     40 |           3           |           F           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     42 |           O           |           O           |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     44 | 1  1|                20                       |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     64 | 1  1|                26                       |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     92 |           0           |                       |
//        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// The domain name for F.ISI.ARPA is shown at offset 20.  The domain name
// FOO.F.ISI.ARPA is shown at offset 40; this definition uses a pointer to
// concatenate a label for FOO to the previously defined F.ISI.ARPA.  The
// domain name ARPA is defined at offset 64 using a pointer to the ARPA
// component of the name F.ISI.ARPA at 20; note that this pointer relies on
// ARPA being the last label in the string at 20.  The root domain name is
// defined by a single octet of zeros at 92; the root domain name has no
// labels.
fn decode_compressed_name(length: u8, reader: &mut BuffReader) -> String {
    // println!("Decoding compressed name");
    // Take bottom 6 bits of the length byte and the next byte and convert
    // that to an integer called pointer
    let six_bits = length & 0b00111111;
    // println!("Bottom bits {:?}", six_bits);
    let next_byte = reader.read(1);
    let converted_next_bytes: [u8; 1] = next_byte.try_into().unwrap();

    let pointer_bytes = u16::from_be_bytes([six_bits, converted_next_bytes[0]]);
    // println!("Pointer bytes: {:?}", pointer_bytes);

    let current_pos = reader.pos.clone();
    reader.seek(pointer_bytes as usize);
    let result = decode_compressed_question_name(reader);
    // println!("Seeking back");
    reader.seek(current_pos);

    result
}

fn get_answer(packet: &DNSPacket) -> String {
    // println!("Getting answers");
    for x in packet.answers.iter().into_iter() {
        // println!("TYPE: #{:?}", x._type);
        if x._type == TYPE_A {
            return String::from_utf8(x.data.clone()).unwrap();
        }
    }

    String::from("")
}

// String::from_utf8(x.data.clone()).unwrap()
// println!("DNSRECORD: {:?}", x);
// if x._type == TYPE_NS {
//     // let result = decode_question_name_simple(x.data);
//     // let mut v : Vec<String> = Vec::new();
//     println!("Converted: {:?}", String::from_utf8(x.data.clone()));
//     let array : [u8;16] = x.data.clone().try_into().unwrap();
//     return IpAddr::from(array)
fn get_nameserver(packet: &DNSPacket) -> String {
    for x in packet.authorities.iter().into_iter() {
        if x._type == TYPE_NS {
            return String::from_utf8(x.data.clone()).unwrap();
        }
    }

    String::from("")
}

fn get_nameserver_ip(packet: &DNSPacket) -> String {
    for x in packet.additionals.iter().into_iter() {
        if x._type == TYPE_A {
            return x.parsed_data.clone();
        }
    }

    String::from("")
}

fn resolve(domain_name: &str, nameserver: &str, record_type: u16) -> String {


    loop {
        println!("Querying {nameserver} for {domain_name}");
        let packet = send_query(nameserver, domain_name, record_type);
        // println!("Packet: {:?}", packet);
        // println!("Authorities: {:?}", packet.authorities);

        let ip = get_answer(&packet);
        if ip != "" {
            // println!("IP is not empty");
            return ip;
        }

        let ns_ip = get_nameserver_ip(&packet);
        if ns_ip != "" {
            let p = format!("{}:53", ns_ip);
            // println!("ns_ip is not empty: {p}");
            let result = resolve(domain_name, &p, record_type);
            return result;
        }

        let ns_domain = get_nameserver(&packet);
        if ns_domain != "" {
            // println!("NS Domain is not empty");
            let nns_ip = resolve(&ns_domain, nameserver, TYPE_A);
            let p = format!("{}:53", nns_ip);
            // println!("Received ns: {p}");
            let result = resolve(domain_name, &p, record_type);
            return result;
        }

        panic!("Something went wrong")
    }
}

fn main() {
    let name = "twitter.com";
    let nameserver = "198.41.0.4:53";
    let result = resolve(name, nameserver, TYPE_A);
    println!("IP: {:?}", result);

    // let ip_address = "8.8.8.8:53";
    // let ip_address = "198.41.0.4:53";
    // let result = send_query(ip_address, name, TYPE_A);


    // println!("IP: {:?}", result.answers);
}

#[cfg(test)]
mod tests {
    use crate::{build_query, encode_name, TYPE_A};

    #[test]
    fn test_encode_name() {
        let name = "google.com";
        let expected_result: Vec<u8> = vec![6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0];
        let result = encode_name(name);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_build_query() {
        let bytes = build_query("www.example.com", TYPE_A);

        let mut c = Vec::new();
        for b in bytes {
            c.push(format!("{:b}", b))
        }
    }
}
