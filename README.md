# TDNS

A toy dns client implementation for learning purposes. This is based on the "implement dns over a weekend" by Julia Evans.

# Reference
- https://implement-dns.wizardzines.com/book/intro
- https://datatracker.ietf.org/doc/html/rfc1035


# Usage

### Compile
```shell
cargo build
```

### Running the program
Pattern: 
`<executable> <domain-name>`

```shell
❯ ./target/debug/tdns google.com
Querying 198.41.0.4:53 for google.com
Querying 192.12.94.30:53 for google.com
Querying 216.239.34.10:53 for google.com
IP: "142.250.182.78"
```
