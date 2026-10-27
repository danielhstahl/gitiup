//! The per-job DNS policy: a local resolver that only answers for the allowlist.
//!
//! Why a DNS server and not just a firewall: a job that is *refused* a lookup fails
//! differently from a job whose lookup succeeds and then cannot connect. `NXDOMAIN`
//! is what "this host does not exist" means to every build tool in existence, and it
//! is the honest answer here — from this job's point of view, a host that is not on
//! its allowlist does not exist.
//!
//! The resolver is authoritative for its own view: it never forwards. An allowlisted
//! name is resolved by *this* process (which is trusted and has whatever network the
//! operator has) and the answer is served to the job; an unlisted name gets
//! `NXDOMAIN`; a query type that is not an address gets `REFUSED`, because "which mail
//! exchanger does the build need" is not a thing a CI job legitimately asks, and a
//! TXT-over-DNS channel is exactly the egress hole this module exists to close.
//!
//! It is a UDP server on loopback with an ephemeral port, one datagram per query, and
//! it lives as long as the [`Egress`](crate::egress::Egress) that started it.

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use gitiup_attest::{Error, ErrorKind, Result};

use crate::egress::Allowlist;

/// Largest DNS message we will read. The protocol allows 65535; a build sends far
/// less, and a bounded read is one less thing to think about.
const MAX_QUERY: usize = 512;

/// Answer TTL, in seconds. Short, so a job cannot pin a stale address for an hour.
const TTL: u32 = 60;

/// The per-job resolver.
#[derive(Debug)]
pub struct Resolver {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    allow: Allowlist,
    endpoint: SocketAddr,
    stop: AtomicBool,
    thread: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl Resolver {
    /// Bind `127.0.0.1:0` and start answering.
    pub fn start(allow: Allowlist) -> Result<Resolver> {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).map_err(|why| {
            Error::new(
                ErrorKind::Invalid,
                "egress",
                format!("could not bind the sandbox resolver on loopback: {why}"),
            )
        })?;
        socket
            .set_nonblocking(true)
            .map_err(|why| Error::new(ErrorKind::Invalid, "egress", format!("{why}")))?;
        let endpoint = socket
            .local_addr()
            .map_err(|why| Error::new(ErrorKind::Invalid, "egress", format!("{why}")))?;
        let inner = Arc::new(Inner {
            allow,
            endpoint,
            stop: AtomicBool::new(false),
            thread: std::sync::Mutex::new(None),
        });
        let handle = std::thread::Builder::new()
            .name("gitiup-sandbox-dns".to_string())
            .spawn({
                let inner = Arc::clone(&inner);
                move || serve(socket, inner)
            })
            .map_err(|why| {
                Error::new(
                    ErrorKind::Invalid,
                    "egress",
                    format!("could not start the sandbox resolver: {why}"),
                )
            })?;
        *inner.thread.lock().unwrap() = Some(handle);
        Ok(Resolver { inner })
    }

    /// Where a job's `/etc/resolv.conf` (or `RES_OPTIONS`) should point.
    pub fn endpoint(&self) -> SocketAddr {
        self.inner.endpoint
    }

    /// The allowlist it answers for.
    pub fn allowlist(&self) -> &Allowlist {
        &self.inner.allow
    }

    /// Answer one query, as a pure function — the tests use this directly, and so
    /// does anything that wants to check a policy without a socket.
    pub fn answer(allow: &Allowlist, query: &[u8]) -> Vec<u8> {
        respond(allow, query)
    }
}

impl Drop for Resolver {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        // The serve loop polls the flag between datagrams, so the join is quick.
        if let Some(handle) = self.inner.thread.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

fn serve(socket: UdpSocket, inner: Arc<Inner>) {
    let mut buffer = [0u8; MAX_QUERY];
    loop {
        if inner.stop.load(Ordering::SeqCst) {
            return;
        }
        match socket.recv_from(&mut buffer) {
            Ok((size, peer)) => {
                let reply = respond(&inner.allow, &buffer[..size]);
                let _ = socket.send_to(&reply, peer);
            }
            Err(why) if why.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(why) if why.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        }
    }
}

/// Response codes, as the four bits they occupy.
const NO_ERROR: u16 = 0;
const FORM_ERROR: u16 = 1;
const NX_DOMAIN: u16 = 3;
const REFUSED: u16 = 5;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

/// Build the reply to one DNS message.
fn respond(allow: &Allowlist, query: &[u8]) -> Vec<u8> {
    let Some((id, name, qtype)) = parse_query(query) else {
        return header(0, FORM_ERROR, 0);
    };
    if qtype != TYPE_A && qtype != TYPE_AAAA {
        // Refuse rather than answer-empty: a job asking for TXT/SRV/HTTPRR through a
        // CI sandbox is not accidentally doing it.
        return header(id, REFUSED, 1);
    }
    if !allow.allows(&name) {
        let mut reply = header(id, NX_DOMAIN, 1);
        push_question(&mut reply, &name, qtype);
        return reply;
    }
    // Authoritative for our own view: resolve here, serve the answer there.
    let addresses = resolve_names(&name);
    let wanted: Vec<IpAddr> = match qtype {
        TYPE_A => addresses.iter().copied().filter(IpAddr::is_ipv4).collect(),
        _ => addresses.iter().copied().filter(IpAddr::is_ipv6).collect(),
    };
    let mut reply = header(id, NO_ERROR, 1);
    // The question is echoed with an ANCOUNT that counts what follows; a name the
    // resolver knows but that has no record of this family is NODATA (NO_ERROR, no
    // answers), which is what a real resolver would say.
    push_question(&mut reply, &name, qtype);
    reply[6..8].copy_from_slice(&(wanted.len() as u16).to_be_bytes());
    for address in wanted {
        push_address(&mut reply, &name, qtype, &address);
    }
    reply
}

/// The 12-byte header, with the question echoed later.
fn header(id: u16, rcode: u16, questions: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&id.to_be_bytes());
    // QR=1, RD echoed as set, RA=1 — the resolver is recursive from the job's
    // point of view, which is the only reason a job points at it.
    out.extend_from_slice(&(0x8180 | rcode).to_be_bytes());
    out.extend_from_slice(&questions.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

fn push_question(out: &mut Vec<u8>, name: &str, qtype: u16) {
    push_name(out, name);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
}

fn push_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// One answer record, with the name as a compression pointer to offset 12 (where the
/// question name always starts in the messages this function builds).
fn push_address(out: &mut Vec<u8>, _name: &str, qtype: u16, address: &IpAddr) {
    out.extend_from_slice(&0xC00Cu16.to_be_bytes());
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&TTL.to_be_bytes());
    match address {
        IpAddr::V4(v4) => {
            let bytes = v4.octets();
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        IpAddr::V6(v6) => {
            let bytes = v6.octets();
            out.extend_from_slice(&16u16.to_be_bytes());
            out.extend_from_slice(&bytes);
        }
    }
}

/// `(id, qname, qtype)` from a query, or `None` if it is not a query this resolver
/// will pretend to understand.
fn parse_query(query: &[u8]) -> Option<(u16, String, u16)> {
    if query.len() < 13 {
        return None;
    }
    // QR must be 0: this answers queries, it does not parse its own answers.
    if query[2] & 0x80 != 0 {
        return None;
    }
    let id = u16::from_be_bytes([query[0], query[1]]);
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount != 1 {
        return None;
    }
    let mut name = String::new();
    let mut index = 12usize;
    loop {
        let len = *query.get(index)?;
        if len == 0 {
            index += 1;
            break;
        }
        if len & 0xC0 != 0 {
            // Compression pointers have no business in a query.
            return None;
        }
        let end = index + 1 + len as usize;
        if end > query.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&query[index + 1..end]));
        index = end;
    }
    let qtype = u16::from_be_bytes([*query.get(index)?, *query.get(index + 1)?]);
    Some((id, name.to_ascii_lowercase(), qtype))
}

/// Build a query message, for tests and for a volunteer checking a policy by hand.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    push_question(&mut out, name, qtype);
    out
}

/// The rcode of a reply, or `None` if it is too short to be one.
pub fn rcode(reply: &[u8]) -> Option<u16> {
    let (a, b) = (*reply.get(2)?, *reply.get(3)?);
    Some(u16::from_be_bytes([a, b]) & 0x000f)
}

/// The answer count of a reply.
pub fn answers(reply: &[u8]) -> Option<usize> {
    let (a, b) = (*reply.get(6)?, *reply.get(7)?);
    Some(u16::from_be_bytes([a, b]) as usize)
}

fn resolve_names(name: &str) -> Vec<IpAddr> {
    // Port 0: we want the addresses, not a connection. `to_socket_addrs` is the only
    // resolver in std, and it is the same one this process would use.
    (name, 0u16)
        .to_socket_addrs()
        .map(|addresses| addresses.map(|address| address.ip()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(hosts: &[&str]) -> Allowlist {
        let mut list = Allowlist::empty();
        for host in hosts {
            list.push(host).unwrap();
        }
        list
    }

    #[test]
    fn an_unlisted_name_does_not_exist() {
        let list = allow(&["crates.io"]);
        let reply = Resolver::answer(&list, &build_query(0x4242, "evil.test", TYPE_A));
        assert_eq!(rcode(&reply), Some(NX_DOMAIN));
        assert_eq!(answers(&reply), Some(0));
        // The id is echoed, or the client ignores the reply.
        assert_eq!(&reply[0..2], &[0x42, 0x42]);
    }

    #[test]
    fn a_listed_name_resolves_locally() {
        let list = allow(&["localhost"]);
        let reply = Resolver::answer(&list, &build_query(7, "localhost", TYPE_A));
        assert_eq!(rcode(&reply), Some(NO_ERROR));
        assert!(answers(&reply).unwrap() >= 1, "localhost has an A record");
        // The last four bytes of the first answer must be the loopback address.
        let index = reply.len() - 4;
        assert_eq!(
            &reply[index..],
            &[127, 0, 0, 1],
            "the answer we serve is the answer this host gives"
        );
    }

    #[test]
    fn a_query_type_a_build_has_no_business_asking_is_refused() {
        let list = allow(&["crates.io"]);
        // TXT (16): the classic covert channel.
        let reply = Resolver::answer(&list, &build_query(9, "crates.io", 16));
        assert_eq!(rcode(&reply), Some(REFUSED));
    }

    #[test]
    fn nonsense_is_not_anwsered_as_a_deny() {
        let list = allow(&["crates.io"]);
        assert_eq!(rcode(&Resolver::answer(&list, &[])), Some(FORM_ERROR));
        assert_eq!(rcode(&Resolver::answer(&list, &[0u8; 8])), Some(FORM_ERROR));
    }

    #[test]
    fn the_socket_serves_the_same_answer_as_the_function() {
        let resolver = Resolver::start(allow(&["localhost"])).unwrap();
        let query = build_query(0x1234, "localhost", TYPE_A);
        let socket = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        // A reply only goes to a peer the server saw, so send first, then read.
        socket.send_to(&query, resolver.endpoint()).unwrap();
        let mut buffer = [0u8; 512];
        let (size, _peer) = socket.recv_from(&mut buffer).unwrap();
        let reply = &buffer[..size];
        assert_eq!(rcode(reply), Some(NO_ERROR));
        assert_eq!(answers(reply), Some(1));

        socket
            .send_to(&build_query(1, "nope.test", TYPE_A), resolver.endpoint())
            .unwrap();
        let (size, _peer) = socket.recv_from(&mut buffer).unwrap();
        assert_eq!(rcode(&buffer[..size]), Some(NX_DOMAIN));
    }

    #[test]
    fn every_answer_is_of_the_family_that_was_asked_for() {
        // Serving an AAAA in answer to an A query is how a resolver gets a build to
        // fail in a way nobody can reproduce, and NODATA (NO_ERROR, no answers) is the
        // honest reply when the name exists but not in that family.
        let list = allow(&["localhost"]);
        let reply = Resolver::answer(&list, &build_query(3, "localhost", TYPE_AAAA));
        assert_eq!(rcode(&reply), Some(NO_ERROR));
        let expected = resolve_names("localhost")
            .iter()
            .filter(|ip| ip.is_ipv6())
            .count();
        assert_eq!(
            answers(&reply),
            Some(expected),
            "localhost has {expected} AAAA records here"
        );
        let v4 = Resolver::answer(&list, &build_query(4, "localhost", TYPE_A));
        let expected4 = resolve_names("localhost")
            .iter()
            .filter(|ip| ip.is_ipv4())
            .count();
        assert_eq!(answers(&v4), Some(expected4));
    }

    #[test]
    fn a_reply_echoes_the_question_so_a_client_can_match_it() {
        // A resolver that answers without echoing the question is ignored by every
        // resolver library in existence, so this is the check that the wire format is
        // real and not just our own reading of it.
        let list = allow(&["localhost"]);
        let query = build_query(0xbeef, "localhost", TYPE_A);
        let reply = Resolver::answer(&list, &query);
        assert_eq!(&reply[0..2], &[0xbe, 0xef], "the id must come back");
        assert_eq!(
            &reply[12..query.len()],
            &query[12..],
            "the question must come back"
        );
        assert!(reply.len() > query.len(), "and the answer must follow it");
    }
}
