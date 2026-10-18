//! The protocol state of one session, without any I/O: what the native
//! client's session worker and peer workers do, as a plain state machine.
//! The caller owns the websocket: bytes from the server go into
//! [`Core::on_server`], bytes for the server come out as [`Event::Out`].
//!
//! No JS types in here, so it can be tested natively; `lib.rs` wraps it.

use std::collections::HashMap;

use bitmule_core::{
    ReceiverId, SessionId, Token,
    crypto::PublicKey,
    inner::{Envelope, EnvelopeCounter, EphemeralKeypair, IdentityKeypair, InnerKeyKind, OuterKey, OuterKeyKind, SessionKey, derive_session_key},
    pow,
    protocol::websocket::{ClientToServer, ECDH, Peer2Peer, PeerCaps, ServerToClient, TransferManifest},
};
use bitmule_crypto as bx;

/// What happened, for the caller to act on.
pub enum Event {
    /// Write this to the websocket.
    Out(Vec<u8>),
    /// We created the session.
    Created { reconnect_token: Token, relay_token: Token },
    /// We joined the session of `sender`.
    Joined { sender: ReceiverId, sender_caps: PeerCaps, relay_token: Token },
    /// A peer joined our session (its key checked out).
    PeerJoined { id: ReceiverId, caps: PeerCaps },
    /// The secure channel to a peer is up; messages can be sent.
    PeerReady { id: ReceiverId },
    /// A decrypted message from a peer.
    Message { from: ReceiverId, message: Peer2Peer },
    PeerLeft { id: ReceiverId },
    PeerFull { id: ReceiverId },
    Text(String),
}

struct Peer {
    outer: OuterKey,
    peer_pub: x25519_dalek::PublicKey,
    ephemeral: Option<EphemeralKeypair>,
    key: Option<SessionKey>,
    tx: EnvelopeCounter,
    rx: EnvelopeCounter,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Created the session (and is the sender of its transfer).
    Creator,
    Joiner,
}

pub struct Core {
    pub role: Role,
    share_key: bx::ShareKey,
    identity: IdentityKeypair,
    session_id: SessionId,
    our_id: ReceiverId,
    caps: PeerCaps,
    peers: HashMap<ReceiverId, Peer>,
    /// the manifest a sender told us about
    pub manifest: Option<TransferManifest>,
}

fn err<E: std::fmt::Debug>(what: &str) -> impl FnOnce(E) -> String + '_ {
    move |e| format!("{what}: {e:?}")
}

impl Core {
    fn new(role: Role, share_key: bx::ShareKey, caps: PeerCaps) -> Self {
        let session_id = SessionId(share_key.session_id());
        Core {
            role,
            share_key,
            identity: IdentityKeypair::generate(),
            session_id,
            our_id: ReceiverId::random(),
            caps,
            peers: HashMap::new(),
            manifest: None,
        }
    }

    /// A session of our own, under a fresh key.
    pub fn create(caps: PeerCaps) -> Self {
        Core::new(Role::Creator, bx::ShareKey::random(), caps)
    }

    /// The session behind `share_key`, which somebody else created.
    pub fn join(share_key: bx::ShareKey, caps: PeerCaps) -> Self {
        Core::new(Role::Joiner, share_key, caps)
    }

    pub fn share_key(&self) -> &bx::ShareKey {
        &self.share_key
    }
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
    pub fn our_id(&self) -> ReceiverId {
        self.our_id
    }

    /// Does `nonce` solve the proof of work for `/ws/create`?
    pub fn pow_step(&self, magic: u32, difficulty: u8, start: u64, count: u32) -> Option<u64> {
        (start..start + count as u64).find(|&n| pow::verify_c(&self.session_id, magic, n, difficulty))
    }

    /// First message to the server: `CreateSession` or `JoinSession`.
    pub fn hello(&self) -> Vec<u8> {
        let pub_key = self.identity.public_key();
        let mac = self.share_key.mac_ephemeral_pub(&pub_key);
        let message = match self.role {
            Role::Creator => ClientToServer::CreateSession { id: self.our_id, capabilities: self.caps, pub_key, mac },
            Role::Joiner => ClientToServer::JoinSession { id: self.our_id, capabilities: self.caps, pub_key, mac },
        };
        postcard::to_stdvec(&message).unwrap()
    }

    /// Start the key exchange with a peer whose identity key is known (and
    /// checked). Returns what to send to the server.
    fn add_peer(&mut self, id: ReceiverId, peer_pub: PublicKey) -> Result<Vec<u8>, String> {
        let peer_pub = x25519_dalek::PublicKey::from(peer_pub.0);
        let outer = self.identity.outer_key_for(&peer_pub, &self.session_id);
        let ephemeral = EphemeralKeypair::generate();
        let mut peer = Peer { outer, peer_pub, ephemeral: None, key: None, tx: EnvelopeCounter::default(), rx: EnvelopeCounter::default() };

        let hello = ECDH { ephemeral_pub: ephemeral.public_key() };
        let msg = Envelope::<OuterKeyKind, ECDH>::seal(&hello, &peer.outer, &mut peer.tx, &self.session_id)
            .map_err(err("sealing key exchange"))?;
        peer.ephemeral = Some(ephemeral);
        self.peers.insert(id, peer);
        Ok(postcard::to_stdvec(&ClientToServer::SendTo1 { dest_id: id, msg }).unwrap())
    }

    /// Seal a message for a peer whose channel is up.
    pub fn seal(&mut self, to: ReceiverId, message: &Peer2Peer) -> Result<Vec<u8>, String> {
        let peer = self.peers.get_mut(&to).ok_or("no such peer")?;
        let key = peer.key.as_ref().ok_or("secure channel to the peer is not up yet")?;
        let msg = Envelope::<InnerKeyKind, Peer2Peer>::seal(message, key, &mut peer.tx, &self.session_id)
            .map_err(err("sealing message"))?;
        Ok(postcard::to_stdvec(&ClientToServer::SendTo2 { dest_id: to, msg }).unwrap())
    }

    pub fn forget(&mut self, id: ReceiverId) {
        self.peers.remove(&id);
    }

    /// Process one binary websocket message from the server.
    pub fn on_server(&mut self, bytes: &[u8]) -> Result<Vec<Event>, String> {
        let message: ServerToClient = postcard::from_bytes(bytes).map_err(err("bad server message"))?;
        let mut events = vec![];
        match message {
            ServerToClient::Text(text) => events.push(Event::Text(text)),
            ServerToClient::SessionCreated { reconnect_token, relay_token } => {
                events.push(Event::Created { reconnect_token, relay_token })
            }
            ServerToClient::SessionJoined { relay_token, sender_id, sender_pub_key, sender_mac, sender_caps } => {
                if self.share_key.mac_ephemeral_pub(&sender_pub_key) != sender_mac {
                    return Err("sender does not know the share key".into());
                }
                events.push(Event::Joined { sender: sender_id, sender_caps, relay_token });
                events.push(Event::Out(self.add_peer(sender_id, sender_pub_key)?));
            }
            ServerToClient::PeerJoined { id, pub_key, mac, caps } => {
                if self.share_key.mac_ephemeral_pub(&pub_key) != mac {
                    // somebody who does not know the key: ignore them
                    return Ok(events);
                }
                events.push(Event::PeerJoined { id, caps });
                events.push(Event::Out(self.add_peer(id, pub_key)?));
            }
            ServerToClient::PeerMessage1 { from, data } => {
                let Some(peer) = self.peers.get_mut(&from) else { return Ok(events) };
                let theirs = data.open(&peer.outer, &self.session_id, &mut peer.rx).map_err(err("opening key exchange"))?;
                let ephemeral = peer.ephemeral.take().ok_or("key exchange twice")?;
                peer.key = Some(derive_session_key(&self.identity, &ephemeral, &peer.peer_pub, &theirs.ephemeral_pub.into(), &self.session_id));
                events.push(Event::PeerReady { id: from });
            }
            ServerToClient::PeerMessage2 { from, data } => {
                let Some(peer) = self.peers.get_mut(&from) else { return Ok(events) };
                let key = peer.key.as_ref().ok_or("message before the key exchange")?;
                let message = data.open(key, &self.session_id, &mut peer.rx).map_err(err("opening message"))?;
                if let Peer2Peer::Manifest(manifest) = &message {
                    self.manifest = Some(manifest.clone());
                }
                events.push(Event::Message { from, message });
            }
            ServerToClient::PeerFull { id } => events.push(Event::PeerFull { id }),
            ServerToClient::PeerDisconnected { id } => {
                self.peers.remove(&id);
                events.push(Event::PeerLeft { id });
            }
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the server does with a message: turn `SendTo*` into the matching
    /// `PeerMessage*` for the destination, from `from`.
    fn route(from: ReceiverId, bytes: &[u8]) -> (ReceiverId, Vec<u8>) {
        match postcard::from_bytes::<ClientToServer>(bytes).unwrap() {
            ClientToServer::SendTo1 { dest_id, msg } => {
                (dest_id, postcard::to_stdvec(&ServerToClient::PeerMessage1 { from, data: msg }).unwrap())
            }
            ClientToServer::SendTo2 { dest_id, msg } => {
                (dest_id, postcard::to_stdvec(&ServerToClient::PeerMessage2 { from, data: msg }).unwrap())
            }
            _ => panic!("not a routed message"),
        }
    }

    fn outs(events: &[Event]) -> Vec<Vec<u8>> {
        events.iter().filter_map(|e| if let Event::Out(b) = e { Some(b.clone()) } else { None }).collect()
    }

    /// Two sessions run the join and key exchange against a fake server,
    /// then a message goes through both ways.
    #[test]
    fn key_exchange_and_messages() {
        let caps = PeerCaps::RELAY | PeerCaps::WEBRTC;
        let mut sender = Core::create(caps);
        let mut receiver = Core::join(bx::ShareKey(sender.share_key.0), caps);
        assert_eq!(sender.session_id(), receiver.session_id());

        // the server tells the sender about the receiver, and the receiver about the sender
        let hello = postcard::from_bytes::<ClientToServer>(&receiver.hello()).unwrap();
        let ClientToServer::JoinSession { id, capabilities, pub_key, mac } = hello else { panic!() };
        let sender_hello = postcard::from_bytes::<ClientToServer>(&sender.hello()).unwrap();
        let ClientToServer::CreateSession { pub_key: sender_pub, mac: sender_mac, .. } = sender_hello else { panic!() };

        let to_sender = postcard::to_stdvec(&ServerToClient::PeerJoined { id, pub_key, mac, caps: capabilities }).unwrap();
        let to_receiver = postcard::to_stdvec(&ServerToClient::SessionJoined {
            relay_token: Token::random(),
            sender_id: sender.our_id(),
            sender_pub_key: sender_pub,
            sender_mac,
            sender_caps: caps,
        }).unwrap();
        let sender_out = outs(&sender.on_server(&to_sender).unwrap());
        let receiver_out = outs(&receiver.on_server(&to_receiver).unwrap());
        assert_eq!((sender_out.len(), receiver_out.len()), (1, 1));

        // each side gets the other's ephemeral key
        let (_, m) = route(sender.our_id(), &sender_out[0]);
        let events = receiver.on_server(&m).unwrap();
        assert!(matches!(events[0], Event::PeerReady { .. }));
        let (_, m) = route(receiver.our_id(), &receiver_out[0]);
        let events = sender.on_server(&m).unwrap();
        assert!(matches!(events[0], Event::PeerReady { .. }));

        // sealed messages both ways
        let sealed = sender.seal(receiver.our_id(), &Peer2Peer::JoinRelay).unwrap();
        let (_, m) = route(sender.our_id(), &sealed);
        let events = receiver.on_server(&m).unwrap();
        assert!(matches!(&events[0], Event::Message { message: Peer2Peer::JoinRelay, .. }));

        let sealed = receiver.seal(sender.our_id(), &Peer2Peer::Get { start: 0, end: 77 }).unwrap();
        let (_, m) = route(receiver.our_id(), &sealed);
        let events = sender.on_server(&m).unwrap();
        assert!(matches!(&events[0], Event::Message { message: Peer2Peer::Get { start: 0, end: 77 }, .. }));
    }

    #[test]
    fn a_peer_without_the_key_is_ignored() {
        let mut sender = Core::create(PeerCaps::RELAY);
        let stranger = Core::join(bx::ShareKey::random(), PeerCaps::RELAY);
        let ClientToServer::JoinSession { id, capabilities, pub_key, mac } = postcard::from_bytes(&stranger.hello()).unwrap() else { panic!() };
        let joined = postcard::to_stdvec(&ServerToClient::PeerJoined { id, pub_key, mac, caps: capabilities }).unwrap();
        assert!(sender.on_server(&joined).unwrap().is_empty());
    }

    #[test]
    fn proof_of_work_agrees_with_the_server_check() {
        let core = Core::create(PeerCaps::RELAY);
        let (magic, difficulty) = (7, 12);
        let mut start = 0;
        let nonce = loop {
            if let Some(n) = core.pow_step(magic, difficulty, start, 10_000) {
                break n;
            }
            start += 10_000;
        };
        assert!(pow::verify(&core.session_id(), magic, nonce, difficulty));
    }
}
