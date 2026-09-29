use serde::{Deserialize, Deserializer, Serializer};
use x25519_dalek::{PublicKey, StaticSecret, SharedSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead};
use aes_gcm::aead::{Aead, Payload};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;
use serde::{Serialize, de::DeserializeOwned};
use std::marker::PhantomData;

use crate::{SessionId, crypto};

fn concat2<const N: usize, const M: usize, const O: usize>(a: &[u8; N], b: &[u8; M]) -> [u8; O] {
    if N + M != O {
        panic!("lengths don't match");
    }
    let mut res = [0u8; O];
    let (left, right) = res.split_at_mut(N);
    left.copy_from_slice(a);
    right.copy_from_slice(b);
    res
}

fn concat3<const N: usize, const M: usize, const P: usize, const O: usize>(
    a: &[u8; N],
    b: &[u8; M],
    c: &[u8; P],
) -> [u8; O] {
    if N + M + P != O {
        panic!("lengths don't match");
    }
    let mut res = [0u8; O];
    res[..N].copy_from_slice(a);
    res[N..N + M].copy_from_slice(b);
    res[N + M..].copy_from_slice(c);
    res
}

#[derive(Debug)]
pub enum Error {
    Serde(postcard::Error),
    Crypto(aead::Error),
    Counter,
}

pub enum OuterKeyKind {}
pub enum InnerKeyKind {}

pub struct Envelope<KeyKind, T> {
    _k: PhantomData<KeyKind>,
    _m: PhantomData<T>,
    counter: u32,
    nonce: [u8; 12], // EAED
    data: Vec<u8>,
}

/// Peer static identity: X25519 keypair.
pub struct IdentityKeypair {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl IdentityKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
    pub fn public_key(&self) -> crate::crypto::PublicKey {
        crate::crypto::PublicKey(self.public.to_bytes())
    }

    /// Derive the outer_key shared with `peer_pub` under this session.
    /// outer_key = HKDF-SHA256(
    ///     salt = session_id,
    ///     ikm  = ECDH(local_priv, peer_pub),
    ///     info = b"bitmule-p2p outer-key v1",
    /// )
    /// Same-peer + same-session = same outer_key on both sides
    /// (X25519-DH is commutative). Session_id in salt binds the key to
    /// this specific session, so leaking one session's outer_key doesn't
    /// leak another between the same two peers.
    pub fn outer_key_for(&self, peer_pub: &PublicKey, session_id: &SessionId) -> OuterKey {
        let shared: SharedSecret = self.secret.diffie_hellman(peer_pub);
        let hkdf = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(b"bitmule-p2p outer-key v1", &mut key)
            .expect("32 bytes fits within HKDF-SHA256 output length");
        OuterKey(key)
    }
}

pub struct OuterKey(pub [u8; 32]);
impl Drop for OuterKey {
    fn drop(&mut self) { self.0.zeroize(); }
}

#[derive(Default)]
pub struct EnvelopeCounter {
    inner: u32,
}
impl EnvelopeCounter {
    pub const SIZE: usize = 4;
    fn as_bytes(&self) -> [u8; 4] {
        self.inner.to_le_bytes()
    }
    fn increment(&mut self) {
        self.inner += 1;
    }
}

impl<T: Serialize + DeserializeOwned> Envelope<OuterKeyKind, T> {
    /// Seal `payload` under `key` with a fresh random nonce.
    /// `counter` should be monotonic per-key; caller tracks last-seen on
    /// the receive side and rejects non-monotonic envelopes as replays.
    /// AAD binds session_id + counter so an attacker can't replay the
    /// ciphertext into a different session or reorder in-session.
    pub fn seal(
        payload: &T,
        key: &OuterKey,
        counter: &mut EnvelopeCounter,
        session_id: &SessionId,
    ) -> Result<Self, Error> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = postcard::to_stdvec(payload)
            .map_err(Error::Serde)?;

        // Increment BEFORE computing AAD so the AAD matches the counter
        // value we stamp into the envelope; open() reads envelope.counter
        // for its own AAD and needs the same value.
        counter.increment();

        let aad: [u8; SessionId::SIZE + EnvelopeCounter::SIZE] = concat2(session_id.as_bytes(), &counter.as_bytes());

        let ct = cipher.encrypt(nonce, Payload { msg: &plaintext, aad: &aad })
            .map_err(Error::Crypto)?;

        Ok(Envelope {
            _k: PhantomData,
            _m: PhantomData,
            counter: counter.inner,
            nonce: nonce_bytes,
            data: ct,
        })
    }

    /// Verify + decrypt. Returns the inner T. Caller MUST additionally
    /// enforce `envelope.counter > last_seen_counter` before treating T
    /// as fresh — AEAD auth alone doesn't stop replay of a valid old
    /// message, only forgery of a new one.
    pub fn open(
        &self,
        key: &OuterKey,
        session_id: &SessionId,
        counter: &mut EnvelopeCounter,
    ) -> Result<T, Error> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
        let nonce = Nonce::from_slice(&self.nonce);

        let aad: [u8; SessionId::SIZE + EnvelopeCounter::SIZE] = concat2(session_id.as_bytes(), &self.counter.to_le_bytes());

        let plaintext = cipher.decrypt(nonce, Payload { msg: &self.data, aad: &aad })
            .map_err(Error::Crypto)?;

        counter.increment();

        if counter.inner != self.counter {
            return Err(Error::Counter);
        }

        postcard::from_bytes(&plaintext)
            .map_err(Error::Serde)
    }
}


/// Post-X3DH shared session key. Derived from three DH operations over the
/// initiator's + responder's static identity keys and their per-session
/// ephemerals (see [`derive_session_key`]). Provides forward secrecy: even
/// if a peer's static private key leaks later, past traffic under this
/// session_key stays confidential — decryption requires the ephemeral
/// privates too, which are zeroized after derivation.
pub struct SessionKey(pub [u8; 32]);
impl Drop for SessionKey {
    fn drop(&mut self) { self.0.zeroize(); }
}


/// Ephemeral X25519 keypair used for the X3DH exchange.
///
/// Uses `StaticSecret` under the hood (not `EphemeralSecret`) because X3DH
/// requires the ephemeral private to be used in TWO DH ops (`dh2` and
/// `dh3`), which `EphemeralSecret` can't support since it's consumed by a
/// single `diffie_hellman()` call. `Zeroize` on drop keeps the same
/// forward-secrecy story — the private key is destroyed once the session
/// key has been derived.
pub struct EphemeralKeypair {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
    pub fn public_key(&self) -> crypto::PublicKey {
        crypto::PublicKey(self.public.to_bytes())
    }
}


/// Derive the post-X3DH session_key from this peer's static + ephemeral
/// privates and the counterpart's static + ephemeral pubs.
///
/// Standard X3DH (Signal-shape, minus the async prekey machinery since
/// bitmule peers are synchronous — both online during KEX):
/// ```text
///   DH1 = DH(IK_A_priv, EK_B_pub)   # A's identity × B's ephemeral
///   DH2 = DH(EK_A_priv, IK_B_pub)   # A's ephemeral × B's identity
///   DH3 = DH(EK_A_priv, EK_B_pub)   # A's ephemeral × B's ephemeral
///   session_key = HKDF-SHA256(
///       salt = session_id,
///       ikm  = DH1 || DH2 || DH3,
///       info = b"bitmule-p2p session-key v1" || IK_A_pub || IK_B_pub,
///   )
/// ```
///
/// Both peers compute the same session_key because X25519-DH is symmetric
/// (DH(x, gy) == DH(y, gx)). To agree on the AD binding (IK_A||IK_B) both
/// sides need to agree who "A" is — we canonicalise by lex-comparing the
/// two identity pubs: the smaller-bytes IK is "A", the larger is "B". This
/// avoids either peer needing a role bit passed in.
///
/// The AD binding of IK_A_pub||IK_B_pub is X3DH's identity-key-substitution
/// defence — an attacker can't swap in different IKs while reusing captured
/// ephemerals without invalidating the derived key.
pub fn derive_session_key(
    my_ik: &IdentityKeypair,
    my_ek: &EphemeralKeypair,
    peer_ik_pub: &PublicKey,
    peer_ek_pub: &PublicKey,
    session_id: &SessionId,
) -> SessionKey {
    // Canonical role: lower-bytes IK_pub is initiator ("A"), higher is
    // responder ("B"). Same order on both sides regardless of who actually
    // sent Init vs Response on the wire.
    let am_initiator = my_ik.public.as_bytes() < peer_ik_pub.as_bytes();
    let (ik_a_pub, ik_b_pub) = if am_initiator {
        (&my_ik.public, peer_ik_pub)
    } else {
        (peer_ik_pub, &my_ik.public)
    };

    // Compute the three DHs from our side. Both sides get bit-identical
    // results because X25519 DH is symmetric.
    let dh1: [u8; 32] = if am_initiator {
        // I'm A. DH1 = DH(IK_A_priv, EK_B_pub) = my_ik_priv × peer_ek_pub
        my_ik.secret.diffie_hellman(peer_ek_pub).to_bytes()
    } else {
        // I'm B. DH1 conceptually = DH(IK_A_priv, EK_B_pub) — I have IK_B_priv + EK_B_priv.
        // By symmetry, DH(IK_A_priv, EK_B_pub) = DH(EK_B_priv, IK_A_pub).
        my_ek.secret.diffie_hellman(peer_ik_pub).to_bytes()
    };
    let dh2: [u8; 32] = if am_initiator {
        // I'm A. DH2 = DH(EK_A_priv, IK_B_pub) = my_ek_priv × peer_ik_pub
        my_ek.secret.diffie_hellman(peer_ik_pub).to_bytes()
    } else {
        // I'm B. DH2 conceptually = DH(EK_A_priv, IK_B_pub) — I have IK_B_priv.
        // By symmetry, DH(EK_A_priv, IK_B_pub) = DH(IK_B_priv, EK_A_pub).
        my_ik.secret.diffie_hellman(peer_ek_pub).to_bytes()
    };
    // DH3 is symmetric on both sides: DH(EK_A_priv, EK_B_pub) = DH(EK_B_priv, EK_A_pub)
    let dh3: [u8; 32] = my_ek.secret.diffie_hellman(peer_ek_pub).to_bytes();

    let ikm: [u8; 96] = concat3(&dh1, &dh2, &dh3);

    let info: [u8; 26 + 32 + 32] = concat3(
        b"bitmule-p2p session-key v1",
        ik_a_pub.as_bytes(),
        ik_b_pub.as_bytes(),
    );

    let hkdf = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), &ikm);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .expect("32 bytes fits within HKDF-SHA256 output length");
    SessionKey(key)
}


impl<T: Serialize + DeserializeOwned> Envelope<InnerKeyKind, T> {
    /// Seal `payload` under the post-X3DH `session_key`. Same on-wire
    /// envelope shape as the outer variant (counter + nonce + ct); only
    /// the key at the seal/open call site differs. Phantom KeyKind
    /// prevents accidentally opening an inner envelope with an outer key
    /// or vice versa at compile time.
    pub fn seal(
        payload: &T,
        key: &SessionKey,
        counter: &mut EnvelopeCounter,
        session_id: &SessionId,
    ) -> Result<Self, Error> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = postcard::to_stdvec(payload)
            .map_err(Error::Serde)?;

        // Increment BEFORE computing AAD so the AAD matches the counter
        // value we stamp into the envelope; open() reads envelope.counter
        // for its own AAD and needs the same value.
        counter.increment();

        let aad: [u8; SessionId::SIZE + EnvelopeCounter::SIZE] = concat2(session_id.as_bytes(), &counter.as_bytes());

        let ct = cipher.encrypt(nonce, Payload { msg: &plaintext, aad: &aad })
            .map_err(Error::Crypto)?;

        Ok(Envelope {
            _k: PhantomData,
            _m: PhantomData,
            counter: counter.inner,
            nonce: nonce_bytes,
            data: ct,
        })
    }

    /// Verify + decrypt an inner envelope. Matches the outer variant's
    /// contract: caller supplies the same monotonic counter as the peer,
    /// mismatch returns `Error::Counter` (out-of-order or replay).
    pub fn open(
        &self,
        key: &SessionKey,
        session_id: &SessionId,
        counter: &mut EnvelopeCounter,
    ) -> Result<T, Error> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
        let nonce = Nonce::from_slice(&self.nonce);

        let aad: [u8; SessionId::SIZE + EnvelopeCounter::SIZE] = concat2(session_id.as_bytes(), &self.counter.to_le_bytes());

        let plaintext = cipher.decrypt(nonce, Payload { msg: &self.data, aad: &aad })
            .map_err(Error::Crypto)?;

        counter.increment();

        if counter.inner != self.counter {
            return Err(Error::Counter);
        }

        postcard::from_bytes(&plaintext)
            .map_err(Error::Serde)
    }
}


// ---- Peer state machine ----
//
// One per P2P connection. Kenna 2026-09-19 per Seb's sketch:
//   begin with KeyExchange (own keys)
//   -> add peer info
//   - SessionKey
//   -> X3DH init
//   -> X3DH Response
//   -> Established
//
// The state machine trusts inputs — MAC verification of peer_ik (against the
// URL-fragment share_key via `ShareKey::mac_ephemeral_pub` in bitmule-crypto)
// happens at the WebSocket handler layer, before frames reach this transition
// surface. Keeps the state-machine boundary clean and free of the crypto dep
// on bitmule-crypto that would otherwise leak in here.

/// State-machine error surface. Distinct from the envelope [`Error`] type
/// because state-machine failures are protocol-level (wrong transition),
/// not per-message crypto failures.
#[derive(Debug)]
pub enum StateError {
    /// Attempted a transition that isn't valid from the current state
    /// (e.g. calling `recv_x3dh` before `add_peer`).
    InvalidTransition,
}

/// Single-variant X3DH frame. Both peers unconditionally send their
/// ephemeral pub as soon as they know the peer's IK (post-add_peer), then
/// wait to receive the counterpart's frame. The key derivation is symmetric
/// so whoever arrives first triggers the transition to Established — no
/// initiator/responder role bookkeeping needed on the wire.
///
/// Wire-shape: caller wraps in `Envelope<OuterKeyKind, X3DHFrame>` before
/// sending; on receive side, unwraps and hands to [`PeerState::recv_x3dh`].
#[derive(Debug, Clone, Copy)]
pub struct X3DHFrame {
    pub ephemeral_pub: [u8; 32],
}

/// Initial state — this peer has its own identity keypair but no peer info
/// yet. Waiting for the server's PeerJoined/SessionJoined notification.
pub struct KeyExchangeState {
    pub my_ik: IdentityKeypair,
}

/// Post-`add_peer`, pre-`recv_x3dh` state — this peer has the counterpart's
/// identity pub, has generated its own X25519 ephemeral, and has emitted
/// (or is about to emit) an X3DHFrame::Init. Waiting for the peer's own
/// ephemeral to arrive so it can derive the session key.
pub struct SessionKeyState {
    pub my_ik: IdentityKeypair,
    pub my_ek: EphemeralKeypair,
    pub peer_ik: PublicKey,
}

/// Terminal state — both peers have exchanged ephemerals, the session_key
/// is derived, and the connection is ready to send/receive
/// `Envelope<InnerKeyKind, T>` app traffic. The send/recv counters are
/// initialized to zero here; envelope counter semantics: seal `increment`s
/// then stamps the incremented value into the envelope; open expects
/// strict-monotonic match.
pub struct EstablishedState {
    pub my_ik: IdentityKeypair,
    pub peer_ik: PublicKey,
    pub session_key: SessionKey,
    pub send_counter: EnvelopeCounter,
    pub recv_counter: EnvelopeCounter,
}

/// The state machine itself. Consumes `self` on each transition so
/// re-use of a superseded state can't compile.
pub enum PeerState {
    KeyExchange(KeyExchangeState),
    SessionKey(SessionKeyState),
    Established(EstablishedState),
}

impl PeerState {
    /// Boot the state machine with this peer's static identity keypair.
    pub fn new(my_ik: IdentityKeypair) -> Self {
        PeerState::KeyExchange(KeyExchangeState { my_ik })
    }

    /// KeyExchange → SessionKey.
    ///
    /// Called after the server delivers PeerJoined/SessionJoined and the
    /// caller has MAC-verified `peer_ik_bytes` against the URL-fragment
    /// `ShareKey`. Generates this side's ephemeral and returns the
    /// `X3DHFrame` (carrying own ephemeral pub) to wrap in an outer envelope
    /// and ship to the peer. Both peers fire their frame unconditionally
    /// on this transition; whoever's `recv_x3dh` fires first triggers
    /// derivation on that side.
    pub fn add_peer(self, peer_ik_bytes: [u8; 32]) -> Result<(Self, X3DHFrame), StateError> {
        let old = match self {
            PeerState::KeyExchange(s) => s,
            _ => return Err(StateError::InvalidTransition),
        };
        let my_ek = EphemeralKeypair::generate();
        let frame = X3DHFrame {
            ephemeral_pub: *my_ek.public.as_bytes(),
        };
        Ok((
            PeerState::SessionKey(SessionKeyState {
                my_ik: old.my_ik,
                my_ek,
                peer_ik: PublicKey::from(peer_ik_bytes),
            }),
            frame,
        ))
    }

    /// SessionKey → Established.
    ///
    /// Called when the peer's `X3DHFrame` arrives. Derives the session_key
    /// via the 3-DH X3DH derivation and transitions to Established. Nothing
    /// to send back — both peers already sent their frames from `add_peer`.
    pub fn recv_x3dh(
        self,
        frame: X3DHFrame,
        session_id: &SessionId,
    ) -> Result<Self, StateError> {
        let s = match self {
            PeerState::SessionKey(s) => s,
            _ => return Err(StateError::InvalidTransition),
        };
        let peer_ek = PublicKey::from(frame.ephemeral_pub);
        let session_key = derive_session_key(
            &s.my_ik,
            &s.my_ek,
            &s.peer_ik,
            &peer_ek,
            session_id,
        );
        Ok(PeerState::Established(EstablishedState {
            my_ik: s.my_ik,
            peer_ik: s.peer_ik,
            session_key,
            send_counter: EnvelopeCounter::default(),
            recv_counter: EnvelopeCounter::default(),
        }))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Simulate two peers running the full state machine and verify they
    /// derive bit-identical session keys.
    #[test]
    fn two_peers_key_exchange() {
        let session_id = SessionId([42u8; 32]);

        let ik_a = IdentityKeypair::generate();
        let ik_b = IdentityKeypair::generate();
        let ik_a_pub_bytes = *ik_a.public.as_bytes();
        let ik_b_pub_bytes = *ik_b.public.as_bytes();

        // Both start in KeyExchange.
        let state_a = PeerState::new(ik_a);
        let state_b = PeerState::new(ik_b);

        // Both add peer info, generating their ephemerals + X3DHFrames.
        let (state_a, frame_a) = state_a.add_peer(ik_b_pub_bytes).unwrap();
        let (state_b, frame_b) = state_b.add_peer(ik_a_pub_bytes).unwrap();

        assert!(matches!(state_a, PeerState::SessionKey(_)));
        assert!(matches!(state_b, PeerState::SessionKey(_)));

        // Each receives the other's frame → Established.
        let state_a = state_a.recv_x3dh(frame_b, &session_id).unwrap();
        let state_b = state_b.recv_x3dh(frame_a, &session_id).unwrap();

        let key_a = match state_a {
            PeerState::Established(ref s) => s.session_key.0,
            _ => panic!("A not Established"),
        };
        let key_b = match state_b {
            PeerState::Established(ref s) => s.session_key.0,
            _ => panic!("B not Established"),
        };

        assert_eq!(key_a, key_b, "both peers must derive identical session_key");
    }

    /// Full round-trip: complete X3DH, then A seals an app-level payload
    /// under the derived session_key and B opens it via its own counter.
    #[test]
    fn round_trip_envelope_via_session_key() {
        let session_id = SessionId([1u8; 32]);
        let ik_a = IdentityKeypair::generate();
        let ik_b = IdentityKeypair::generate();
        let ik_a_pub = *ik_a.public.as_bytes();
        let ik_b_pub = *ik_b.public.as_bytes();

        let (a, frame_a) = PeerState::new(ik_a).add_peer(ik_b_pub).unwrap();
        let (b, frame_b) = PeerState::new(ik_b).add_peer(ik_a_pub).unwrap();
        let a = a.recv_x3dh(frame_b, &session_id).unwrap();
        let b = b.recv_x3dh(frame_a, &session_id).unwrap();

        let mut a_est = match a {
            PeerState::Established(s) => s,
            _ => panic!("A not Established"),
        };
        let mut b_est = match b {
            PeerState::Established(s) => s,
            _ => panic!("B not Established"),
        };

        let payload: u64 = 12345;
        let env = Envelope::<InnerKeyKind, u64>::seal(
            &payload,
            &a_est.session_key,
            &mut a_est.send_counter,
            &session_id,
        )
        .unwrap();

        let recovered = env
            .open(&b_est.session_key, &session_id, &mut b_est.recv_counter)
            .unwrap();
        assert_eq!(recovered, 12345);
    }

    /// Attempting `recv_x3dh` before `add_peer` should reject with
    /// InvalidTransition — you can't advance past KeyExchange without
    /// setting peer info first.
    #[test]
    fn recv_before_add_peer_rejects() {
        let session_id = SessionId([0u8; 32]);
        let state = PeerState::new(IdentityKeypair::generate());
        let bogus_frame = X3DHFrame { ephemeral_pub: [0u8; 32] };
        let err = state.recv_x3dh(bogus_frame, &session_id);
        assert!(matches!(err, Err(StateError::InvalidTransition)));
    }
}


#[derive(Serialize)]
#[serde(rename = "Envelope")]
struct EnvelopeRef<'a> {
    counter: u32,
    nonce: [u8; 12],
    // #[serde(with = "serde_bytes")] // optional, see note below
    data: &'a [u8],
}

// Owned form for deserializing
#[derive(Deserialize)]
#[serde(rename = "Envelope")]
struct EnvelopeOwned {
    counter: u32,
    nonce: [u8; 12],
    // #[serde(with = "serde_bytes")] // optional, see note below
    data: Vec<u8>,
}
impl<KeyKind, T> Serialize for Envelope<KeyKind, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        EnvelopeRef {
            counter: self.counter,
            nonce: self.nonce,
            data: &self.data,
        }
        .serialize(serializer)
    }
}

impl<'de, KeyKind, T> Deserialize<'de> for Envelope<KeyKind, T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let EnvelopeOwned { counter, nonce, data } = EnvelopeOwned::deserialize(deserializer)?;
        Ok(Envelope {
            _k: PhantomData,
            _m: PhantomData,
            counter,
            nonce,
            data,
        })
    }
}
