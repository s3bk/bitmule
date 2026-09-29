C1 := client 1
C2 := client 2
R := relay

C1 -> R     GET /api/v0.1/pow/challenge
              returns level, magic
C1          generate reconnect token and solve
            HASH(session_id, reconnect_token, magic, nonce).leading_zeros() == level
            
C1 -> R     connect to /api/v0.1/create?sid=abdefg&pow=42&token=deadcat
              server verifies POW before the websocket handshake

C1 -> R     send CreateSession
              id (our id, randomly generated)
              capabilities (relay + SDP optional)
              pub_key (our public key, valid for this sid)
              mac (proof that we know the share key)
R -> C1     send SessionCreated

C2 -> R     connect to /api/v0.1/join?sid=abdefg
C2 -> R     send JoinSession
              id (our id, randomly generated)
              capabilities (relay + SDP optional)
              pub_key (our public key, valid for this sid)
              mac (proof that we know the share key)
R -> C2     send SessionJoined
              C2 now knows C1's id, caps, pub_key and has verfied mac
R -> C1     send PeerJoined
              C1 now knows C2's id, caps, pub_key and has verfied mac

C1 & C2     generate their ECDH keys for the (C1, C2) connection

C1 -> R     send SendTo1
              dest_id = C2
              data = X25519 ephemeral
R -> C2     send PeerMessage1 (data from C1)

C2 -> R     send SendTo1
                dest_id = C1
                data = X25519 ephemeral
R -> C1     send PeerMessage1 (data from C2)

C1 & C2     finish the ECDH handshake and compute the new encryption keys

The following messages are Peer2Peer tunneled though the relay via SendTo and recieved via PeerMessage2

C1 -> C2    send Manifest
C2          decides to initiate SDP or not.

C2 -> C1    send Get start=0, end=file_size
C1          connects to relay server as sender
C1 -> C2    JoinRelay
C2          connect to relay server as receiver
C1          begins sending data to relay

If both peers have SDP enabled, they start SDP discovery via websocket at the same time.

If a SDP channel is established
C2 -> C1 (via SDP)  Get (remaining range)
C1 -> C2 (via SDP)  InlineData
