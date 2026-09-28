C1 := client 1
C2 := client 2
R := relay

C1 -> R     GET /api/v0.1/pow-level
C1 -> R     connect to /api/v0.1/create?sid=abdefg&pow=42
              wire-version = v0.1
              session-id = abdefg
              pow=42
C1 -> R     send CreateSession
R -> C1     send SessionCreated

C2 -> R     connect to /api/v0.1/join?sid=abdefg
C2 -> R     send JoinSession
R -> C2     send SessionJoined
R -> C1     send PeerJoined

C1 & C2 generate their X3DH keys for the (C1, C2) connection

C1 -> R     send SendToX3DH
              dest_id = C2
              data=X3DH
R -> C2     send PeerMessageX3DH (data from C1)

C2 -> R     send SendToX3DH
                dest_id = C1
                data = X25519 ephemeral
R -> C1     send PeerMessageX3DH (data from C2)

C1 & C2     finish the X3DH handshake

The following messages are Peer2Peer tunneled though the relay via SendTo and recieved via PeerMessage

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
