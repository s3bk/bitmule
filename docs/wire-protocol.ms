## Tunable parameters:
 - BLOCK_SIZE: 2 MB
 - FRAME_SIZE: 64 kB

-> 1 GB has 2^14 frames = 2 kB state

Transfer -> chunk into blocks
chunk each block into frames

sender needs to maintain missing chunk set per receiver


## Relay protocol

The sender sends data to the relay and selects which receivers get the data via a bitmask that can be updated between each frame.

Receivers request new 

