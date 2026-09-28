## Tunable parameters:
 - BLOCK_SIZE: 2 MB - 32 MB (adjustable)
 - FRAME_SIZE: <= 64 kB (in practice 60kB + tags)

 (when using fountain codes)
 - SYMBOL_SIZE: 8 kB (fixed)
 - 8kB data + 3 bytes symbol_id ?

-> 1 GB has 2^14 frames = 2 kB state

## Blocks, frames, symbols
Transfer -> chunk into blocks
chunk each block into frames
in fountain mode each frame contains multiple symbols

sender needs to maintain missing chunk set per receiver


## Relay protocol

The sender sends data to the relay and selects which receivers get the data via a bitmask that can be updated between each frame.

Receivers request new


## Raptor mode

- Encoder cheap to create
- first send encoder.source_packets()
- don't send payload_id (always 1)

### after first round:
- encoder.repair_start(repair_start, repair_packets_per_block)
- keep track of how many repair packets send for next 'repair_start'

modify `Encoder::source_packets` and `Encoder::repair_start` to write directly into output buffer


### Decoder
- write first N symbols (256) into SymbolSlab
- if all recieved, write directly to output, no decode needed
- otherwise record partial state separately
- in subsequent iteration write recovery symbols into gaps of SymbolSlab
- if >N symbols received but no recovery yet, store extra symbols elsewhere