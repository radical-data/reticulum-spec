# Layouts (from SSOT)

## RNS.PKT.LAYOUT.HEADER_1
HEADER_1 packets have byte 0 as flags, byte 1 as hops, bytes 2 through 17 as destination hash (16 bytes), and byte 18 as context; total minimum header 19 bytes.
| Field | Offset | Length |
|-------|--------|--------|
| flags | 0 | 1 |
| hops | 1 | 1 |
| destination_hash | 2 | 16 |
| context | 18 | 1 |

## RNS.PKT.LAYOUT.HEADER_2
HEADER_2 packets have byte 0 as flags, byte 1 as hops, bytes 2 through 17 as transport_id, bytes 18 through 33 as destination hash, and byte 34 as context; total minimum header 35 bytes.
| Field | Offset | Length |
|-------|--------|--------|
| flags | 0 | 1 |
| hops | 1 | 1 |
| transport_id | 2 | 16 |
| destination_hash | 18 | 16 |
| context | 34 | 1 |
