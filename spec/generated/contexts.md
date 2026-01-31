# Packet context byte values (from SSOT)

| Value | Hex | ID | Meaning |
|-------|-----|----|---------|
| 0 | 0x00 | RNS.PKT.CONST.CTX_NONE | Context byte value 0 denotes generic data packet. |
| 1 | 0x01 | RNS.PKT.CONST.CTX_RESOURCE | Context byte value 1 denotes packet is part of a resource. |
| 2 | 0x02 | RNS.PKT.CONST.CTX_RESOURCE_ADV | Context byte value 2 denotes resource advertisement. |
| 3 | 0x03 | RNS.PKT.CONST.CTX_RESOURCE_REQ | Context byte value 3 denotes resource part request. |
| 4 | 0x04 | RNS.PKT.CONST.CTX_RESOURCE_HMU | Context byte value 4 denotes resource hashmap update. |
| 5 | 0x05 | RNS.PKT.CONST.CTX_RESOURCE_PRF | Context byte value 5 denotes resource proof. |
| 6 | 0x06 | RNS.PKT.CONST.CTX_RESOURCE_ICL | Context byte value 6 denotes resource initiator cancel. |
| 7 | 0x07 | RNS.PKT.CONST.CTX_RESOURCE_RCL | Context byte value 7 denotes resource receiver cancel. |
| 8 | 0x08 | RNS.PKT.CONST.CTX_CACHE_REQUEST | Context byte value 8 denotes cache request. |
| 9 | 0x09 | RNS.PKT.CONST.CTX_REQUEST | Context byte value 9 denotes request. |
| 10 | 0x0A | RNS.PKT.CONST.CTX_RESPONSE | Context byte value 10 denotes response to a request. |
| 11 | 0x0B | RNS.PKT.CONST.CTX_PATH_RESPONSE | Context byte value 11 denotes path response. |
| 12 | 0x0C | RNS.PKT.CONST.CTX_COMMAND | Context byte value 12 denotes command. |
| 13 | 0x0D | RNS.PKT.CONST.CTX_COMMAND_STATUS | Context byte value 13 denotes command status. |
| 14 | 0x0E | RNS.PKT.CONST.CTX_CHANNEL | Context byte value 14 denotes link channel data. |
| 250 | 0xFA | RNS.PKT.CONST.CTX_KEEPALIVE | Context byte value 250 denotes keepalive packet. |
| 251 | 0xFB | RNS.PKT.CONST.CTX_LINKIDENTIFY | Context byte value 251 denotes link peer identification proof. |
| 252 | 0xFC | RNS.PKT.CONST.CTX_LINKCLOSE | Context byte value 252 denotes link close message. |
| 253 | 0xFD | RNS.PKT.CONST.CTX_LINKPROOF | Context byte value 253 denotes link packet proof. |
| 254 | 0xFE | RNS.PKT.CONST.CTX_LRRTT | Context byte value 254 denotes link request round-trip time measurement. |
| 255 | 0xFF | RNS.PKT.CONST.CTX_LRPROOF | Context byte value 255 denotes link request proof. |
