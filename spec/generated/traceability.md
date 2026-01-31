# Traceability (atoms → references)

## RNS.PKT.LAYOUT.HEADER_1
- RNS/Packet.py `unpack` lines 241-272 (definition) @ 286a78e
- RNS/Packet.py `pack` lines 176-235 (implementation) @ 286a78e

## RNS.PKT.LAYOUT.HEADER_2
- RNS/Packet.py `unpack` lines 241-272 (definition) @ 286a78e

## RNS.PKT.CONST.HEADER_MINSIZE
- RNS/Reticulum.py `HEADER_MINSIZE` lines 147-154 (definition) @ 286a78e

## RNS.PKT.CONST.HEADER_MAXSIZE
- RNS/Reticulum.py `HEADER_MAXSIZE` lines 147-154 (definition) @ 286a78e

## RNS.PKT.ALG.FLAGS_PACK_UNPACK
- RNS/Packet.py `get_packed_flags` lines 168-174 (implementation) @ 286a78e
- RNS/Packet.py `unpack` lines 241-252 (implementation) @ 286a78e

## RNS.PKT.ALG.HASHABLE_PART
- RNS/Packet.py `get_hashable_part` lines 353-359 (definition) @ 286a78e

## RNS.PKT.ALG.TRUNCATED_HASH
- RNS/Identity.py `truncated_hash` lines 247-256 (definition) @ 286a78e
- RNS/Identity.py `full_hash` lines 238-246 (derivation) @ 286a78e

## RNS.LNK.ALG.LINK_ID_FROM_LINKREQUEST
- RNS/Link.py `link_id_from_lr_packet` lines 340-346 (definition) @ 286a78e

## RNS.LNK.CONST.LINK_MTU_SIZE
- RNS/Link.py `LINK_MTU_SIZE` lines 78-81 (definition) @ 286a78e

## RNS.LNK.CONST.MTU_BYTEMASK
- RNS/Link.py `MTU_BYTEMASK` lines 144-145 (definition) @ 286a78e

## RNS.LNK.CONST.MODE_BYTEMASK
- RNS/Link.py `MODE_BYTEMASK` lines 144-145 (definition) @ 286a78e

## RNS.LNK.ALG.SIGNALLING_ENCODE
- RNS/Link.py `signalling_bytes` lines 146-150 (definition) @ 286a78e

## RNS.LNK.ALG.SIGNALLING_DECODE
- RNS/Link.py `mtu_from_lr_packet` lines 152-156 (implementation) @ 286a78e
- RNS/Link.py `mode_from_lr_packet` lines 172-176 (implementation) @ 286a78e

## RNS.IFAC.CONST.IFAC_FLAG_BIT
- RNS/Transport.py `new_header` lines 907-912 (implementation) @ 286a78e

## RNS.IFAC.CONST.IFAC_SALT
- RNS/Reticulum.py `IFAC_SALT` lines 147-154 (definition) @ 286a78e

## RNS.IFAC.ALG.OUTBOUND_INSERT_AND_MASK
- RNS/Transport.py `transmit` lines 894-928 (implementation) @ 286a78e

## RNS.IFAC.ALG.INBOUND_UNMASK_AND_VERIFY
- RNS/Transport.py `inbound` lines 1241-1295 (implementation) @ 286a78e

## RNS.PKT.CONST.CTX_NONE
- RNS/Packet.py `NONE` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_RESOURCE
- RNS/Packet.py `RESOURCE` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_RESOURCE_ADV
- RNS/Packet.py `RESOURCE_ADV` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_RESOURCE_REQ
- RNS/Packet.py `RESOURCE_REQ` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_RESOURCE_HMU
- RNS/Packet.py `RESOURCE_HMU` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_RESOURCE_PRF
- RNS/Packet.py `RESOURCE_PRF` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_RESOURCE_ICL
- RNS/Packet.py `RESOURCE_ICL` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_RESOURCE_RCL
- RNS/Packet.py `RESOURCE_RCL` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_CACHE_REQUEST
- RNS/Packet.py `CACHE_REQUEST` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_REQUEST
- RNS/Packet.py `REQUEST` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_RESPONSE
- RNS/Packet.py `RESPONSE` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_PATH_RESPONSE
- RNS/Packet.py `PATH_RESPONSE` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_COMMAND
- RNS/Packet.py `COMMAND` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_COMMAND_STATUS
- RNS/Packet.py `COMMAND_STATUS` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_CHANNEL
- RNS/Packet.py `CHANNEL` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_KEEPALIVE
- RNS/Packet.py `KEEPALIVE` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_LINKIDENTIFY
- RNS/Packet.py `LINKIDENTIFY` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_LINKCLOSE
- RNS/Packet.py `LINKCLOSE` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_LINKPROOF
- RNS/Packet.py `LINKPROOF` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_LRRTT
- RNS/Packet.py `LRRTT` lines 71-92 (definition) @ 286a78e

## RNS.PKT.CONST.CTX_LRPROOF
- RNS/Packet.py `LRPROOF` lines 71-92 (definition) @ 286a78e
