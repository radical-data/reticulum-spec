# Traceability (atoms → references)

## RNS.PKT.LAYOUT.HEADER_1
- RNS/Packet.py `unpack` lines 241-272 (definition)
- RNS/Packet.py `pack` lines 176-235 (implementation)

## RNS.PKT.LAYOUT.HEADER_2
- RNS/Packet.py `unpack` lines 241-272 (definition)

## RNS.PKT.CONST.HEADER_MINSIZE
- RNS/Reticulum.py `HEADER_MINSIZE` lines 147-154 (definition)

## RNS.PKT.CONST.HEADER_MAXSIZE
- RNS/Reticulum.py `HEADER_MAXSIZE` lines 147-154 (definition)

## RNS.PKT.ALG.FLAGS_PACK_UNPACK
- RNS/Packet.py `get_packed_flags` lines 168-174 (implementation)
- RNS/Packet.py `unpack` lines 241-252 (implementation)

## RNS.PKT.ALG.HASHABLE_PART
- RNS/Packet.py `get_hashable_part` lines 353-359 (definition)

## RNS.PKT.ALG.TRUNCATED_HASH
- RNS/Identity.py `truncated_hash` lines 247-256 (definition)
- RNS/Identity.py `full_hash` lines 238-246 (derivation)

## RNS.LNK.ALG.LINK_ID_FROM_LINKREQUEST
- RNS/Link.py `link_id_from_lr_packet` lines 340-346 (definition)

## RNS.LNK.CONST.LINK_MTU_SIZE
- RNS/Link.py `LINK_MTU_SIZE` lines 78-81 (definition)

## RNS.LNK.CONST.MTU_BYTEMASK
- RNS/Link.py `MTU_BYTEMASK` lines 144-145 (definition)

## RNS.LNK.CONST.MODE_BYTEMASK
- RNS/Link.py `MODE_BYTEMASK` lines 144-145 (definition)

## RNS.LNK.ALG.SIGNALLING_ENCODE
- RNS/Link.py `signalling_bytes` lines 146-150 (definition)

## RNS.LNK.ALG.SIGNALLING_DECODE
- RNS/Link.py `mtu_from_lr_packet` lines 152-156 (implementation)
- RNS/Link.py `mode_from_lr_packet` lines 172-176 (implementation)

## RNS.IFAC.CONST.IFAC_FLAG_BIT
- RNS/Transport.py `new_header` lines 907-912 (implementation)

## RNS.IFAC.CONST.IFAC_SALT
- RNS/Reticulum.py `IFAC_SALT` lines 147-154 (definition)

## RNS.IFAC.ALG.OUTBOUND_INSERT_AND_MASK
- RNS/Transport.py `transmit` lines 894-928 (implementation)

## RNS.IFAC.ALG.INBOUND_UNMASK_AND_VERIFY
- RNS/Transport.py `inbound` lines 1241-1295 (implementation)

## RNS.PKT.CONST.CTX_NONE
- RNS/Packet.py `NONE` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_RESOURCE
- RNS/Packet.py `RESOURCE` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_RESOURCE_ADV
- RNS/Packet.py `RESOURCE_ADV` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_RESOURCE_REQ
- RNS/Packet.py `RESOURCE_REQ` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_RESOURCE_HMU
- RNS/Packet.py `RESOURCE_HMU` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_RESOURCE_PRF
- RNS/Packet.py `RESOURCE_PRF` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_RESOURCE_ICL
- RNS/Packet.py `RESOURCE_ICL` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_RESOURCE_RCL
- RNS/Packet.py `RESOURCE_RCL` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_CACHE_REQUEST
- RNS/Packet.py `CACHE_REQUEST` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_REQUEST
- RNS/Packet.py `REQUEST` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_RESPONSE
- RNS/Packet.py `RESPONSE` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_PATH_RESPONSE
- RNS/Packet.py `PATH_RESPONSE` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_COMMAND
- RNS/Packet.py `COMMAND` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_COMMAND_STATUS
- RNS/Packet.py `COMMAND_STATUS` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_CHANNEL
- RNS/Packet.py `CHANNEL` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_KEEPALIVE
- RNS/Packet.py `KEEPALIVE` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_LINKIDENTIFY
- RNS/Packet.py `LINKIDENTIFY` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_LINKCLOSE
- RNS/Packet.py `LINKCLOSE` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_LINKPROOF
- RNS/Packet.py `LINKPROOF` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_LRRTT
- RNS/Packet.py `LRRTT` lines 71-92 (definition)

## RNS.PKT.CONST.CTX_LRPROOF
- RNS/Packet.py `LRPROOF` lines 71-92 (definition)

## RNS.TRN.CONST.MTU_DEFAULT
- RNS/Reticulum.py `MTU` lines 89-95 (definition)

## RNS.TRN.CONST.DST_LEN
- RNS/Reticulum.py `TRUNCATED_HASHLENGTH` lines 147-154 (definition)

## RNS.TRN.CONST.IFAC_MIN_SIZE
- RNS/Reticulum.py `IFAC_MIN_SIZE` lines 147-154 (definition)

## RNS.TRN.CONST.MDU
- RNS/Reticulum.py `MDU` lines 147-154 (definition)

## RNS.PKT.CONST.KEYSIZE_BYTES
- RNS/Identity.py `KEYSIZE` lines 59-89 (definition)

## RNS.PKT.CONST.SIGLENGTH_BYTES
- RNS/Identity.py `SIGLENGTH` lines 59-89 (definition)

## RNS.PKT.CONST.HASHLENGTH_BYTES
- RNS/Identity.py `HASHLENGTH` lines 59-89 (definition)

## RNS.PKT.CONST.RATCHETSIZE_BYTES
- RNS/Identity.py `RATCHETSIZE` lines 59-89 (definition)

## RNS.PKT.CONST.NAME_HASH_LENGTH_BYTES
- RNS/Identity.py `NAME_HASH_LENGTH` lines 59-89 (definition)

## RNS.PKT.CONST.TOKEN_OVERHEAD
- RNS/Cryptography/Token.py `TOKEN_OVERHEAD` lines 48-52 (definition)

## RNS.PKT.CONST.AES128_BLOCKSIZE
- RNS/Identity.py `AES128_BLOCKSIZE` lines 59-89 (definition)

## RNS.RES.CONST.MAPHASH_LEN
- RNS/Resource.py `MAPHASH_LEN` lines 100-106 (definition)

## RNS.LNK.CONST.ECPUBSIZE
- RNS/Link.py `ECPUBSIZE` lines 70-80 (definition)

## RNS.PKT.ALG.DESTINATION_HASH_FROM_NAME
- RNS/Destination.py `hash` lines 96-130 (definition)

## RNS.PKT.CONST.TRANSPORT_BROADCAST
- RNS/Transport.py `BROADCAST` lines 49-54 (definition)

## RNS.PKT.CONST.TRANSPORT_TRANSPORT
- RNS/Transport.py `TRANSPORT` lines 49-54 (definition)

## RNS.TRN.BEHAV.HDLC_FRAMING
- RNS/Interfaces/TCPInterface.py `HDLC` lines 44-53 (definition)

## RNS.TRN.BEHAV.KISS_FRAMING
- RNS/Interfaces/TCPInterface.py `KISS` lines 55-66 (definition)
- RNS/Interfaces/KISSInterface.py `KISS` lines 38-57 (implementation)

## RNS.TRN.BEHAV.RAW_UDP
- RNS/Interfaces/UDPInterface.py `UDPInterface` lines 40-46 (definition)

## RNS.PKT.RULE.WELLFORMED_PACKET
- RNS/Transport.py `inbound` lines 1241-1250 (implementation)

## RNS.PKT.RULE.UNKNOWN_CONTEXT_OPAQUE
- RNS/Transport.py `inbound` lines 1241-1250 (dispatch)

## RNS.PKT.LAYOUT.PROOF_EXPLICIT
- RNS/Packet.py `EXPL_LENGTH` lines 413-414 (definition)

## RNS.PKT.LAYOUT.PROOF_IMPLICIT
- RNS/Packet.py `IMPL_LENGTH` lines 413-414 (definition)

## RNS.LNK.LAYOUT.LINKREQUEST_PAYLOAD
- RNS/Link.py `ECPUBSIZE` lines 70-80 (definition)

## RNS.LNK.LAYOUT.LINKPROOF_PAYLOAD
- RNS/Link.py `prove` lines 371-377 (definition)

## RNS.LNK.ALG.LINKPROOF_SIGNED_DATA
- RNS/Link.py `prove` lines 371-377 (implementation)

## RNS.PKT.LAYOUT.TOKEN
- RNS/Cryptography/Token.py `TOKEN_OVERHEAD` lines 48-52 (definition)

## RNS.PKT.ALG.SINGLE_ENCRYPTION
- RNS/Identity.py `encrypt` lines 668-690 (implementation)

## RNS.LNK.ALG.LINK_ENCRYPTION
- RNS/Link.py `encrypt` lines 1191-1210 (implementation)

## RNS.PKT.LAYOUT.ANNOUNCE_WITH_RATCHET
- RNS/Identity.py `validate_announce` lines 391-424 (definition)

## RNS.PKT.LAYOUT.ANNOUNCE_WITHOUT_RATCHET
- RNS/Identity.py `validate_announce` lines 391-424 (definition)

## RNS.LNK.CONST.KEEPALIVE_INITIATOR
- RNS/Link.py `KEEPALIVE` lines 850-856 (implementation)

## RNS.LNK.CONST.KEEPALIVE_RESPONDER
- RNS/Link.py `KEEPALIVE` lines 1151-1158 (implementation)

## RNS.LNK.LAYOUT.LINKCLOSE_PAYLOAD
- RNS/Link.py `LINKCLOSE` lines 693-698 (implementation)

## RNS.LNK.LAYOUT.LINKIDENTIFY_PAYLOAD
- RNS/Link.py `LINKIDENTIFY` lines 469-476 (implementation)

## RNS.CHN.LAYOUT.CHANNEL_ENVELOPE
- RNS/Channel.py `pack` lines 179-197 (definition)

## RNS.TRN.LAYOUT.PATH_REQUEST_CLIENT
- RNS/Transport.py `path_request_handler` lines 2646-2672 (implementation)

## RNS.TRN.LAYOUT.PATH_REQUEST_TRANSPORT
- RNS/Transport.py `path_request_handler` lines 2646-2672 (implementation)

## RNS.TRN.LAYOUT.TUNNEL_SYNTHESIS
- RNS/Transport.py `synthesize_tunnel` lines 2120-2132 (implementation)

## RNS.RES.LAYOUT.RESOURCE_ADV
- RNS/Resource.py `ResourceAdvertisement` lines 1312-1338 (definition)

## RNS.RES.LAYOUT.RESOURCE_REQ
- RNS/Resource.py `request_next` lines 918-952 (implementation)

## RNS.RES.LAYOUT.RESOURCE_HMU
- RNS/Resource.py `request` lines 970-1047 (implementation)

## RNS.RES.LAYOUT.RESOURCE_PRF
- RNS/Resource.py `prove` lines 739-748 (implementation)

## RNS.IFAC.ALG.IFAC_KEY_DERIVATION
- RNS/Reticulum.py `ifac_key` lines 819-826 (implementation)
