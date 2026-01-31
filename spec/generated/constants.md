# Constants (from SSOT)

| ID | Value | Unit | Statement |
|----|-------|------|-----------|
| RNS.IFAC.CONST.IFAC_FLAG_BIT | 128 | byte mask | The IFAC-present flag is bit 7 of the flags byte; value 0x80 when IFAC is present. |
| RNS.IFAC.CONST.IFAC_SALT | adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8 | bytes | The IFAC key derivation uses a 32-byte salt with hex value adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8. |
| RNS.LNK.CONST.ECPUBSIZE | 64 | bytes | Link request/response key material is 64 bytes (Initiator X25519 32 + Ed25519 32). |
| RNS.LNK.CONST.KEEPALIVE_INITIATOR | 255 | byte | KEEPALIVE payload initiator to responder: single byte 0xFF. |
| RNS.LNK.CONST.KEEPALIVE_RESPONDER | 254 | byte | KEEPALIVE payload responder to initiator: single byte 0xFE. |
| RNS.LNK.CONST.LINK_MTU_SIZE | 3 | bytes | Signalling bytes are exactly 3 bytes on the wire. |
| RNS.LNK.CONST.MODE_BYTEMASK | 224 | byte mask | The mode value in signalling bytes occupies the top 3 bits of the first byte; the byte mask is 0xE0. |
| RNS.LNK.CONST.MTU_BYTEMASK | 2097151 | byte mask | The MTU value in signalling bytes is encoded in 21 bits; the byte mask for the MTU field is 0x1FFFFF. |
| RNS.PKT.CONST.AES128_BLOCKSIZE | 16 | bytes | AES block size is 16 bytes (used for padding and ciphertext alignment). |
| RNS.PKT.CONST.HASHLENGTH_BYTES | 32 | bytes | Full SHA-256 hash length is 32 bytes. |
| RNS.PKT.CONST.HEADER_MAXSIZE | 35 | bytes | The maximum packet header size is 35 bytes (flags, hops, transport_id, destination hash, context). |
| RNS.PKT.CONST.HEADER_MINSIZE | 19 | bytes | The minimum packet header size is 19 bytes (flags, hops, destination hash, context). |
| RNS.PKT.CONST.KEYSIZE_BYTES | 64 | bytes | Identity public and private key format is 64 bytes (X25519 32 + Ed25519 32). |
| RNS.PKT.CONST.NAME_HASH_LENGTH_BYTES | 10 | bytes | Name hash and announce random hash are 10 bytes (NAME_HASH_LENGTH//8). |
| RNS.PKT.CONST.RATCHETSIZE_BYTES | 32 | bytes | Ratchet public key is 32 bytes (RATCHETSIZE//8). |
| RNS.PKT.CONST.SIGLENGTH_BYTES | 64 | bytes | Ed25519 signature length is 64 bytes. |
| RNS.PKT.CONST.TOKEN_OVERHEAD | 48 | bytes | Token overhead is 48 bytes (IV 16 + HMAC 32). |
| RNS.PKT.CONST.TRANSPORT_BROADCAST | 0 | byte | Flags byte bit 4 value 0 denotes BROADCAST transport type on the wire. |
| RNS.PKT.CONST.TRANSPORT_TRANSPORT | 1 | byte | Flags byte bit 4 value 1 denotes TRANSPORT transport type on the wire. |
| RNS.RES.CONST.MAPHASH_LEN | 4 | bytes | Resource map hash (part hash) is 4 bytes; first 4 bytes of full_hash(part_data+random_hash). |
| RNS.TRN.CONST.DST_LEN | 16 | bytes | Destination hash, transport id, and link_id are 16 bytes (TRUNCATED_HASHLENGTH//8). |
| RNS.TRN.CONST.IFAC_MIN_SIZE | 1 | bytes | Minimum IFAC payload length is 1 byte; interface.ifac_size defines actual length. |
| RNS.TRN.CONST.MDU | 464 | bytes | MDU (maximum data unit) is MTU minus HEADER_MAXSIZE and IFAC_MIN_SIZE; maximum plaintext in a single packet before encryption overhead. |
| RNS.TRN.CONST.MTU_DEFAULT | 500 | bytes | Default physical-layer MTU is 500 bytes; the wire packet length MUST NOT exceed the applicable MTU (interface or link). |
