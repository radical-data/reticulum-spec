# Constants (from SSOT)

| ID | Value | Unit | Statement |
|----|-------|------|-----------|
| RNS.IFAC.CONST.IFAC_FLAG_BIT | 128 | byte mask | The IFAC-present flag is bit 7 of the flags byte; value 0x80 when IFAC is present. |
| RNS.IFAC.CONST.IFAC_SALT | adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8 | bytes | The IFAC key derivation uses a 32-byte salt with hex value adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8. |
| RNS.LNK.CONST.LINK_MTU_SIZE | 3 | bytes | Signalling bytes are exactly 3 bytes on the wire. |
| RNS.LNK.CONST.MODE_BYTEMASK | 224 | byte mask | The mode value in signalling bytes occupies the top 3 bits of the first byte; the byte mask is 0xE0. |
| RNS.LNK.CONST.MTU_BYTEMASK | 2097151 | byte mask | The MTU value in signalling bytes is encoded in 21 bits; the byte mask for the MTU field is 0x1FFFFF. |
| RNS.PKT.CONST.HEADER_MAXSIZE | 35 | bytes | The maximum packet header size is 35 bytes (flags, hops, transport_id, destination hash, context). |
| RNS.PKT.CONST.HEADER_MINSIZE | 19 | bytes | The minimum packet header size is 19 bytes (flags, hops, destination hash, context). |
