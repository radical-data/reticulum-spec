# Reticulum Wire Format (generated from SSOT)

## RNS.PKT.LAYOUT.HEADER_1
- **Kind:** layout
- **Normative:** MUST
- **Statement:** HEADER_1 packets have byte 0 as flags, byte 1 as hops, bytes 2 through 17 as destination hash (16 bytes), and byte 18 as context; total minimum header 19 bytes.
- **References:**
  - RNS/Packet.py (unpack) lines 241-272 @ 286a78e
  - RNS/Packet.py (pack) lines 176-235 @ 286a78e
- **Layout fields:**
  - flags: offset 0, length 1
  - hops: offset 1, length 1
  - destination_hash: offset 2, length 16
  - context: offset 18, length 1

## RNS.PKT.LAYOUT.HEADER_2
- **Kind:** layout
- **Normative:** MUST
- **Statement:** HEADER_2 packets have byte 0 as flags, byte 1 as hops, bytes 2 through 17 as transport_id, bytes 18 through 33 as destination hash, and byte 34 as context; total minimum header 35 bytes.
- **References:**
  - RNS/Packet.py (unpack) lines 241-272 @ 286a78e
- **Layout fields:**
  - flags: offset 0, length 1
  - hops: offset 1, length 1
  - transport_id: offset 2, length 16
  - destination_hash: offset 18, length 16
  - context: offset 34, length 1

## RNS.PKT.CONST.HEADER_MINSIZE
- **Kind:** constant
- **Normative:** MUST
- **Statement:** The minimum packet header size is 19 bytes (flags, hops, destination hash, context).
- **References:**
  - RNS/Reticulum.py (HEADER_MINSIZE) lines 147-154 @ 286a78e
- **Value:** {'number': 19, 'unit': 'bytes'}

## RNS.PKT.CONST.HEADER_MAXSIZE
- **Kind:** constant
- **Normative:** MUST
- **Statement:** The maximum packet header size is 35 bytes (flags, hops, transport_id, destination hash, context).
- **References:**
  - RNS/Reticulum.py (HEADER_MAXSIZE) lines 147-154 @ 286a78e
- **Value:** {'number': 35, 'unit': 'bytes'}

## RNS.PKT.ALG.FLAGS_PACK_UNPACK
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** The flags byte is packed and unpacked as follows: bit 7 IFAC-present (0x80, see RNS.IFAC.CONST.IFAC_FLAG_BIT); bit 6 header type (0=HEADER_1, 1=HEADER_2); bit 5 context flag; bit 4 transport type; bits 3-2 destination type; bits 1-0 packet type. When packing from packet fields, the IFAC bit is not set by the packet layer; transport sets bit 7 on the wire when IFAC is present.
- **References:**
  - RNS/Packet.py (get_packed_flags) lines 168-174 @ 286a78e
  - RNS/Packet.py (unpack) lines 241-252 @ 286a78e
- **Steps:**
  - Header type is (flags & 0b01000000) >> 6 (bit 6 only; bit 7 is IFAC).
  - Context flag is (flags & 0b00100000) >> 5.
  - Transport type is (flags & 0b00010000) >> 4.
  - Destination type is (flags & 0b00001100) >> 2.
  - Packet type is (flags & 0b00000011).
  - When packing canonical flags (without IFAC), flags = (header_type << 6) | (context_flag << 5) | (transport_type << 4) | (destination_type << 2) | packet_type. Set bit 7 only when emitting IFAC-protected packets on the wire.

## RNS.PKT.ALG.HASHABLE_PART
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** The hashable part is used for packet and link hashes. Byte 0 (flags) is masked to 0x0F; byte 1 (hops) is excluded. For HEADER_1 the remainder is raw[2:]; for HEADER_2 the remainder is raw[18:] (skipping transport_id bytes 2..17).
- **References:**
  - RNS/Packet.py (get_hashable_part) lines 353-359 @ 286a78e
- **Steps:**
  - Let b0 = raw[0] & 0x0F (canonical flags low nibble; excludes header-type and IFAC bits).
  - If header_type is HEADER_2, hashable_part = b0 || raw[18:] (bytes [2..18) are transport_id, excluded).
  - Else (HEADER_1), hashable_part = b0 || raw[2:] (bytes [0,1] are flags and hops; hops excluded).
  - Return hashable_part.

## RNS.PKT.ALG.TRUNCATED_HASH
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** The truncated hash is the first 16 bytes of the SHA-256 hash of the input.
- **References:**
  - RNS/Identity.py (truncated_hash) lines 247-256 @ 286a78e
  - RNS/Identity.py (full_hash) lines 238-246 @ 286a78e
- **Steps:**
  - Compute full_hash = SHA-256(data).
  - Return full_hash[0:(TRUNCATED_HASHLENGTH//8)]; TRUNCATED_HASHLENGTH is 128 bits.

## RNS.LNK.ALG.LINK_ID_FROM_LINKREQUEST
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** Link ID is the truncated hash (first 16 bytes of SHA-256) of the hashable part with signalling bytes stripped when payload length exceeds 64 bytes.
- **References:**
  - RNS/Link.py (link_id_from_lr_packet) lines 340-346 @ 286a78e
- **Steps:**
  - Obtain hashable_part = packet.get_hashable_part().
  - If len(packet.data) > ECPUBSIZE (64), set hashable_part = hashable_part[:-diff] where diff = len(packet.data) - ECPUBSIZE.
  - Return RNS.Identity.truncated_hash(hashable_part).

## RNS.LNK.CONST.LINK_MTU_SIZE
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Signalling bytes are exactly 3 bytes on the wire.
- **References:**
  - RNS/Link.py (LINK_MTU_SIZE) lines 78-81 @ 286a78e
- **Value:** {'number': 3, 'unit': 'bytes'}

## RNS.LNK.CONST.MTU_BYTEMASK
- **Kind:** constant
- **Normative:** MUST
- **Statement:** The MTU value in signalling bytes is encoded in 21 bits; the byte mask for the MTU field is 0x1FFFFF.
- **References:**
  - RNS/Link.py (MTU_BYTEMASK) lines 144-145 @ 286a78e
- **Value:** {'number': 2097151, 'unit': 'byte mask', 'format': '0x1FFFFF', 'max_reasonable': 2097151}

## RNS.LNK.CONST.MODE_BYTEMASK
- **Kind:** constant
- **Normative:** MUST
- **Statement:** The mode value in signalling bytes occupies the top 3 bits of the first byte; the byte mask is 0xE0.
- **References:**
  - RNS/Link.py (MODE_BYTEMASK) lines 144-145 @ 286a78e
- **Value:** {'number': 224, 'unit': 'byte mask', 'format': '0xE0'}

## RNS.LNK.ALG.SIGNALLING_ENCODE
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** Signalling bytes encode MTU (21 bits) and mode (3 bits) as three big-endian bytes; byte0 = (mode<<5)|(MTU>>16), byte1 = (MTU>>8)&0xFF, byte2 = MTU&0xFF.
- **References:**
  - RNS/Link.py (signalling_bytes) lines 146-150 @ 286a78e
- **Steps:**
  - Pack signalling_value = (mtu & MTU_BYTEMASK) + (((mode<<5) & MODE_BYTEMASK)<<16).
  - Pack as big-endian 32-bit unsigned integer and take bytes [1:4] (drop high byte).
  - Return the 3-byte sequence.

## RNS.LNK.ALG.SIGNALLING_DECODE
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** Signalling bytes decode as mode = (byte0>>5)&0x07 and MTU = ((byte0&0x1F)<<16)|(byte1<<8)|byte2.
- **References:**
  - RNS/Link.py (mtu_from_lr_packet) lines 152-156 @ 286a78e
  - RNS/Link.py (mode_from_lr_packet) lines 172-176 @ 286a78e
- **Steps:**
  - Mode is (first_byte & MODE_BYTEMASK) >> 5.
  - MTU is (byte0<<16 + byte1<<8 + byte2) & MTU_BYTEMASK.

## RNS.IFAC.CONST.IFAC_FLAG_BIT
- **Kind:** constant
- **Normative:** MUST
- **Statement:** The IFAC-present flag is bit 7 of the flags byte; value 0x80 when IFAC is present.
- **References:**
  - RNS/Transport.py (new_header) lines 907-912 @ 286a78e
- **Value:** {'number': 128, 'unit': 'byte mask', 'format': '0x80'}

## RNS.IFAC.CONST.IFAC_SALT
- **Kind:** constant
- **Normative:** MUST
- **Statement:** The IFAC key derivation uses a 32-byte salt with hex value adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8.
- **References:**
  - RNS/Reticulum.py (IFAC_SALT) lines 147-154 @ 286a78e
- **Value:** {'number': 'adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8', 'unit': 'bytes', 'format': 'hex'}

## RNS.IFAC.ALG.OUTBOUND_INSERT_AND_MASK
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** Outbound IFAC: sign raw packet, take last ifac_size bytes as IFAC, insert after byte 1, set bit 7 of byte 0, then mask with HKDF-derived mask. Mask bytes [0], [1], and [2+ifac_size .. end); do not mask bytes [2 .. 2+ifac_size) (the IFAC bytes).
- **References:**
  - RNS/Transport.py (transmit) lines 894-928 @ 286a78e
- **Steps:**
  - IFAC = sign(raw)[-ifac_size:].
  - new_header = (raw[0]|0x80, raw[1]); new_raw = new_header + ifac + raw[2:] (layout: [0]=flags|0x80, [1]=hops, [2..2+ifac_size)=IFAC, [2+ifac_size..end)=payload).
  - mask = HKDF(length=len(new_raw), derive_from=ifac, salt=ifac_key, context=None).
  - Mask bytes at indices [0], [1], and [2+ifac_size .. len(new_raw)); do not mask [2 .. 2+ifac_size). Byte 0 after XOR: (new_raw[0]^mask[0])|0x80; all other masked bytes: new_raw[i]^mask[i].

## RNS.IFAC.ALG.INBOUND_UNMASK_AND_VERIFY
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** Inbound packets with IFAC flag set: extract IFAC from raw[2..2+ifac_size), derive mask, unmask bytes [0], [1], and [2+ifac_size .. end); leave [2 .. 2+ifac_size) unchanged. Reassemble canonical raw and verify IFAC equals sign(canonical_raw)[-ifac_size:].
- **References:**
  - RNS/Transport.py (inbound) lines 1241-1295 @ 286a78e
- **Steps:**
  - If raw[0]&0x80 != 0x80 or len(raw) <= 2+ifac_size, drop packet.
  - ifac = raw[2:2+ifac_size]; mask = HKDF(length=len(raw), derive_from=ifac, salt=ifac_key, context=None).
  - Unmask bytes at indices [0], [1], and [2+ifac_size .. len(raw)); do not unmask [2 .. 2+ifac_size).
  - canonical_raw = (raw[0]&0x7f, raw[1]) + raw[2+ifac_size:] (IFAC bit cleared, IFAC bytes removed).
  - expected_ifac = sign(canonical_raw)[-ifac_size:]; accept iff ifac == expected_ifac.

## RNS.PKT.CONST.CTX_NONE
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 0 denotes generic data packet.
- **References:**
  - RNS/Packet.py (NONE) lines 71-92 @ 286a78e
- **Value:** {'number': 0, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 1 denotes packet is part of a resource.
- **References:**
  - RNS/Packet.py (RESOURCE) lines 71-92 @ 286a78e
- **Value:** {'number': 1, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE_ADV
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 2 denotes resource advertisement.
- **References:**
  - RNS/Packet.py (RESOURCE_ADV) lines 71-92 @ 286a78e
- **Value:** {'number': 2, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE_REQ
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 3 denotes resource part request.
- **References:**
  - RNS/Packet.py (RESOURCE_REQ) lines 71-92 @ 286a78e
- **Value:** {'number': 3, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE_HMU
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 4 denotes resource hashmap update.
- **References:**
  - RNS/Packet.py (RESOURCE_HMU) lines 71-92 @ 286a78e
- **Value:** {'number': 4, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE_PRF
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 5 denotes resource proof.
- **References:**
  - RNS/Packet.py (RESOURCE_PRF) lines 71-92 @ 286a78e
- **Value:** {'number': 5, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE_ICL
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 6 denotes resource initiator cancel.
- **References:**
  - RNS/Packet.py (RESOURCE_ICL) lines 71-92 @ 286a78e
- **Value:** {'number': 6, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE_RCL
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 7 denotes resource receiver cancel.
- **References:**
  - RNS/Packet.py (RESOURCE_RCL) lines 71-92 @ 286a78e
- **Value:** {'number': 7, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_CACHE_REQUEST
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 8 denotes cache request.
- **References:**
  - RNS/Packet.py (CACHE_REQUEST) lines 71-92 @ 286a78e
- **Value:** {'number': 8, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_REQUEST
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 9 denotes request.
- **References:**
  - RNS/Packet.py (REQUEST) lines 71-92 @ 286a78e
- **Value:** {'number': 9, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESPONSE
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 10 denotes response to a request.
- **References:**
  - RNS/Packet.py (RESPONSE) lines 71-92 @ 286a78e
- **Value:** {'number': 10, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_PATH_RESPONSE
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 11 denotes path response.
- **References:**
  - RNS/Packet.py (PATH_RESPONSE) lines 71-92 @ 286a78e
- **Value:** {'number': 11, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_COMMAND
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 12 denotes command.
- **References:**
  - RNS/Packet.py (COMMAND) lines 71-92 @ 286a78e
- **Value:** {'number': 12, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_COMMAND_STATUS
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 13 denotes command status.
- **References:**
  - RNS/Packet.py (COMMAND_STATUS) lines 71-92 @ 286a78e
- **Value:** {'number': 13, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_CHANNEL
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 14 denotes link channel data.
- **References:**
  - RNS/Packet.py (CHANNEL) lines 71-92 @ 286a78e
- **Value:** {'number': 14, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_KEEPALIVE
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 250 denotes keepalive packet.
- **References:**
  - RNS/Packet.py (KEEPALIVE) lines 71-92 @ 286a78e
- **Value:** {'number': 250, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_LINKIDENTIFY
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 251 denotes link peer identification proof.
- **References:**
  - RNS/Packet.py (LINKIDENTIFY) lines 71-92 @ 286a78e
- **Value:** {'number': 251, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_LINKCLOSE
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 252 denotes link close message.
- **References:**
  - RNS/Packet.py (LINKCLOSE) lines 71-92 @ 286a78e
- **Value:** {'number': 252, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_LINKPROOF
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 253 denotes link packet proof.
- **References:**
  - RNS/Packet.py (LINKPROOF) lines 71-92 @ 286a78e
- **Value:** {'number': 253, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_LRRTT
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 254 denotes link request round-trip time measurement.
- **References:**
  - RNS/Packet.py (LRRTT) lines 71-92 @ 286a78e
- **Value:** {'number': 254, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_LRPROOF
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 255 denotes link request proof.
- **References:**
  - RNS/Packet.py (LRPROOF) lines 71-92 @ 286a78e
- **Value:** {'number': 255, 'unit': 'byte'}

## RNS.TRN.CONST.MTU_DEFAULT
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Default physical-layer MTU is 500 bytes; the wire packet length MUST NOT exceed the applicable MTU (interface or link).
- **References:**
  - RNS/Reticulum.py (MTU) lines 89-95 @ 286a78e
- **Value:** {'number': 500, 'unit': 'bytes'}

## RNS.TRN.CONST.DST_LEN
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Destination hash, transport id, and link_id are 16 bytes (TRUNCATED_HASHLENGTH//8).
- **References:**
  - RNS/Reticulum.py (TRUNCATED_HASHLENGTH) lines 147-154 @ 286a78e
- **Value:** {'number': 16, 'unit': 'bytes'}

## RNS.TRN.CONST.IFAC_MIN_SIZE
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Minimum IFAC payload length is 1 byte; interface.ifac_size defines actual length.
- **References:**
  - RNS/Reticulum.py (IFAC_MIN_SIZE) lines 147-154 @ 286a78e
- **Value:** {'number': 1, 'unit': 'bytes'}

## RNS.TRN.CONST.MDU
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** MDU (maximum data unit) is MTU minus HEADER_MAXSIZE and IFAC_MIN_SIZE; maximum plaintext in a single packet before encryption overhead.
- **References:**
  - RNS/Reticulum.py (MDU) lines 147-154 @ 286a78e
- **Value:** {'number': 464, 'unit': 'bytes'}

## RNS.PKT.CONST.KEYSIZE_BYTES
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Identity public and private key format is 64 bytes (X25519 32 + Ed25519 32).
- **References:**
  - RNS/Identity.py (KEYSIZE) lines 59-89 @ 286a78e
- **Value:** {'number': 64, 'unit': 'bytes'}

## RNS.PKT.CONST.SIGLENGTH_BYTES
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Ed25519 signature length is 64 bytes.
- **References:**
  - RNS/Identity.py (SIGLENGTH) lines 59-89 @ 286a78e
- **Value:** {'number': 64, 'unit': 'bytes'}

## RNS.PKT.CONST.HASHLENGTH_BYTES
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Full SHA-256 hash length is 32 bytes.
- **References:**
  - RNS/Identity.py (HASHLENGTH) lines 59-89 @ 286a78e
- **Value:** {'number': 32, 'unit': 'bytes'}

## RNS.PKT.CONST.RATCHETSIZE_BYTES
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Ratchet public key is 32 bytes (RATCHETSIZE//8).
- **References:**
  - RNS/Identity.py (RATCHETSIZE) lines 59-89 @ 286a78e
- **Value:** {'number': 32, 'unit': 'bytes'}

## RNS.PKT.CONST.NAME_HASH_LENGTH_BYTES
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Name hash and announce random hash are 10 bytes (NAME_HASH_LENGTH//8).
- **References:**
  - RNS/Identity.py (NAME_HASH_LENGTH) lines 59-89 @ 286a78e
- **Value:** {'number': 10, 'unit': 'bytes'}

## RNS.PKT.CONST.TOKEN_OVERHEAD
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Token overhead is 48 bytes (IV 16 + HMAC 32).
- **References:**
  - RNS/Cryptography/Token.py (TOKEN_OVERHEAD) lines 48-52 @ 286a78e
- **Value:** {'number': 48, 'unit': 'bytes'}

## RNS.PKT.CONST.AES128_BLOCKSIZE
- **Kind:** constant
- **Normative:** MUST
- **Statement:** AES block size is 16 bytes (used for padding and ciphertext alignment).
- **References:**
  - RNS/Identity.py (AES128_BLOCKSIZE) lines 59-89 @ 286a78e
- **Value:** {'number': 16, 'unit': 'bytes'}

## RNS.RES.CONST.MAPHASH_LEN
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Resource map hash (part hash) is 4 bytes; first 4 bytes of full_hash(part_data+random_hash).
- **References:**
  - RNS/Resource.py (MAPHASH_LEN) lines 100-106 @ 286a78e
- **Value:** {'number': 4, 'unit': 'bytes'}

## RNS.LNK.CONST.ECPUBSIZE
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Link request/response key material is 64 bytes (Initiator X25519 32 + Ed25519 32).
- **References:**
  - RNS/Link.py (ECPUBSIZE) lines 70-80 @ 286a78e
- **Value:** {'number': 64, 'unit': 'bytes'}

## RNS.PKT.ALG.DESTINATION_HASH_FROM_NAME
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** Destination hash (16 bytes) is derived from human-readable name and optional identity: expand_name (app_name + aspects, + identity.hexhash if present), name_hash = SHA-256(expand_name(None, app_name, *aspects).encode())[:10], addr_hash_material = name_hash [+ identity.hash if identity], destination_hash = SHA-256(addr_hash_material)[:16].
- **References:**
  - RNS/Destination.py (hash) lines 96-130 @ 286a78e
- **Steps:**
  - Build full name string: app_name + '.' + aspect1 + '.' + ... ; if identity supplied append '.' + identity.hexhash. No dots inside app_name or aspects.
  - name_hash = SHA-256(expand_name(None, app_name, *aspects).encode('utf-8'))[:NAME_HASH_LENGTH//8] (10 bytes).
  - addr_hash_material = name_hash; if identity is not None append identity.hash (16 bytes) or identity bytes.
  - Return full_hash(addr_hash_material)[:TRUNCATED_HASHLENGTH//8] (16 bytes).

## RNS.PKT.CONST.TRANSPORT_BROADCAST
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Flags byte bit 4 value 0 denotes BROADCAST transport type on the wire.
- **References:**
  - RNS/Transport.py (BROADCAST) lines 49-54 @ 286a78e
- **Value:** {'number': 0, 'unit': 'byte'}

## RNS.PKT.CONST.TRANSPORT_TRANSPORT
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Flags byte bit 4 value 1 denotes TRANSPORT transport type on the wire.
- **References:**
  - RNS/Transport.py (TRANSPORT) lines 49-54 @ 286a78e
- **Value:** {'number': 1, 'unit': 'byte'}

## RNS.TRN.BEHAV.HDLC_FRAMING
- **Kind:** behaviour
- **Normative:** MUST
- **Statement:** HDLC framing (TCP, Serial, Pipe, Weave): packets delimited by FLAG 0x7E. Escape 0x7E to 0x7D 0x5E, 0x7D to 0x7D 0x5D. Unescape then extract frame between FLAG bytes.
- **References:**
  - RNS/Interfaces/TCPInterface.py (HDLC) lines 44-53 @ 286a78e

## RNS.TRN.BEHAV.KISS_FRAMING
- **Kind:** behaviour
- **Normative:** MUST
- **Statement:** KISS framing (packet radio): packets delimited by FEND 0xC0; command byte 0x00 (CMD_DATA) prepended before escaping. Escape 0xC0 to 0xDB 0xDC, 0xDB to 0xDB 0xDD. Unescape then payload is data after command byte between FEND boundaries.
- **References:**
  - RNS/Interfaces/TCPInterface.py (KISS) lines 55-66 @ 286a78e
  - RNS/Interfaces/KISSInterface.py (KISS) lines 38-57 @ 286a78e

## RNS.TRN.BEHAV.RAW_UDP
- **Kind:** behaviour
- **Normative:** NOTE
- **Statement:** UDPInterface sends on-wire packet bytes raw inside UDP payload; one datagram equals one packet (no HDLC or KISS).
- **References:**
  - RNS/Interfaces/UDPInterface.py (UDPInterface) lines 40-46 @ 286a78e

## RNS.PKT.RULE.WELLFORMED_PACKET
- **Kind:** validation_rule
- **Normative:** MUST
- **Statement:** After IFAC removal (if present), packet MUST be parseable as HEADER_1 or HEADER_2 and length MUST be at least HEADER_MINSIZE or HEADER_MAXSIZE respectively. Malformed packets MUST be discarded.
- **References:**
  - RNS/Transport.py (inbound) lines 1241-1250 @ 286a78e

## RNS.PKT.RULE.UNKNOWN_CONTEXT_OPAQUE
- **Kind:** validation_rule
- **Normative:** MUST
- **Statement:** Unknown context or packet type values MAY appear on the wire; implementations MUST NOT assign semantics to unknown values and MUST treat payload as opaque (drop or forward without interpreting).
- **References:**
  - RNS/Transport.py (inbound) lines 1241-1250 @ 286a78e

## RNS.PKT.LAYOUT.PROOF_EXPLICIT
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Explicit proof payload: Packet_Hash (32 bytes) + Signature (64 bytes); total 96 bytes. Receiver validates hash matches proved packet and signature over hash.
- **References:**
  - RNS/Packet.py (EXPL_LENGTH) lines 413-414 @ 286a78e
- **Layout fields:**
  - packet_hash: offset 0, length 32
  - signature: offset 32, length 64

## RNS.PKT.LAYOUT.PROOF_IMPLICIT
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Implicit proof payload: Signature (64 bytes) only. Receiver infers proved packet by validating signature against pending packets.
- **References:**
  - RNS/Packet.py (IMPL_LENGTH) lines 413-414 @ 286a78e
- **Layout fields:**
  - signature: offset 0, length 64

## RNS.LNK.LAYOUT.LINKREQUEST_PAYLOAD
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Link request payload: Initiator X25519 public key (32 bytes) + Initiator Ed25519 public key (32 bytes) + optional Signalling bytes (3 bytes). Total 64 or 67 bytes.
- **References:**
  - RNS/Link.py (ECPUBSIZE) lines 70-80 @ 286a78e
- **Layout fields:**
  - initiator_x25519: offset 0, length 32
  - initiator_ed25519: offset 32, length 32
  - signalling: offset 64, length 3

## RNS.LNK.LAYOUT.LINKPROOF_PAYLOAD
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Link proof (LRPROOF) payload: Ed25519 Signature (64 bytes) + Responder X25519 public key (32 bytes) + optional Signalling bytes (3 bytes). Signed data = link_id + Responder X25519 + Responder Ed25519 + Signalling.
- **References:**
  - RNS/Link.py (prove) lines 371-377 @ 286a78e
- **Layout fields:**
  - signature: offset 0, length 64
  - responder_x25519: offset 64, length 32
  - signalling: offset 96, length 3

## RNS.LNK.ALG.LINKPROOF_SIGNED_DATA
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** Link proof signed data is link_id (16 bytes) + Responder X25519 (32) + Responder Ed25519 (32) + Signalling bytes (3). Signature is Ed25519 over that concatenation.
- **References:**
  - RNS/Link.py (prove) lines 371-377 @ 286a78e
- **Steps:**
  - signed_data = link_id + pub_bytes + sig_pub_bytes + signalling_bytes.
  - signature = identity.sign(signed_data).
  - proof_data = signature + pub_bytes + signalling_bytes.

## RNS.PKT.LAYOUT.TOKEN
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Token (encryption envelope): IV (16 bytes) + AES-256-CBC ciphertext (PKCS7-padded) + HMAC-SHA256 (32 bytes, final 32 bytes of token). Total overhead 48 bytes (TOKEN_OVERHEAD).
- **References:**
  - RNS/Cryptography/Token.py (TOKEN_OVERHEAD) lines 48-52 @ 286a78e
- **Layout fields:**
  - iv: offset 0, length 16
  - ciphertext: offset 16, length 0

## RNS.PKT.ALG.SINGLE_ENCRYPTION
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** SINGLE-destination encryption: Ephemeral X25519 public key (32 bytes) + Token (IV + ciphertext + HMAC). Key derived via HKDF from ECDH shared key, salt = identity truncated hash, length 64, split: first 32 = HMAC key, next 32 = AES key.
- **References:**
  - RNS/Identity.py (encrypt) lines 668-690 @ 286a78e
- **Steps:**
  - Generate ephemeral X25519 key pair; prepend ephemeral public key (32 bytes) to token.
  - shared_key = ECDH(ephemeral_prv, peer_identity_pub).
  - derived = HKDF(length=64, derive_from=shared_key, salt=identity_hash, context=b''); first 32 = HMAC key, next 32 = AES-256 key.
  - Token: PKCS7 pad → AES-256-CBC encrypt → prepend IV (16) → HMAC-SHA256(IV||ciphertext) → append HMAC (32).

## RNS.LNK.ALG.LINK_ENCRYPTION
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** LINK-destination DATA encryption: Token only (no ephemeral key prefix). Key derived once per link via ECDH and HKDF(salt=link_id, length=32 or 64). Ciphertext on wire is Token.encrypt(plaintext).
- **References:**
  - RNS/Link.py (encrypt) lines 1191-1210 @ 286a78e
- **Steps:**
  - shared_key = X25519(link_prv, peer_pub) or inverse for other side.
  - derived = HKDF(derive_from=shared_key, salt=link_id, context=b'', length=32 or 64).
  - ciphertext = Token(derived).encrypt(plaintext); no ephemeral prefix.

## RNS.PKT.LAYOUT.ANNOUNCE_WITH_RATCHET
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Announce payload with ratchet (context flag 1): PublicKey (64) + NameHash (10) + RandomHash (10) + RatchetKey (32) + Signature (64) + optional App Data. Fixed header 176 bytes.
- **References:**
  - RNS/Identity.py (validate_announce) lines 391-424 @ 286a78e
- **Layout fields:**
  - public_key: offset 0, length 64
  - name_hash: offset 64, length 10
  - random_hash: offset 74, length 10
  - ratchet_key: offset 84, length 32
  - signature: offset 116, length 64
  - app_data: offset 180, length 0

## RNS.PKT.LAYOUT.ANNOUNCE_WITHOUT_RATCHET
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Announce payload without ratchet (context flag 0): PublicKey (64) + NameHash (10) + RandomHash (10) + Signature (64) + optional App Data. Fixed header 148 bytes.
- **References:**
  - RNS/Identity.py (validate_announce) lines 391-424 @ 286a78e
- **Layout fields:**
  - public_key: offset 0, length 64
  - name_hash: offset 64, length 10
  - random_hash: offset 74, length 10
  - signature: offset 84, length 64
  - app_data: offset 148, length 0

## RNS.LNK.CONST.KEEPALIVE_INITIATOR
- **Kind:** constant
- **Normative:** MUST
- **Statement:** KEEPALIVE payload initiator to responder: single byte 0xFF.
- **References:**
  - RNS/Link.py (KEEPALIVE) lines 850-856 @ 286a78e
- **Value:** {'number': 255, 'unit': 'byte'}

## RNS.LNK.CONST.KEEPALIVE_RESPONDER
- **Kind:** constant
- **Normative:** MUST
- **Statement:** KEEPALIVE payload responder to initiator: single byte 0xFE.
- **References:**
  - RNS/Link.py (KEEPALIVE) lines 1151-1158 @ 286a78e
- **Value:** {'number': 254, 'unit': 'byte'}

## RNS.LNK.LAYOUT.LINKCLOSE_PAYLOAD
- **Kind:** layout
- **Normative:** MUST
- **Statement:** LINKCLOSE payload: link_id (16 bytes), plaintext (no link encryption).
- **References:**
  - RNS/Link.py (LINKCLOSE) lines 693-698 @ 286a78e
- **Layout fields:**
  - link_id: offset 0, length 16

## RNS.LNK.LAYOUT.LINKIDENTIFY_PAYLOAD
- **Kind:** layout
- **Normative:** MUST
- **Statement:** LINKIDENTIFY payload (plaintext before link encrypt): PublicKey (64 bytes) + Signature (64 bytes). Signed data = link_id + identity.get_public_key().
- **References:**
  - RNS/Link.py (LINKIDENTIFY) lines 469-476 @ 286a78e
- **Layout fields:**
  - public_key: offset 0, length 64
  - signature: offset 64, length 64

## RNS.CHN.LAYOUT.CHANNEL_ENVELOPE
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Channel data (context CHANNEL): envelope is MSGTYPE (2 bytes, >H) + Sequence (2 bytes) + Length (2 bytes) + Message Data (variable). Total 6 bytes overhead. MSGTYPE >= 0xf000 reserved for system.
- **References:**
  - RNS/Channel.py (pack) lines 179-197 @ 286a78e
- **Layout fields:**
  - msgtype: offset 0, length 2
  - sequence: offset 2, length 2
  - length: offset 4, length 2
  - data: offset 6, length 0

## RNS.TRN.LAYOUT.PATH_REQUEST_CLIENT
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Path request (client to transport): Destination Hash (16 bytes) + Request Tag (16 bytes).
- **References:**
  - RNS/Transport.py (path_request_handler) lines 2646-2672 @ 286a78e
- **Layout fields:**
  - destination_hash: offset 0, length 16
  - request_tag: offset 16, length 16

## RNS.TRN.LAYOUT.PATH_REQUEST_TRANSPORT
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Path request (transport to transport): Destination Hash (16) + Requesting Transport Instance ID (16) + Request Tag (16).
- **References:**
  - RNS/Transport.py (path_request_handler) lines 2646-2672 @ 286a78e
- **Layout fields:**
  - destination_hash: offset 0, length 16
  - requesting_transport_id: offset 16, length 16
  - request_tag: offset 32, length 16

## RNS.TRN.LAYOUT.TUNNEL_SYNTHESIS
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Tunnel synthesis payload: Public Key (64) + Interface Hash (32) + Random Hash (16) + Signature (64). Signed data = public_key + interface_hash + random_hash.
- **References:**
  - RNS/Transport.py (synthesize_tunnel) lines 2120-2132 @ 286a78e
- **Layout fields:**
  - public_key: offset 0, length 64
  - interface_hash: offset 64, length 32
  - random_hash: offset 96, length 16
  - signature: offset 112, length 64

## RNS.RES.LAYOUT.RESOURCE_ADV
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Resource advertisement (RESOURCE_ADV): umsgpack-packed dictionary with keys t (transfer size), d (uncompressed size), n (parts), h (resource hash), r (random hash), o (original hash), m (hashmap), f (flags), i (segment index), l (segments), q (request id), and flag keys u/p/x/c/e/s. Implementations MUST use same encoding for compatibility.
- **References:**
  - RNS/Resource.py (ResourceAdvertisement) lines 1312-1338 @ 286a78e
- **Layout fields:**
  - payload: offset 0, length 0

## RNS.RES.LAYOUT.RESOURCE_REQ
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Resource part request (RESOURCE_REQ): Hashmap Exhausted (1 byte) + optional Last Map Hash (4 bytes) + Resource Hash (32 bytes) + Requested Part Hashes (4 bytes each).
- **References:**
  - RNS/Resource.py (request_next) lines 918-952 @ 286a78e
- **Layout fields:**
  - hashmap_exhausted: offset 0, length 1
  - last_map_hash: offset 1, length 4
  - resource_hash: offset 5, length 32
  - requested_hashes: offset 37, length 0

## RNS.RES.LAYOUT.RESOURCE_HMU
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Resource hashmap update (RESOURCE_HMU): Resource Hash (32 bytes) + umsgpack.packb([segment_index, hashmap_bytes]).
- **References:**
  - RNS/Resource.py (request) lines 970-1047 @ 286a78e
- **Layout fields:**
  - resource_hash: offset 0, length 32
  - packed_hashmap: offset 32, length 0

## RNS.RES.LAYOUT.RESOURCE_PRF
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Resource proof (RESOURCE_PRF): Resource Hash (32 bytes, full SHA-256) + Proof (32 bytes, full_hash(resource_data+resource_hash)).
- **References:**
  - RNS/Resource.py (prove) lines 739-748 @ 286a78e
- **Layout fields:**
  - resource_hash: offset 0, length 32
  - proof: offset 32, length 32

## RNS.IFAC.ALG.IFAC_KEY_DERIVATION
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** IFAC key (interface.ifac_key) is derived with HKDF: length=64, derive_from=ifac_origin_hash (full_hash of ifac origin material), salt=IFAC_SALT (32-byte constant), context=None. ifac_identity = Identity.from_bytes(ifac_key).
- **References:**
  - RNS/Reticulum.py (ifac_key) lines 819-826 @ 286a78e
- **Steps:**
  - Build ifac_origin from interface config (ifac_netname, ifac_netkey, etc.); ifac_origin_hash = full_hash(ifac_origin).
  - ifac_key = HKDF(length=64, derive_from=ifac_origin_hash, salt=IFAC_SALT, context=None).
  - ifac_identity = Identity.from_bytes(ifac_key).
