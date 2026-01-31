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
