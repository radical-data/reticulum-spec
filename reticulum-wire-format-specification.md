# Reticulum Wire Format Specification

This document specifies the Reticulum wire format: the sequence of bytes as transmitted on the physical/interface layer. *Packet*: unit of transmission. *Header*: fixed layout bytes (flags, hops, destination/transport id, context). *Payload* / *ciphertext*: remainder; *context*: one-byte field indicating payload semantics. *Destination hash*: 16-byte truncated identity hash used for addressing.

-   **Code Reference:** `RNS/Packet.py` (Packet, raw, header, data, context); `RNS/Transport.py` (inbound/outbound).

**Notation:** Byte 0 is the first byte on the wire. Within a byte, bit 7 is MSB, bit 0 is LSB. Multi-byte integers are big-endian unless stated otherwise.

-   **Code Reference:** `RNS/Packet.py`, `struct.pack("!B", ...)`; `RNS/Channel.py`, `struct.pack(">HHH", ...)`; `RNS/Link.py`, `struct.pack(">I", ...)[1:]`.

### Constants (sizes in bytes unless noted)
| Constant | Value | Meaning |
|----------|--------|---------|
| TRUNCATED_HASHLENGTH/8 (DST_LEN) | 16 | Destination hash, transport id, link_id |
| KEYSIZE/8 | 64 | Identity public/private key |
| SIGLENGTH/8 | 64 | Ed25519 signature |
| HASHLENGTH/8 | 32 | Full SHA-256 hash, interface hash |
| RATCHETSIZE/8 | 32 | Ratchet public key |
| NAME_HASH_LENGTH/8 | 10 | Name hash, announce random hash |
| TOKEN_OVERHEAD | 48 | IV (16) + HMAC (32) |
| AES128_BLOCKSIZE | 16 | AES block size |
| MAPHASH_LEN | 4 | Resource map/part hash |
| LINK_MTU_SIZE | 3 | Signalling bytes length |
| ECPUBSIZE | 64 | Link request/response key material (32+32) |
| MTU_BYTEMASK | 0x1FFFFF | MTU in signalling (21 bits) |
| MODE_BYTEMASK | 0xE0 | Mode in signalling (bits 7–5 of first byte) |
| IFAC_SALT | 32 bytes (hex below) | Salt for deriving interface IFAC key (HKDF) |
| IFAC_SALT (hex) | `adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8` | Static salt; used when computing `interface.ifac_key` |

-   **Code Reference:** `RNS/Reticulum.py`, lines 147–154 (IFAC_SALT at 152); `RNS/Identity.py`, lines 59–89; `RNS/Packet.py`, line 252 (`DST_LEN`); `RNS/Resource.py`, line 102; `RNS/Link.py`, lines 70–71, 80, 144–145; `RNS/Cryptography/Token.py`, line 50.

### Packet size bounds
-   **Minimum header size (HEADER_1):** 2 + 16 + 1 = 19 bytes (flags, hops, destination hash, context). **HEADER_2:** 2 + 16 + 16 + 1 = 35 bytes.
-   **HEADER_MINSIZE:** 2+1+(TRUNCATED_HASHLENGTH//8)*1 = 19. **HEADER_MAXSIZE:** 2+1+(TRUNCATED_HASHLENGTH//8)*2 = 35.
-   **MTU:** 500 bytes (default physical layer). **MDU:** MTU − HEADER_MAXSIZE − IFAC_MIN_SIZE. **IFAC_MIN_SIZE:** 1.
-   **ENCRYPTED_MDU:** Maximum plaintext in a single encrypted packet (SINGLE/LINK); depends on TOKEN_OVERHEAD and AES block size. **PLAIN_MDU:** MDU. Link **MDU** derived from link MTU and header/IFAC/Token overhead.
-   Total on-wire packet length (after any framing decode, before any IFAC validation/removal) MUST be at most the applicable MTU (interface MTU, or link MTU for link packets).
-   After IFAC removal (if present), a packet MUST be long enough to contain its declared header:
    -   **HEADER_1:** length MUST be at least `HEADER_MINSIZE` (19 bytes).
    -   **HEADER_2:** length MUST be at least `HEADER_MAXSIZE` (35 bytes).
    -   **Note (ingress filtering in reference code):** Several stream-framing interfaces prefilter with `len(frame) > RNS.Reticulum.HEADER_MINSIZE` before handing the frame to `Transport.inbound`. This means a HEADER_1 packet of length exactly `HEADER_MINSIZE` (no payload bytes after the context byte) may be dropped before parsing in the reference implementation.

-   **Code Reference:** `RNS/Reticulum.py`, lines 91, 149–154; `RNS/Packet.py`, lines 100–110, 106 (`ENCRYPTED_MDU`); `RNS/Link.py`, lines 73, 531–532.

### Canonical header layout (after IFAC removal if present)
| Byte range | HEADER_1 | HEADER_2 |
|------------|----------|----------|
| 0 | flags | flags |
| 1 | hops | hops |
| 2–17 | destination_hash (16) | transport_id (16) |
| 18–33 | — | destination_hash (16) |
| 18 (HEADER_1) / 34 (HEADER_2) | context (1) | context (1) |
| 19– / 35– | payload (ciphertext) | payload (ciphertext) |

-   **Code Reference:** `RNS/Packet.py`, `pack` (header build), `unpack` (DST_LEN, `self.raw` slicing).

## 0. Transport Framing & Encapsulation

Reticulum packets are rarely sent as raw byte streams. To distinguish packet boundaries over streams (TCP, serial) or packet-radio hardware, the packet bytes are encapsulated in one of the following frames.

To avoid ambiguity around IFAC, this specification uses the following terms:

-   **On-wire packet bytes:** The bytes carried inside the interface framing (HDLC/KISS) or inside the UDP datagram payload. If IFAC is enabled on an interface, the on-wire bytes include the IFAC field (inserted after the hops byte) and the IFAC masking as implemented in `RNS/Transport.py`.
-   **Canonical packet bytes:** The packet bytes after IFAC validation and removal (if present). This is what `RNS/Packet.py` parses in `Packet.unpack()`, and what the “Canonical header layout” table in this document describes.

### HDLC Framing (TCP, Serial, Pipe)

-   **Used for:** `TCPClientInterface`, `TCPServerInterface`, `SerialInterface`, `PipeInterface`, `WeaveInterface`.
-   **Delimiters:** Packets are surrounded by FLAG bytes `0x7E`.
-   **Escaping (before sending):**
    -   `0x7E` (FLAG) → `0x7D 0x5E` (ESC + FLAG⊕0x20)
    -   `0x7D` (ESC) → `0x7D 0x5D` (ESC + ESC⊕0x20)
-   **Unescaping (after receiving):** Reverse the above; then extract the frame between two FLAG bytes.
-   **Code Reference:** `RNS/Interfaces/TCPInterface.py`, lines 44–52 (HDLC class); `RNS/Interfaces/WeaveInterface.py`, lines 38–46 (HDLC class).

### KISS Framing (Packet radio / modems)

-   **Used for:** `KISSInterface`, `AX25KISSInterface`, `RNodeInterface`, `RNodeMultiInterface` (when in KISS mode).
-   **Delimiters:** Packets are surrounded by FEND bytes `0xC0`.
-   **Command byte:** A command byte is prepended to the packet *before* escaping: `0x00` (CMD_DATA) for data.
-   **Escaping (before sending):**
    -   `0xC0` (FEND) → `0xDB 0xDC` (FESC + TFEND)
    -   `0xDB` (FESC) → `0xDB 0xDD` (FESC + TFESC)
-   **Unescaping (after receiving):** Reverse the above; then the payload is the data after the command byte, between FEND boundaries.
-   **Code Reference:** `RNS/Interfaces/KISSInterface.py`, lines 38–57 (KISS class); `RNS/Interfaces/TCPInterface.py`, lines 55–59 (KISS), 321 (frame build), 350–376 (parse).

### No framing (raw)

-   **UDPInterface** sends the on-wire packet bytes **raw** inside the UDP payload (no HDLC or KISS). Packet boundaries are one UDP datagram = one packet.

## 1. Canonical Packet Structure (`RNS/Packet.py`, `RNS/Transport.py`)

### Packet Header
Reticulum packets begin with a header containing flags and hop count, followed by destination information.

-   **Flags Byte (1 byte)**: The first byte of every packet.
    -   `Bit 7 (MSB)`: IFAC Flag (1 if IFAC is present, 0 otherwise).
    -   `Bit 6`: Header Type (0 for HEADER_1, 1 for HEADER_2).
    -   `Bit 5`: Context flag.
    -   `Bit 4`: Transport flag (1 bit): `0x00` = BROADCAST, `0x01` = TRANSPORT.
    -   `Bits 3-2`: Destination Type (0x00 for SINGLE, 0x01 for GROUP, 0x02 for PLAIN, 0x03 for LINK).
    -   `Bits 1-0`: Packet Type (0x00 for DATA, 0x01 for ANNOUNCE, 0x02 for LINKREQUEST, 0x03 for PROOF).
    -   **Code Reference:** `RNS/Packet.py`, lines 168–174 (`get_packed_flags`)
        ```python
        packed_flags = (self.header_type << 6) | (self.context_flag << 5) | (self.transport_type << 4) | (self.destination.type << 2) | self.packet_type
        ```
        And: `RNS/Packet.py`, lines 246–251 (`unpack`)
        ```python
        self.header_type      = (self.flags & 0b01000000) >> 6
        self.context_flag     = (self.flags & 0b00100000) >> 5
        self.transport_type   = (self.flags & 0b00010000) >> 4
        self.destination_type = (self.flags & 0b00001100) >> 2
        self.packet_type      = (self.flags & 0b00000011)
        ```
-   **Hop Count (1 byte)**: The second byte, indicating the number of hops taken by the packet.
    -   **Code Reference:** `RNS/Packet.py`, lines 179–180 (pack), 245–246 (unpack)
        ```python
        self.header += struct.pack("!B", self.hops)
        self.hops  = self.raw[1]
        ```
-   **Destination Hash / Transport ID**:
    -   **Header Type 1**: Followed by `Destination Hash` (16 bytes, `TRUNCATED_HASHLENGTH//8`).
        -   **Code Reference:** `RNS/Packet.py`, lines 187 (pack), 261 (unpack)
            ```python
            self.header += self.destination.hash
            self.destination_hash = self.raw[2:DST_LEN+2]
            ```
    -   **Header Type 2**: Followed by `Transport ID` (16 bytes) then `Destination Hash` (16 bytes).
        -   **Code Reference:** `RNS/Packet.py`, lines 220–222 (pack), 255–256 (unpack)
            ```python
            self.header += self.transport_id
            self.header += self.destination.hash
            self.transport_id = self.raw[2:DST_LEN+2]
            self.destination_hash = self.raw[DST_LEN+2:2*DST_LEN+2]
            ```
-   **Context Byte (1 byte)**: The byte immediately following destination info, indicating the packet's context (e.g., DATA, RESOURCE, REQUEST).
    -   **Code Reference:** `RNS/Packet.py`, lines 230 (pack), 257, 262 (unpack)
        ```python
        self.header += bytes([self.context])
        self.context = ord(self.raw[DST_LEN+2:DST_LEN+3]) # for HEADER_1
        self.context = ord(self.raw[2*DST_LEN+2:2*DST_LEN+3]) # for HEADER_2
        ```
-   **Ciphertext**: The remainder of the packet is the encrypted or plaintext data payload.
    -   **Code Reference:** `RNS/Packet.py`, lines 231 (pack), 258, 263 (unpack)
        ```python
        self.raw = self.header + self.ciphertext
        self.data = self.raw[DST_LEN+3:] # for HEADER_1
        ```

### Packet hashing (hashable part)
Packet hash and truncated hash (used for Link ID, proofs, deduplication) are **not** computed over the raw packet. The hash input is the **hashable part**, defined as follows.

-   **Rule:** The hash input excludes the IFAC flag, the Header Type flag, the Context flag, the Transport flag, and (if present) the Transport ID. It is **not** the raw packet bytes.
-   **Definition:** (1) Take the first byte of the header (flags). Mask it with `0b00001111` (discard bits 7–4: IFAC, Header Type, Context flag, Transport flag). (2) If Header Type is HEADER_2: skip the Hops byte (1 byte) and the Transport ID (16 bytes); append the rest of the raw packet, i.e. `raw[18:]`. (3) If Header Type is HEADER_1: skip the Hops byte (1 byte); append the rest of the raw packet, i.e. `raw[2:]`.
-   **Hash:** `packet.get_hash()` = full SHA-256 of the hashable part. `packet.getTruncatedHash()` = first 16 bytes of that hash.
-   **Code Reference:** `RNS/Packet.py`, lines 354–361 (`get_hashable_part`), 348–352 (`get_hash`, `getTruncatedHash`).

### Link ID derivation from LINKREQUEST (special case)

The **Link ID** (16-byte truncated hash used to address the Link destination) is derived from the LINKREQUEST packet. When the LINKREQUEST payload includes **signalling bytes** (MTU/Mode), the hash input MUST exclude those bytes so the Link ID stays stable across MTU renegotiation.

-   **Rule:** (1) Obtain the hashable part of the LINKREQUEST packet (as in `get_hashable_part`). (2) If `len(packet.data) > ECPUBSIZE` (64 bytes), strip the last `len(packet.data) - ECPUBSIZE` bytes from the hashable part (these correspond to the signalling data). (3) Link ID = truncated hash (first 16 bytes of SHA-256) of that (possibly truncated) hashable part.
-   **Code Reference:** `RNS/Link.py`, lines 341–347 (`link_id_from_lr_packet`).

-   **Byte order**: Multi-byte integer header fields use **big-endian** (network byte order). Packet header uses `struct.pack("!B", ...)`; Channel/Buffer use `>H`, `>HHH`.

**Well-formed packet:** After IFAC removal (if any), the packet MUST be parseable as either HEADER_1 or HEADER_2, and MUST meet the corresponding minimum length (`HEADER_MINSIZE` for HEADER_1, `HEADER_MAXSIZE` for HEADER_2). Malformed packets MUST be discarded and MUST NOT be used for crypto or routing.

-   **Code Reference:** `RNS/Transport.py`, `inbound` (IFAC checks, unpack, drop-on-exception); stream-framing interfaces check `len(frame) > RNS.Reticulum.HEADER_MINSIZE` before calling inbound.

**Unknown context or packet type:** Unrecognised context or packet type values MAY be encountered on the wire. Implementations MUST NOT assume semantics for unknown values; they MUST treat payload as opaque, and either drop the packet or forward it without interpreting the payload.

-   **Code Reference:** `RNS/Transport.py`, inbound dispatch; `RNS/Packet.py`, pack/unpack by packet_type and context.

**Version:** There is no protocol or wire-format version field in the header; the current design has no version field.

-   **Code Reference:** `RNS/Packet.py`, `pack` (no version byte).

### Packet context byte values
The following are the **known** context byte values used by the reference implementation (`RNS/Packet.py`). Other context values may appear (extensions, future versions, or non-reference implementations); receivers MUST treat unknown contexts as opaque and MUST NOT interpret their payload.

| Value   | Constant       | Meaning |
|---------|-----------------|---------|
| 0x00    | NONE            | Generic data |
| 0x01    | RESOURCE        | Resource data part |
| 0x02    | RESOURCE_ADV    | Resource advertisement |
| 0x03    | RESOURCE_REQ    | Resource part request |
| 0x04    | RESOURCE_HMU    | Resource hashmap update |
| 0x05    | RESOURCE_PRF    | Resource proof |
| 0x06    | RESOURCE_ICL    | Resource initiator cancel |
| 0x07    | RESOURCE_RCL    | Resource receiver cancel |
| 0x08    | CACHE_REQUEST   | Cache request |
| 0x09    | REQUEST         | Request (link); payload application-defined, often umsgpack. |
| 0x0A    | RESPONSE        | Response (link); small responses = umsgpack.packb([request_id, response]). |
| 0x0B    | PATH_RESPONSE   | Path request response (announce); payload same as ANNOUNCE (public key, name hash, random hash, optional ratchet, signature, optional app data). |
| 0x0C    | COMMAND         | Command |
| 0x0D    | COMMAND_STATUS  | Command status |
| 0x0E    | CHANNEL         | Link channel data (envelope format) |
| 0xFA    | KEEPALIVE       | Keepalive |
| 0xFB    | LINKIDENTIFY    | Link peer identification |
| 0xFC    | LINKCLOSE       | Link close |
| 0xFD    | LINKPROOF       | Link packet proof |
| 0xFE    | LRRTT           | Link RTT measurement |
| 0xFF    | LRPROOF         | Link request proof |

-   **Code Reference:** `RNS/Packet.py`, lines 72–92 (`Packet.context` constants). REQUEST/RESPONSE: `RNS/Link.py` (e.g. `umsgpack.packb([request_id, response])` for response). PATH_RESPONSE: same wire format as announce; `RNS/Destination.py` (`announce`, path_response=True), `RNS/Transport.py` (forwarding).

### Destination address hashing (from human-readable name)
Destination hash (16 bytes) used in headers and addressing can be derived from a human-readable name (e.g. `lxmf.delivery`) and an optional identity.

-   **Rule:** (1) Build the full name string: `app_name + "." + aspect1 + "." + aspect2 + ...` (no dots inside app_name or any aspect; if identity is supplied, append `"." + identity.hexhash`). Encode as UTF-8. (2) `name_hash` = SHA-256(full_name_string) truncated to 10 bytes (`NAME_HASH_LENGTH//8`). Use `expand_name(None, app_name, *aspects)` for the name string when computing the hash (identity not included in name_hash input). (3) `addr_hash_material` = name_hash; if identity is not None, append identity.hash (16 bytes, truncated identity hash). (4) Destination hash = SHA-256(addr_hash_material) truncated to 16 bytes (`TRUNCATED_HASHLENGTH//8`).
-   **Code Reference:** `RNS/Destination.py`, lines 96–111 (`expand_name`), 116–130 (`hash`).

### Transport type (flags bits)
-   **On-wire (flags byte bit 4):** `0x00` = BROADCAST, `0x01` = TRANSPORT.
-   **Note:** `RNS/Transport.py` defines additional internal constants (`RELAY = 0x02`, `TUNNEL = 0x03`) for transport-layer logic, but these values are not encoded directly in the packet flags byte in the reference wire format (bit 4 is a single bit and is unpacked as 0/1 in `RNS/Packet.py`).
-   **Code Reference:** `RNS/Packet.py` (unpack extracts only bit 4); `RNS/Transport.py`, lines 49–54 (constants).

## 2. Cryptographic Primitives & Key Formats (`RNS/Identity.py`)

-   **Identity Key Sizes**:
    -   `Identity.KEYSIZE`: 512 bits (total for an Identity, 256-bit encryption + 256-bit signing).
    -   `Identity.RATCHETSIZE`: 256 bits (for ephemeral ratchet keys).
    -   `Identity.HASHLENGTH`: 256 bits (SHA-256 output).
    -   `Identity.SIGLENGTH`: 256 bits (Ed25519 signature length).
    -   `Identity.TRUNCATED_HASHLENGTH`: 128 bits (used for addressing).
    -   `Identity.NAME_HASH_LENGTH`: 80 bits.
    -   **Code Reference:** `RNS/Identity.py`, lines 59–83
        ```python
        Identity.CURVE = "Curve25519"
        Identity.KEYSIZE     = 256*2
        Identity.RATCHETSIZE = 256
        Identity.HASHLENGTH  = 256
        Identity.SIGLENGTH   = KEYSIZE
        Identity.NAME_HASH_LENGTH = 80
        Identity.TRUNCATED_HASHLENGTH = 128
        ```
-   **Public Key Format**: Concatenation of `X25519PublicKey` (32 bytes) and `Ed25519PublicKey` (32 bytes). Total 64 bytes.
    -   **Code Reference:** `RNS/Identity.py`, lines 595–596 (`get_public_key`)
        ```python
        return self.pub_bytes+self.sig_pub_bytes
        ```
-   **Private Key Format**: Concatenation of `X25519PrivateKey` (32 bytes) and `Ed25519PrivateKey` (32 bytes). Total 64 bytes.
    -   **Code Reference:** `RNS/Identity.py`, lines 589–590 (`get_private_key`)
        ```python
        return self.prv_bytes+self.sig_prv_bytes
        ```
-   **Encryption (for SINGLE destinations)**:
    -   Payload structure: `Ephemeral_X25519_PublicKey` (32 bytes) + **Token** (variable length). Token layout: `IV` (16 bytes) + AES-256-CBC ciphertext (PKCS7-padded) + HMAC-SHA256 (32 bytes). Total Token overhead: 48 bytes (`TOKEN_OVERHEAD`).
    -   Key derivation: HKDF with `length=64` (`DERIVED_KEY_LENGTH`), `derive_from=shared_key` (X25519 ECDH), `salt=identity truncated hash` (16 bytes, `get_salt()`), `context=None` (passed as `b""`). Derived key is split: first 32 bytes = HMAC signing key, next 32 = AES-256 key.
    -   **Code Reference:** `RNS/Identity.py` (`encrypt`, `get_salt`, `get_context`); `RNS/Cryptography/Token.py` (IV 16, HMAC 32, PKCS7); `RNS/Cryptography/HKDF.py`.
-   **Reference code excerpt (`RNS/Identity.py:encrypt`)**:
        ```python
        ephemeral_key = X25519PrivateKey.generate()
        ephemeral_pub_bytes = ephemeral_key.public_key().public_bytes()
        # ...
        token = Token(derived_key)
        ciphertext = token.encrypt(plaintext)
        token = ephemeral_pub_bytes+ciphertext
        ```
-   **LINK destination encryption**: DATA to a LINK destination uses the same **Token** format but with no ephemeral key prefix: ciphertext is `Token.encrypt(plaintext)` only (link-derived key). Implementations MUST NOT prepend an ephemeral key for link DATA.
-   **Reference code excerpt (`RNS/Link.py:encrypt`)**:
        ```python
        return self.token.encrypt(plaintext)
        ```
-   **Signatures (Ed25519)**:
    -   Generated by `Ed25519PrivateKey.sign(message)`.
    -   Validated by `Ed25519PublicKey.verify(signature, message)`.
    -   **Code Reference:** `RNS/Identity.py`, lines 772–773 (`sign`), 789–790 (`validate`).

**Cryptographic algorithms:** Hashing: SHA-256. Encryption: AES-256-CBC. Authentication: HMAC-SHA256. Key derivation: HKDF with HMAC-SHA256. Key exchange: X25519. Signatures: Ed25519. Implementations MUST use these; no algorithm identifiers are sent on the wire.

-   **Code Reference:** `RNS/Cryptography/Hashes.py`, `RNS/Cryptography/AES.py`, `RNS/Cryptography/HMAC.py`, `RNS/Cryptography/HKDF.py`, `RNS/Cryptography/X25519.py`, `RNS/Cryptography/Ed25519.py`.

**Token encryption order:** HKDF → split key (first 32 = signing, next 32 = encryption) → PKCS7 pad plaintext → AES-256-CBC encrypt → prepend IV (16) → HMAC-SHA256(IV||ciphertext) → append HMAC (32). Decryption: verify HMAC over token (excluding last 32 bytes), then decrypt, then PKCS7 unpad.

-   **Code Reference:** `RNS/Cryptography/Token.py`, `encrypt` (iv, pad, encrypt, signed_parts, HMAC), `decrypt` (verify_hmac, iv, ciphertext, unpad)
        ```python
        return self.sig_prv.sign(message)
        # ...
        self.sig_pub.verify(signature, message)
        ```

## 3. Announce Packet Format (`RNS/Destination.py`, `RNS/Identity.py`)

Announce packets (`Packet.ANNOUNCE` type) carry information about a destination and its public key.

-   **Structure when Ratchet is present (Context Flag 0x01)**:
    -   `PublicKey` (64 bytes)
    -   `Name Hash` (10 bytes, `RNS.Identity.NAME_HASH_LENGTH//8`)
    -   `Random Hash` (10 bytes)
    -   `Ratchet Public Key` (32 bytes, `Identity.RATCHETSIZE//8`)
    -   `Signature` (64 bytes)
    -   `App Data` (variable length, optional)
    -   **Code Reference:** `RNS/Destination.py`, lines 243–310 (`announce`) and `RNS/Identity.py`, lines 391–424 (`validate_announce`)
        ```python
        signed_data = self.hash+self.identity.get_public_key()+self.name_hash+random_hash+ratchet
        if app_data != None: signed_data += app_data
        signature = self.identity.sign(signed_data)
        announce_data = self.identity.get_public_key()+self.name_hash+random_hash+ratchet+signature
        if app_data != None: announce_data += app_data
        ```
        ```python
        public_key = packet.data[:keysize]
        # ...
        ratchet     = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+ratchetsize]
        signature   = packet.data[keysize+name_hash_len+10+ratchetsize:keysize+name_hash_len+10+ratchetsize+sig_len]
        app_data    = b""
        if len(packet.data) > keysize+name_hash_len+10+sig_len+ratchetsize:
            app_data = packet.data[keysize+name_hash_len+10+sig_len+ratchetsize:]
        ```
-   **Structure when Ratchet is *not* present (Context Flag 0x00)**:
    -   `PublicKey` (64 bytes)
    -   `Name Hash` (10 bytes)
    -   `Random Hash` (10 bytes)
    -   `Signature` (64 bytes)
    -   `App Data` (variable length, optional)
    -   **Code Reference:** `RNS/Destination.py`, lines 243–310 (`announce`) and `RNS/Identity.py`, lines 391–424 (`validate_announce`)
        ```python
        ratchet     = b"" # empty
        name_hash   = packet.data[keysize:keysize+name_hash_len]
        random_hash = packet.data[keysize+name_hash_len:keysize+name_hash_len+10]
        signature   = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+sig_len]
        app_data    = b""
        if len(packet.data) > keysize+name_hash_len+10+sig_len:
            app_data = packet.data[keysize+name_hash_len+10+sig_len:]
        ```

### Announce App Data location

App Data in an ANNOUNCE packet is any data after the fixed-size header. Parsing MUST use the following offsets (packet payload = `packet.data`).

-   **Rule:** `App_Data = packet.data[Fixed_Header_Size:]`.
-   **Fixed header size (no ratchet, context flag 0):** 148 bytes = Key (64) + NameHash (10) + RandHash (10) + Sig (64) (`keysize+name_hash_len+10+sig_len`).
-   **Fixed header size (with ratchet, context flag 1):** 176 bytes = Key (64) + NameHash (10) + RandHash (10) + RatchetKey (32) + Sig (64).
-   **Code Reference:** `RNS/Identity.py`, lines 404–423 (`validate_announce`: slice for app_data; no ratchet: `keysize+name_hash_len+10+sig_len`, with ratchet: `keysize+name_hash_len+10+sig_len+ratchetsize`).

### Interface discovery App Data (rnstransport.discovery.interface)
For a node to participate in the network map or auto-peer, ANNOUNCE packets for the destination `rnstransport.discovery.interface` may carry App Data that describes an interface. This payload is required for interface discovery.

-   **Rule:** The App Data of an ANNOUNCE packet for this destination is: 1-byte flags (e.g. FLAG_SIGNED, FLAG_ENCRYPTED) followed by either (a) a umsgpack-packed dictionary plus an optional stamp, or (b) the same encrypted with the network identity (Token). The dictionary keys map to interface properties: interface type, transport enabled, transport ID, name, latitude, longitude, height, and per-interface-type fields (e.g. reachable_on, port, frequency, bandwidth, IFAC net name/key). Key values are numeric (e.g. 0x00 = INTERFACE_TYPE, 0x01 = TRANSPORT, 0x02 = REACHABLE_ON). Implementations that parse or emit interface discovery MUST use the same key encoding and dictionary layout.
-   **Code Reference:** `RNS/Discovery.py`, lines 94–178 (`get_interface_announce_data`); key constants at lines 11–26.

## 4. Link Request and Proof Format (`RNS/Link.py`)

### Link Request Packets
Link Request packets (`Packet.LINKREQUEST` type) are used to initiate a link.

-   **Structure**: `Initiator_X25519_PublicKey` (32 bytes) + `Initiator_Ed25519_PublicKey` (32 bytes) + `Signalling Bytes` (3 bytes, optional).
    -   **Signalling Bytes (3 bytes, LINK_MTU_SIZE):** Big-endian encoding. MTU is 21 bits (MTU_BYTEMASK 0x1FFFFF); Mode is 3 bits (MODE_BYTEMASK 0xE0). Compose: `signalling_value = (mtu & MTU_BYTEMASK) + (((mode << 5) & MODE_BYTEMASK) << 16)`; emit `struct.pack(">I", signalling_value)[1:]` (high 3 bytes of the 32-bit value). Explicit byte layout:
        -   Byte 0: `(Mode << 5) | (MTU >> 16)`  (bits 7–5 = Mode, bits 4–0 = high 5 bits of MTU)
        -   Byte 1: `(MTU >> 8) & 0xFF`
        -   Byte 2: `MTU & 0xFF`
    -   Parse: Mode = (byte0 >> 5) & 0x07; MTU = ((byte0 & 0x1F) << 16) | (byte1 << 8) | byte2 (then mask with MTU_BYTEMASK). Reserved/unused bits MUST be zero when sending and MUST be ignored when receiving.
    -   **Code Reference:** `RNS/Link.py`, lines 147–151 (`signalling_bytes`), 155–156 (`mtu_from_lr_packet`), 173–174 (`mode` from packet.data); request_data build: `__init__` (pub_bytes+sig_pub_bytes+signalling_bytes).

### Link Proof Packets
Link Proof packets (`Packet.PROOF` type, `Packet.LRPROOF` context) are used to confirm link establishment.

-   **Structure**: `Ed25519_Signature` (64 bytes) + `Responder_X25519_PublicKey` (32 bytes) + `Signalling Bytes` (3 bytes, optional).
    -   `Signature`: Signed over `link_id+Responder_X25519_PublicKey+Responder_Ed25519_PublicKey+Signalling_Bytes`.
    -   **Code Reference:** `RNS/Link.py`, lines 371–377 (`prove`)
        ```python
        signed_data = self.link_id+self.pub_bytes+self.sig_pub_bytes+signalling_bytes
        signature = self.owner.identity.sign(signed_data)
        proof_data = signature+self.pub_bytes+signalling_bytes
        ```
    -   **Code Reference:** `RNS/Link.py`, lines 396–418 (`validate_proof`)
        ```python
        # In this part of the code, packet.data is the raw data received in the proof packet
        signature = packet.data[:RNS.Identity.SIGLENGTH//8]
        peer_pub_bytes = packet.data[RNS.Identity.SIGLENGTH//8:RNS.Identity.SIGLENGTH//8+Link.ECPUBSIZE//2]
        # peer_identity will be the remote destination's Identity from local lookup tables
        peer_sig_pub_bytes = peer_identity.get_public_key()[RNS.Link.ECPUBSIZE//2:RNS.Link.ECPUBSIZE]
        
        # This is the data that the remote peer signed
        signed_data = packet.destination_hash+peer_pub_bytes+peer_sig_pub_bytes+signalling_bytes
        
        if peer_identity.validate(signature, signed_data): ...
        ```

### Proof payload formats (explicit vs implicit)

PROOF packets to a LINK destination (or SINGLE for delivery proofs) can carry one of two payload formats. Compatible implementations MUST accept both when validating incoming proofs.

-   **Explicit proof (default/standard):**
    -   **Size:** 96 bytes (`HASHLENGTH//8` + `SIGLENGTH//8` = 32 + 64).
    -   **Layout:** `Packet_Hash` (32 bytes) + `Signature` (64 bytes). The receiver checks that the hash matches the proved packet and validates the signature over that hash.
-   **Implicit proof:**
    -   **Size:** 64 bytes (`SIGLENGTH//8`).
    -   **Layout:** `Signature` (64 bytes) only. The receiver MUST infer which packet is proved by validating the signature against each pending sent packet (or equivalent logic).
-   **Code Reference:** `RNS/Packet.py`, lines 413–414 (`EXPL_LENGTH`, `IMPL_LENGTH`), 442–495 (`validate_proof_packet`, `validate_proof`), 497–531 (`validate_proof` explicit vs implicit).

### Link and system context payloads (DATA or PROOF to LINK destination)
-   **KEEPALIVE (0xFA):** Payload exactly 1 byte. **Initiator → Responder:** `0xFF`. **Responder → Initiator:** `0xFE`. No other payload values are specified; implementations MUST treat only these as valid keepalive payloads.
-   **Code Reference:** `RNS/Link.py`, lines 853 (`bytes([0xFF])`), 1154–1156 (`bytes([0xFE])`), 978 (check `packet.data == bytes([0xFF])`).
-   **LINKCLOSE (0xFC):** Payload = link_id (16 bytes). Plaintext (no link encryption).
-   **Code Reference:** `RNS/Link.py`, lines 695–696 (`RNS.Packet(self, self.link_id, context=RNS.Packet.LINKCLOSE)`), 710–712 (`teardown_packet`, decrypt payload).
-   **LINKIDENTIFY (0xFB):** Payload = link-encrypted Token. Plaintext before encryption: PublicKey (64 bytes) + Signature (64 bytes). Signed data = link_id + identity.get_public_key().
-   **Code Reference:** `RNS/Link.py`, lines 469–474 (`proof_data = identity.get_public_key() + signature`, context LINKIDENTIFY), 1014–1016 (decrypt packet.data).
-   **LRRTT (0xFE):** Payload = umsgpack-packed float (RTT in seconds). Link-encrypted.
-   **Code Reference:** `RNS/Link.py`, lines 440–441 (`umsgpack.packb(self.rtt)`), 1060–1062 (handle LRRTT).
-   **LINKPROOF (0xFD):** Reserved; no payload layout specified in reference. Implementations MUST NOT assume a format; drop or forward without interpreting if encountered.
-   **Code Reference:** `RNS/Packet.py`, line 90 (constant only; no send path uses LINKPROOF in codebase).

## 5. Interface Access Control (IFAC) (`RNS/Transport.py`)

IFAC (Interface Access Control) is an optional mechanism to authenticate packets at the interface level, preventing unauthorised traffic on a physical medium.

-   **IFAC Flag (Bit 7 of Flags Byte)**:
    -   `0x80` if IFAC is present, `0x00` if not.
    -   **Code Reference:** `RNS/Transport.py`, lines 908–909 (`transmit`)
        ```python
        new_header = bytes([raw[0] | 0x80, raw[1]])
        ```
-   **IFAC Payload**:
    -   Inserted after the second header byte (hop count).
    -   Length defined by `interface.ifac_size` (min 1 byte).
    -   Value is `Ed25519_Signature` of the original raw packet data (excluding IFAC and its flags).
    -   **Code Reference:** `RNS/Transport.py`, lines 898, 912 (`transmit`)
        ```python
        # Calculate packet access code
        ifac = interface.ifac_identity.sign(raw)[-interface.ifac_size:]
        # ...
        new_raw    = new_header+ifac+raw[2:]
        ```
-   **Masking**: A mask is derived with HKDF from `derive_from=ifac`, `salt=interface.ifac_key`, `context=None`, `length=len(raw)+interface.ifac_size`. The first header byte is replaced by `(raw[0] ^ mask[0]) | 0x80` so the IFAC bit remains set. Bytes at index 1 and at index &gt; 1+ifac_size are XORed with the corresponding mask bytes. Bytes at indices 2..1+ifac_size (the IFAC) are NOT masked.
    -   **Code Reference:** `RNS/Transport.py`, lines 901–927 (`transmit`)
        ```python
        mask = RNS.Cryptography.hkdf(
            length=len(raw)+interface.ifac_size,
            derive_from=ifac,
            salt=interface.ifac_key,
            context=None,
        )
        # ... masking logic ...
        ```
-   **Validation (Inbound)**: Inbound packets with the IFAC flag set undergo unmasking, IFAC extraction, recalculation of expected IFAC, and verification against the received IFAC.

**IFAC order of operations (outbound):** Build raw packet → sign full raw with ifac_identity → take last ifac_size bytes as IFAC → new header = (raw[0]|0x80, raw[1]) → new_raw = new_header + ifac + raw[2:] → derive mask from HKDF(ifac, ifac_key) → mask bytes 0,1 and bytes after 1+ifac_size (leave IFAC bytes unmasked); first byte becomes (byte^mask)|0x80.

**IFAC order of operations (inbound):** Extract ifac = raw[2:2+ifac_size] → derive mask same as outbound → unmask bytes 0,1 and bytes after 1+ifac_size → new_raw = (raw[0]&0x7f, raw[1]) + raw[2+ifac_size:] → expected_ifac = sign(new_raw)[-ifac_size:] → if ifac == expected_ifac accept new_raw else drop.

-   **Code Reference:** `RNS/Transport.py`, transmit (ifac sign, mask, first byte OR 0x80); inbound (extract ifac, derive mask, unmask, new_raw, expected_ifac, verify, strip).

## 6. Channel Messaging (`RNS/Channel.py`, `RNS/Buffer.py`)

Channel data is carried in **DATA** packets with **context CHANNEL (0x0E)** to a LINK destination. The packet payload is link-encrypted; the decrypted payload is the channel envelope (MSGTYPE + sequence + length + message data). The Channel provides reliable, ordered message delivery over a Link.

-   **Message Envelope**: Messages are wrapped in an internal envelope.
    -   Structure: `MSGTYPE` (2 bytes, `>H`) + `Sequence` (2 bytes, `>H`) + `Length` (2 bytes, `>H`) + `Message Data` (variable length). Total 6 bytes overhead.
    -   `MSGTYPE`: Unique identifier for the message class. Values `>= 0xf000` are reserved for system use.
    -   `Sequence`: Incremental sequence number for reliable delivery.
    -   `Length`: Length of `Message Data`.
    -   **Code Reference:** `RNS/Channel.py`, lines 180 (`unpack`), 196 (`pack`)
        ```python
        self.raw = struct.pack(">HHH", self.message.MSGTYPE, self.sequence, len(data)) + data
        # ...
        msgtype, self.sequence, length = struct.unpack(">HHH", self.raw[:6])
        ```
-   **Stream Data Message (`StreamDataMessage`)**: A system message type (`0xff00`) used for raw data streams over a channel.
    -   Header: `stream_id` (14 bits) + `eof` flag (1 bit) + `compressed` flag (1 bit), packed as `>H` (2 bytes).
    -   **Code Reference:** `RNS/Buffer.py`, lines 84-85 (`StreamDataMessage.pack`)
        ```python
        header_val = (0x3fff & self.stream_id) | (0x8000 if self.eof else 0x0000) | (0x4000 if self.compressed > 0 else 0x0000)
        return bytes(struct.pack(">H", header_val) + (self.data if self.data else bytes()))
        ```
    -   **Code Reference:** `RNS/Buffer.py`, lines 88-91 (`StreamDataMessage.unpack`)
        ```python
        self.stream_id = struct.unpack(">H", raw[:2])[0]
        self.eof = (0x8000 & self.stream_id) > 0
        self.compressed = (0x4000 & self.stream_id) > 0
        self.stream_id = self.stream_id & 0x3fff
        ```

## 7. Transport Instance Communication (`RNS/Transport.py`)

### Path Request (Packet.DATA, Packet.NONE context)
Used by clients to request paths or by transport instances to discover paths.

-   **Structure (client to transport)**: `Destination Hash` (16 bytes) + `Request Tag` (16 bytes).
-   **Structure (transport to transport)**: `Destination Hash` (16 bytes) + `Requesting Transport Instance ID` (16 bytes) + `Request Tag` (16 bytes).
    -   **Code Reference:** `RNS/Transport.py`, lines 2646–2672 (`path_request_handler`)
        ```python
        destination_hash = data[:RNS.Identity.TRUNCATED_HASHLENGTH//8]
        requesting_transport_instance = data[RNS.Identity.TRUNCATED_HASHLENGTH//8:(RNS.Identity.TRUNCATED_HASHLENGTH//8)*2]
        tag_bytes = data[RNS.Identity.TRUNCATED_HASHLENGTH//8*2:]
        ```

### Tunnel Synthesis (Packet.DATA, Packet.NONE context)
Used to establish tunnels between transport instances.

-   **Structure**: `Public Key` (64 bytes) + `Interface Hash` (32 bytes) + `Random Hash` (16 bytes) + `Signature` (64 bytes).
    -   **Code Reference:** `RNS/Transport.py`, lines 2120–2132 (`synthesize_tunnel`), 2141–2159 (`tunnel_synthesize_handler`)
        ```python
        public_key     = RNS.Transport.identity.get_public_key()
        random_hash    = RNS.Identity.get_random_hash()
        tunnel_id_data = public_key+interface_hash
        tunnel_id      = RNS.Identity.full_hash(tunnel_id_data) # Hash of public_key+interface_hash
        signed_data    = tunnel_id_data+random_hash
        signature      = Transport.identity.sign(signed_data)
        data           = signed_data+signature
        ```

## 8. Resource Transfer (`RNS/Resource.py`)

### Resource Advertisement (Packet.DATA, Packet.RESOURCE_ADV context)
Used to advertise a resource for transfer.

-   **Structure (packed via umsgpack)**: Dictionary with fields:
    -   `t`: Transfer size (total bytes in segments).
    -   `d`: Total uncompressed data size.
    -   `n`: Number of parts.
    -   `h`: Resource hash.
    -   `r`: Resource random hash.
    -   `o`: Original hash (first segment hash).
    -   `m`: Resource hashmap (concatenation of part hashes).
    -   `f`: Resource flags (bitmask for encrypted, compressed, split, has_metadata, is_request, is_response).
    -   `i`: Segment index.
    -   `l`: Total segments.
    -   `q`: Request ID (if part of a request/response).
    -   `u`: Is request flag.
    -   `p`: Is response flag.
    -   `x`: Has metadata flag.
    -   `c`: Compressed flag.
    -   `e`: Encrypted flag.
    -   `s`: Split flag.
    -   **Code Reference:** `RNS/Resource.py`, lines 1314–1336 (`ResourceAdvertisement.pack`), 1340–1362 (`ResourceAdvertisement.unpack`)
        ```python
        dictionary = {
            "t": self.t,    # Transfer size
            "d": self.d,    # Total uncompressed data size
            "n": self.n,    # Number of parts
            "h": self.h,    # Resource hash
            "r": self.r,    # Resource random hash
            "o": self.o,    # Original hash
            "i": self.i,    # Segment index
            "l": self.l,    # Total segments
            "q": self.q,    # Request ID
            "f": self.f,    # Resource flags
            "m": hashmap
        }
        return umsgpack.packb(dictionary)
        ```
        -   `self.f` flags bitmask logic: `flags = 0x00 | self.x << 5 | self.p << 4 | self.u << 3 | self.s << 2 | self.c << 1 | self.e`
-   **umsgpack:** Resource advertisement and link REQUEST/RESPONSE use the project umsgpack (`RNS/vendor/umsgpack.py`). For byte-compatible resource/link payloads, implementations MUST use the same encoding or a MessagePack profile that matches umsgpack output.
-   **Code Reference:** `RNS/vendor/umsgpack.py`; `RNS/Resource.py` (ResourceAdvertisement pack/unpack); `RNS/Link.py` (response packing).

### Resource Part Request (Packet.DATA, Packet.RESOURCE_REQ context)
Used by a receiver to request specific parts of a resource.

-   **Structure**: `Hashmap Exhausted Flag` (1 byte) + `Last Map Hash` (4 bytes, if exhausted) + `Resource Hash` (32 bytes) + `Requested Part Hashes` (variable length, multiple 4-byte map hashes).
    -   **Code Reference:** `RNS/Resource.py`, lines 920–951 (`request_next`)
        ```python
        hmu_part = bytes([hashmap_exhausted])
        if hashmap_exhausted == Resource.HASHMAP_IS_EXHAUSTED:
            last_map_hash = self.hashmap[self.hashmap_height-1]
            hmu_part += last_map_hash
            self.waiting_for_hmu = True
        request_data = hmu_part + self.hash + requested_hashes
        ```

### Resource Hashmap Update (Packet.DATA, Packet.RESOURCE_HMU context)
Sent by a sender to provide more of the resource hashmap.

-   **Structure**: `Resource Hash` (32 bytes) + `Packed Hashmap Segment` (umsgpack.packb([segment_index, hashmap_data])).
    -   `segment_index`: Integer index of the hashmap segment.
    -   `hashmap_data`: Concatenation of 4-byte map hashes.
    -   **Code Reference:** `RNS/Resource.py`, lines 1041–1043 (`request`, hmu build)
        ```python
        hmu = self.hash+umsgpack.packb([segment, hashmap])
        ```

### Resource Proof (Packet.PROOF, Packet.RESOURCE_PRF context)
Sent by the sender to prove receipt of the full resource.

-   **Structure**: `Resource Hash` (32 bytes, full SHA-256) + `Proof` (32 bytes, `full_hash(resource_data+resource_hash)`).
-   **Code Reference:** `RNS/Resource.py`, lines 741–747 (`prove`).

### Resource hash and map hash sizes
-   Resource hash and original hash: 32 bytes (`RNS.Identity.full_hash`).
-   Map hash (part hash): 4 bytes (`Resource.MAPHASH_LEN`); first 4 bytes of `full_hash(part_data+random_hash)`.
-   **Code Reference:** `RNS/Resource.py`, line 102 (`MAPHASH_LEN`), line 503 (`get_map_hash`).

### Resource encryption and segmentation scope
Reticulum encrypts the **entire** resource payload (data + optional metadata) as a single Link Token ciphertext **before** segmentation. Parts sent in RESOURCE packets are segments of that ciphertext, not individually encrypted blobs.

-   **Rule:** (1) Concatenate metadata (optional) + data: if metadata is present, metadata = 3-byte length (big-endian, high 3 bytes of 32-bit size) + umsgpack-packed metadata; then payload = metadata + data. (2) Optionally compress the payload (e.g. bz2). (3) Prepend random hash (e.g. first 16 bytes of a random hash). (4) Encrypt the result once using the Link's Token (one ciphertext blob). (5) Split that ciphertext into SDU-sized chunks for transmission; each chunk is sent in a RESOURCE-context DATA packet.
-   **Code Reference:** `RNS/Resource.py`, lines 328–331 (metadata + resource_data), 384–418 (optional compress, random_hash + data, `self.link.encrypt(self.data)`), 429–469 (split into parts by sdu).

### Resource Data (Packet.DATA, Packet.RESOURCE context)
Carries a single part (segment) of the resource ciphertext.

-   **Structure**: One SDU-sized segment of the single encrypted resource ciphertext (see "Resource encryption and segmentation scope" above).
    -   **Code Reference:** `RNS/Resource.py`, `__init__` (part data slicing), lines 817–818 (`receive_part`)
        ```python
        data = self.data[i*self.sdu:(i+1)*self.sdu] # Part of raw resource data
        # ...
        part_data = packet.data # Received packet data
        ```

---

## 9. See also (semantics and derivation)

Implementations that encrypt/decrypt these payloads or handle IFAC/umsgpack **MUST** match the behaviour below. Aligning means producing and consuming the same bytes and using the same derivation and dispatch as the reference code.

-   **GROUP and PLAIN destination encryption**  
    **What we're aligning with:** (1) **PLAIN:** no encryption; `encrypt` returns plaintext unchanged, `decrypt` returns ciphertext unchanged. (2) **GROUP:** symmetric-key Token only; the destination holds a single Token key (`prv`); `encrypt(plaintext)` = `self.prv.encrypt(plaintext)`, `decrypt(ciphertext)` = `self.prv.decrypt(ciphertext)` — no ephemeral key, same Token wire format as elsewhere. (3) **When to encrypt:** Packet uses `destination.encrypt(self.data)` for DATA only when the packet is not ANNOUNCE, LINKREQUEST, PROOF (RESOURCE_PRF or LINK), RESOURCE, KEEPALIVE, or CACHE_REQUEST; SINGLE uses identity.encrypt (with optional ratchet); GROUP uses the above; PLAIN returns plaintext.  
    **What aligning looks like:** Same destination-type dispatch; PLAIN never passed through Token; GROUP uses one Token key per destination and Token.encrypt/decrypt only; same packet-type and context rules for when encrypt is called.  
    **Code Reference:** `RNS/Destination.py`, lines 596–664 (`encrypt`, `decrypt`); `RNS/Packet.py`, lines 214–215 (`self.ciphertext = self.destination.encrypt(self.data)`).

-   **Link key derivation**  
    **What we're aligning with:** Link DATA payload is Token-only (no ephemeral prefix). Key is derived once per link: (1) `shared_key = self.prv.exchange(self.peer_pub)` (X25519: initiator private × responder public, or the inverse for the other side). (2) HKDF with `derive_from=shared_key`, `salt=link_id` (16 bytes), `context=None` (passed as `b""`), `length=32` for MODE_AES128_CBC or `64` for MODE_AES256_CBC. (3) All link DATA encrypt/decrypt uses `Token(derived_key)` with that key; no per-packet ephemeral.  
    **What aligning looks like:** Same ECDH role (who uses prv vs peer_pub); same HKDF parameters and length by mode; same Token construction from the derived key; ciphertext on the wire is exactly Token.encrypt(plaintext) / Token.decrypt(ciphertext).  
    **Code Reference:** `RNS/Link.py`, lines 353–367 (`handshake`, HKDF); lines 642–646 (`get_salt` → `link_id`, `get_context` → `None`); lines 1191–1209 (`encrypt`/`decrypt`).

-   **Ratchet decryption and rotation**  
    **What we're aligning with:** (1) **Decryption order:** For SINGLE-destination decrypt, first try each stored ratchet: for each ratchet (X25519 private bytes), `shared_key = ratchet_prv.exchange(peer_pub)` where `peer_pub` is the first 32 bytes of the ciphertext token, then `__decrypt(shared_key, ciphertext)` (same HKDF/Token as identity); first successful try wins. If none succeed, try main identity key (ephemeral 32 bytes + Token). (2) **Ratchet ID:** `full_hash(ratchet_public_bytes)[:NAME_HASH_LENGTH//8]` (10 bytes). (3) **Storage:** When an announce has context_flag set, the ratchet public bytes are remembered for that destination_hash; decrypt and key derivation use the stored ratchet private bytes.  
    **What aligning looks like:** Same try order (ratchets first, then main key); same ratchet ID derivation; same __decrypt (HKDF salt = identity hash, context = None) for each key; same rule for when ratchets are used and updated.  
    **Code Reference:** `RNS/Identity.py`, lines 713–770 (`decrypt`, ratchets loop 730–744, main key 752–756); lines 283–284 (`_get_ratchet_id`); lines 297–306 (`_remember_ratchet`); lines 365–380 (`get_ratchet`).

-   **IFAC and header offsets**  
    **What we're aligning with:** (1) **IFAC key derivation:** `interface.ifac_key` is derived with HKDF(`length=64`, `derive_from=ifac_origin_hash`, `salt=IFAC_SALT`, `context=None`). IFAC_SALT is the 32-byte constant in the constants table (`RNS.Reticulum.IFAC_SALT`). (2) **Outbound:** IFAC = last `ifac_size` bytes of `sign(raw)` with the interface IFAC identity. Packet on wire = `(raw[0]|0x80, raw[1]) + ifac + raw[2:]`; then mask with HKDF(`length=len(raw)+ifac_size`, `derive_from=ifac`, `salt=interface.ifac_key`, `context=None`). Byte 0 replaced by `(byte^mask[0])|0x80`; bytes 1 and indices &gt; 1+ifac_size XORed with mask; bytes at indices 2..1+ifac_size (the IFAC) not masked. (3) **Inbound:** Extract ifac = raw[2:2+ifac_size]; same HKDF for mask; unmask bytes 0, 1, and &gt; 1+ifac_size; reassemble `new_raw = (raw[0]&0x7f, raw[1]) + raw[2+ifac_size:]`; accept iff `ifac == sign(new_raw)[-ifac_size:]`. The canonical header in this document applies to `new_raw`.  
    **What aligning looks like:** Same IFAC_SALT and HKDF for ifac_key; same sign input (full raw outbound, new_raw inbound); same mask HKDF and which bytes are masked/unmasked; byte-for-byte same on-the-wire packet when IFAC is used.  
    **Code Reference:** `RNS/Reticulum.py`, line 152 (IFAC_SALT); lines 821–826, 983–986 (ifac_key HKDF with ifac_salt); `RNS/Transport.py`, lines 894–930 (`transmit`); lines 1245–1283 (`inbound`).

-   **umsgpack (Resource advertisement, HMU, link REQUEST/RESPONSE, LRRTT)**  
    **What we're aligning with:** Resource advertisement is a umsgpack-encoded dict (keys and types as in ResourceAdvertisement.pack). Resource HMU segment is `umsgpack.packb([segment_index, hashmap_bytes])`. Link small response is `umsgpack.packb([request_id, response])`. LRRTT payload is `umsgpack.packb(rtt_float)`. The project uses `RNS/vendor/umsgpack.py`; type codes, integer/float/bytes/dict/list encoding and extension types must match.  
    **What aligning looks like:** For the same logical value (same dict, list, or float), the encoded bytes on the wire MUST be identical. Use the same umsgpack implementation or one that produces byte-identical output for these use cases.  
    **Code Reference:** `RNS/vendor/umsgpack.py`; `RNS/Resource.py`, lines 1314–1336, 1340–1362 (ResourceAdvertisement), 1041–1043 (HMU); `RNS/Link.py`, lines 440–441 (LRRTT), 901 (response).
