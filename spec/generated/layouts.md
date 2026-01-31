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

## RNS.PKT.LAYOUT.PROOF_EXPLICIT
Explicit proof payload: Packet_Hash (32 bytes) + Signature (64 bytes); total 96 bytes. Receiver validates hash matches proved packet and signature over hash.
| Field | Offset | Length |
|-------|--------|--------|
| packet_hash | 0 | 32 |
| signature | 32 | 64 |

## RNS.PKT.LAYOUT.PROOF_IMPLICIT
Implicit proof payload: Signature (64 bytes) only. Receiver infers proved packet by validating signature against pending packets.
| Field | Offset | Length |
|-------|--------|--------|
| signature | 0 | 64 |

## RNS.LNK.LAYOUT.LINKREQUEST_PAYLOAD
Link request payload: Initiator X25519 public key (32 bytes) + Initiator Ed25519 public key (32 bytes) + optional Signalling bytes (3 bytes). Total 64 or 67 bytes.
| Field | Offset | Length |
|-------|--------|--------|
| initiator_x25519 | 0 | 32 |
| initiator_ed25519 | 32 | 32 |
| signalling | 64 | 3 |

## RNS.LNK.LAYOUT.LINKPROOF_PAYLOAD
Link proof (LRPROOF) payload: Ed25519 Signature (64 bytes) + Responder X25519 public key (32 bytes) + optional Signalling bytes (3 bytes). Signed data = link_id + Responder X25519 + Responder Ed25519 + Signalling.
| Field | Offset | Length |
|-------|--------|--------|
| signature | 0 | 64 |
| responder_x25519 | 64 | 32 |
| signalling | 96 | 3 |

## RNS.PKT.LAYOUT.TOKEN
Token (encryption envelope): IV (16 bytes) + AES-256-CBC ciphertext (PKCS7-padded) + HMAC-SHA256 (32 bytes, final 32 bytes of token). Total overhead 48 bytes (TOKEN_OVERHEAD).
| Field | Offset | Length |
|-------|--------|--------|
| iv | 0 | 16 |
| ciphertext | 16 | 0 |

## RNS.PKT.LAYOUT.ANNOUNCE_WITH_RATCHET
Announce payload with ratchet (context flag 1): PublicKey (64) + NameHash (10) + RandomHash (10) + RatchetKey (32) + Signature (64) + optional App Data. Fixed header 176 bytes.
| Field | Offset | Length |
|-------|--------|--------|
| public_key | 0 | 64 |
| name_hash | 64 | 10 |
| random_hash | 74 | 10 |
| ratchet_key | 84 | 32 |
| signature | 116 | 64 |
| app_data | 180 | 0 |

## RNS.PKT.LAYOUT.ANNOUNCE_WITHOUT_RATCHET
Announce payload without ratchet (context flag 0): PublicKey (64) + NameHash (10) + RandomHash (10) + Signature (64) + optional App Data. Fixed header 148 bytes.
| Field | Offset | Length |
|-------|--------|--------|
| public_key | 0 | 64 |
| name_hash | 64 | 10 |
| random_hash | 74 | 10 |
| signature | 84 | 64 |
| app_data | 148 | 0 |

## RNS.LNK.LAYOUT.LINKCLOSE_PAYLOAD
LINKCLOSE payload: link_id (16 bytes), plaintext (no link encryption).
| Field | Offset | Length |
|-------|--------|--------|
| link_id | 0 | 16 |

## RNS.LNK.LAYOUT.LINKIDENTIFY_PAYLOAD
LINKIDENTIFY payload (plaintext before link encrypt): PublicKey (64 bytes) + Signature (64 bytes). Signed data = link_id + identity.get_public_key().
| Field | Offset | Length |
|-------|--------|--------|
| public_key | 0 | 64 |
| signature | 64 | 64 |

## RNS.CHN.LAYOUT.CHANNEL_ENVELOPE
Channel data (context CHANNEL): envelope is MSGTYPE (2 bytes, >H) + Sequence (2 bytes) + Length (2 bytes) + Message Data (variable). Total 6 bytes overhead. MSGTYPE >= 0xf000 reserved for system.
| Field | Offset | Length |
|-------|--------|--------|
| msgtype | 0 | 2 |
| sequence | 2 | 2 |
| length | 4 | 2 |
| data | 6 | 0 |

## RNS.TRN.LAYOUT.PATH_REQUEST_CLIENT
Path request (client to transport): Destination Hash (16 bytes) + Request Tag (16 bytes).
| Field | Offset | Length |
|-------|--------|--------|
| destination_hash | 0 | 16 |
| request_tag | 16 | 16 |

## RNS.TRN.LAYOUT.PATH_REQUEST_TRANSPORT
Path request (transport to transport): Destination Hash (16) + Requesting Transport Instance ID (16) + Request Tag (16).
| Field | Offset | Length |
|-------|--------|--------|
| destination_hash | 0 | 16 |
| requesting_transport_id | 16 | 16 |
| request_tag | 32 | 16 |

## RNS.TRN.LAYOUT.TUNNEL_SYNTHESIS
Tunnel synthesis payload: Public Key (64) + Interface Hash (32) + Random Hash (16) + Signature (64). Signed data = public_key + interface_hash + random_hash.
| Field | Offset | Length |
|-------|--------|--------|
| public_key | 0 | 64 |
| interface_hash | 64 | 32 |
| random_hash | 96 | 16 |
| signature | 112 | 64 |

## RNS.RES.LAYOUT.RESOURCE_ADV
Resource advertisement (RESOURCE_ADV): umsgpack-packed dictionary with keys t (transfer size), d (uncompressed size), n (parts), h (resource hash), r (random hash), o (original hash), m (hashmap), f (flags), i (segment index), l (segments), q (request id), and flag keys u/p/x/c/e/s. Implementations MUST use same encoding for compatibility.
| Field | Offset | Length |
|-------|--------|--------|
| payload | 0 | 0 |

## RNS.RES.LAYOUT.RESOURCE_REQ
Resource part request (RESOURCE_REQ): Hashmap Exhausted (1 byte) + optional Last Map Hash (4 bytes) + Resource Hash (32 bytes) + Requested Part Hashes (4 bytes each).
| Field | Offset | Length |
|-------|--------|--------|
| hashmap_exhausted | 0 | 1 |
| last_map_hash | 1 | 4 |
| resource_hash | 5 | 32 |
| requested_hashes | 37 | 0 |

## RNS.RES.LAYOUT.RESOURCE_HMU
Resource hashmap update (RESOURCE_HMU): Resource Hash (32 bytes) + umsgpack.packb([segment_index, hashmap_bytes]).
| Field | Offset | Length |
|-------|--------|--------|
| resource_hash | 0 | 32 |
| packed_hashmap | 32 | 0 |

## RNS.RES.LAYOUT.RESOURCE_PRF
Resource proof (RESOURCE_PRF): Resource Hash (32 bytes, full SHA-256) + Proof (32 bytes, full_hash(resource_data+resource_hash)).
| Field | Offset | Length |
|-------|--------|--------|
| resource_hash | 0 | 32 |
| proof | 32 | 32 |
