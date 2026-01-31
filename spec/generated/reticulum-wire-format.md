# Reticulum Wire Format (generated from SSOT)

## RNS.PKT.LAYOUT.HEADER_1
- **Kind:** layout
- **Normative:** MUST
- **Statement:** HEADER_1 packets have byte 0 as flags, byte 1 as hops, bytes 2 through 17 as destination hash (16 bytes), and byte 18 as context; total minimum header 19 bytes.
- **References:**
  - RNS/Packet.py (`unpack`) lines 241–272 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:241–272 — unpack — definition</summary>

```py
241:     def unpack(self):
242:         try:
243:             self.flags = self.raw[0]
244:             self.hops  = self.raw[1]
245: 
246:             self.header_type      = (self.flags & 0b01000000) >> 6
247:             self.context_flag     = (self.flags & 0b00100000) >> 5
248:             self.transport_type   = (self.flags & 0b00010000) >> 4
249:             self.destination_type = (self.flags & 0b00001100) >> 2
250:             self.packet_type      = (self.flags & 0b00000011)
251: 
252:             DST_LEN = RNS.Reticulum.TRUNCATED_HASHLENGTH//8
253: 
254:             if self.header_type == Packet.HEADER_2:
255:                 self.transport_id = self.raw[2:DST_LEN+2]
256:                 self.destination_hash = self.raw[DST_LEN+2:2*DST_LEN+2]
257:                 self.context = ord(self.raw[2*DST_LEN+2:2*DST_LEN+3])
258:                 self.data = self.raw[2*DST_LEN+3:]
259:             else:
260:                 self.transport_id = None
261:                 self.destination_hash = self.raw[2:DST_LEN+2]
262:                 self.context = ord(self.raw[DST_LEN+2:DST_LEN+3])
263:                 self.data = self.raw[DST_LEN+3:]
264: 
265:             self.packed = False
266:             self.update_hash()
267:             return True
268: 
269:         except Exception as e:
270:             RNS.log("Received malformed packet, dropping it. The contained exception was: "+str(e), RNS.LOG_EXTREME)
271:             return False
272: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   231:         self.header += bytes([self.context])
   232:         self.raw = self.header + self.ciphertext
   233: 
   234:         if len(self.raw) > self.MTU:
   235:             raise IOError("Packet size of "+str(len(self.raw))+" exceeds MTU of "+str(self.MTU)+" bytes")
   236: 
   237:         self.packed = True
   238:         self.update_hash()
   239: 
   240: 
>> 241:     def unpack(self):
>> 242:         try:
>> 243:             self.flags = self.raw[0]
>> 244:             self.hops  = self.raw[1]
>> 245: 
>> 246:             self.header_type      = (self.flags & 0b01000000) >> 6
>> 247:             self.context_flag     = (self.flags & 0b00100000) >> 5
>> 248:             self.transport_type   = (self.flags & 0b00010000) >> 4
>> 249:             self.destination_type = (self.flags & 0b00001100) >> 2
>> 250:             self.packet_type      = (self.flags & 0b00000011)
>> 251: 
>> 252:             DST_LEN = RNS.Reticulum.TRUNCATED_HASHLENGTH//8
>> 253: 
>> 254:             if self.header_type == Packet.HEADER_2:
>> 255:                 self.transport_id = self.raw[2:DST_LEN+2]
>> 256:                 self.destination_hash = self.raw[DST_LEN+2:2*DST_LEN+2]
>> 257:                 self.context = ord(self.raw[2*DST_LEN+2:2*DST_LEN+3])
>> 258:                 self.data = self.raw[2*DST_LEN+3:]
>> 259:             else:
>> 260:                 self.transport_id = None
>> 261:                 self.destination_hash = self.raw[2:DST_LEN+2]
>> 262:                 self.context = ord(self.raw[DST_LEN+2:DST_LEN+3])
>> 263:                 self.data = self.raw[DST_LEN+3:]
>> 264: 
>> 265:             self.packed = False
>> 266:             self.update_hash()
>> 267:             return True
>> 268: 
>> 269:         except Exception as e:
>> 270:             RNS.log("Received malformed packet, dropping it. The contained exception was: "+str(e), RNS.LOG_EXTREME)
>> 271:             return False
>> 272: 
   273:     def send(self):
   274:         """
   275:         Sends the packet.
   276:         
   277:         :returns: A :ref:`RNS.PacketReceipt<api-packetreceipt>` instance if *create_receipt* was set to *True* when the packet was instantiated, if not returns *None*. If the packet could not be sent *False* is returned.
   278:         """
   279:         if not self.sent:
   280:             if self.destination.type == RNS.Destination.LINK:
   281:                 if self.destination.status == RNS.Link.CLOSED:
   282:                     RNS.log("Attempt to transmit over a closed link, dropping packet", RNS.LOG_DEBUG)
```

    </details>
  - RNS/Packet.py (`pack`) lines 176–235 (implementation)
    <details>
      <summary>Show code: RNS/Packet.py:176–235 — pack — implementation</summary>

```py
176:     def pack(self):
177:         self.destination_hash = self.destination.hash
178:         self.header = b""
179:         self.header += struct.pack("!B", self.flags)
180:         self.header += struct.pack("!B", self.hops)
181: 
182:         if self.context == Packet.LRPROOF:
183:             self.header += self.destination.link_id
184:             self.ciphertext = self.data
185:         else:
186:             if self.header_type == Packet.HEADER_1:
187:                 self.header += self.destination.hash
188: 
189:                 if self.packet_type == Packet.ANNOUNCE:
190:                     # Announce packets are not encrypted
191:                     self.ciphertext = self.data
192:                 elif self.packet_type == Packet.LINKREQUEST:
193:                     # Link request packets are not encrypted
194:                     self.ciphertext = self.data
195:                 elif self.packet_type == Packet.PROOF and self.context == Packet.RESOURCE_PRF:
196:                     # Resource proofs are not encrypted
197:                     self.ciphertext = self.data
198:                 elif self.packet_type == Packet.PROOF and self.destination.type == RNS.Destination.LINK:
199:                     # Packet proofs over links are not encrypted
200:                     self.ciphertext = self.data
201:                 elif self.context == Packet.RESOURCE:
202:                     # A resource takes care of encryption
203:                     # by itself
204:                     self.ciphertext = self.data
205:                 elif self.context == Packet.KEEPALIVE:
206:                     # Keepalive packets contain no actual
207:                     # data
208:                     self.ciphertext = self.data
209:                 elif self.context == Packet.CACHE_REQUEST:
210:                     # Cache-requests are not encrypted
211:                     self.ciphertext = self.data
212:                 else:
213:                     # In all other cases, we encrypt the packet
214:                     # with the destination's encryption method
215:                     self.ciphertext = self.destination.encrypt(self.data)
216:                     if hasattr(self.destination, "latest_ratchet_id"):
217:                         self.ratchet_id = self.destination.latest_ratchet_id
218: 
219:             if self.header_type == Packet.HEADER_2:
220:                 if self.transport_id != None:
221:                     self.header += self.transport_id
222:                     self.header += self.destination.hash
223: 
224:                     if self.packet_type == Packet.ANNOUNCE:
225:                         # Announce packets are not encrypted
226:                         self.ciphertext = self.data
227:                 else:
228:                     raise IOError("Packet with header type 2 must have a transport ID")
229: 
230: 
231:         self.header += bytes([self.context])
232:         self.raw = self.header + self.ciphertext
233: 
234:         if len(self.raw) > self.MTU:
235:             raise IOError("Packet size of "+str(len(self.raw))+" exceeds MTU of "+str(self.MTU)+" bytes")
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   166:         self.q = None
   167: 
   168:     def get_packed_flags(self):
   169:         if self.context == Packet.LRPROOF:
   170:             packed_flags = (self.header_type << 6) | (self.context_flag << 5) | (self.transport_type << 4) | (RNS.Destination.LINK << 2) | self.packet_type
   171:         else:
   172:             packed_flags = (self.header_type << 6) | (self.context_flag << 5) | (self.transport_type << 4) | (self.destination.type << 2) | self.packet_type
   173: 
   174:         return packed_flags
   175: 
>> 176:     def pack(self):
>> 177:         self.destination_hash = self.destination.hash
>> 178:         self.header = b""
>> 179:         self.header += struct.pack("!B", self.flags)
>> 180:         self.header += struct.pack("!B", self.hops)
>> 181: 
>> 182:         if self.context == Packet.LRPROOF:
>> 183:             self.header += self.destination.link_id
>> 184:             self.ciphertext = self.data
>> 185:         else:
>> 186:             if self.header_type == Packet.HEADER_1:
>> 187:                 self.header += self.destination.hash
>> 188: 
>> 189:                 if self.packet_type == Packet.ANNOUNCE:
>> 190:                     # Announce packets are not encrypted
>> 191:                     self.ciphertext = self.data
>> 192:                 elif self.packet_type == Packet.LINKREQUEST:
>> 193:                     # Link request packets are not encrypted
>> 194:                     self.ciphertext = self.data
>> 195:                 elif self.packet_type == Packet.PROOF and self.context == Packet.RESOURCE_PRF:
>> 196:                     # Resource proofs are not encrypted
>> 197:                     self.ciphertext = self.data
>> 198:                 elif self.packet_type == Packet.PROOF and self.destination.type == RNS.Destination.LINK:
>> 199:                     # Packet proofs over links are not encrypted
>> 200:                     self.ciphertext = self.data
>> 201:                 elif self.context == Packet.RESOURCE:
>> 202:                     # A resource takes care of encryption
>> 203:                     # by itself
>> 204:                     self.ciphertext = self.data
>> 205:                 elif self.context == Packet.KEEPALIVE:
>> 206:                     # Keepalive packets contain no actual
>> 207:                     # data
>> 208:                     self.ciphertext = self.data
>> 209:                 elif self.context == Packet.CACHE_REQUEST:
>> 210:                     # Cache-requests are not encrypted
>> 211:                     self.ciphertext = self.data
>> 212:                 else:
>> 213:                     # In all other cases, we encrypt the packet
>> 214:                     # with the destination's encryption method
>> 215:                     self.ciphertext = self.destination.encrypt(self.data)
>> 216:                     if hasattr(self.destination, "latest_ratchet_id"):
>> 217:                         self.ratchet_id = self.destination.latest_ratchet_id
>> 218: 
>> 219:             if self.header_type == Packet.HEADER_2:
>> 220:                 if self.transport_id != None:
>> 221:                     self.header += self.transport_id
>> 222:                     self.header += self.destination.hash
>> 223: 
>> 224:                     if self.packet_type == Packet.ANNOUNCE:
>> 225:                         # Announce packets are not encrypted
>> 226:                         self.ciphertext = self.data
>> 227:                 else:
>> 228:                     raise IOError("Packet with header type 2 must have a transport ID")
>> 229: 
>> 230: 
>> 231:         self.header += bytes([self.context])
>> 232:         self.raw = self.header + self.ciphertext
>> 233: 
>> 234:         if len(self.raw) > self.MTU:
>> 235:             raise IOError("Packet size of "+str(len(self.raw))+" exceeds MTU of "+str(self.MTU)+" bytes")
   236: 
   237:         self.packed = True
   238:         self.update_hash()
   239: 
   240: 
   241:     def unpack(self):
   242:         try:
   243:             self.flags = self.raw[0]
   244:             self.hops  = self.raw[1]
   245: 
```

    </details>
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
  - RNS/Packet.py (`unpack`) lines 241–272 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:241–272 — unpack — definition</summary>

```py
241:     def unpack(self):
242:         try:
243:             self.flags = self.raw[0]
244:             self.hops  = self.raw[1]
245: 
246:             self.header_type      = (self.flags & 0b01000000) >> 6
247:             self.context_flag     = (self.flags & 0b00100000) >> 5
248:             self.transport_type   = (self.flags & 0b00010000) >> 4
249:             self.destination_type = (self.flags & 0b00001100) >> 2
250:             self.packet_type      = (self.flags & 0b00000011)
251: 
252:             DST_LEN = RNS.Reticulum.TRUNCATED_HASHLENGTH//8
253: 
254:             if self.header_type == Packet.HEADER_2:
255:                 self.transport_id = self.raw[2:DST_LEN+2]
256:                 self.destination_hash = self.raw[DST_LEN+2:2*DST_LEN+2]
257:                 self.context = ord(self.raw[2*DST_LEN+2:2*DST_LEN+3])
258:                 self.data = self.raw[2*DST_LEN+3:]
259:             else:
260:                 self.transport_id = None
261:                 self.destination_hash = self.raw[2:DST_LEN+2]
262:                 self.context = ord(self.raw[DST_LEN+2:DST_LEN+3])
263:                 self.data = self.raw[DST_LEN+3:]
264: 
265:             self.packed = False
266:             self.update_hash()
267:             return True
268: 
269:         except Exception as e:
270:             RNS.log("Received malformed packet, dropping it. The contained exception was: "+str(e), RNS.LOG_EXTREME)
271:             return False
272: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   231:         self.header += bytes([self.context])
   232:         self.raw = self.header + self.ciphertext
   233: 
   234:         if len(self.raw) > self.MTU:
   235:             raise IOError("Packet size of "+str(len(self.raw))+" exceeds MTU of "+str(self.MTU)+" bytes")
   236: 
   237:         self.packed = True
   238:         self.update_hash()
   239: 
   240: 
>> 241:     def unpack(self):
>> 242:         try:
>> 243:             self.flags = self.raw[0]
>> 244:             self.hops  = self.raw[1]
>> 245: 
>> 246:             self.header_type      = (self.flags & 0b01000000) >> 6
>> 247:             self.context_flag     = (self.flags & 0b00100000) >> 5
>> 248:             self.transport_type   = (self.flags & 0b00010000) >> 4
>> 249:             self.destination_type = (self.flags & 0b00001100) >> 2
>> 250:             self.packet_type      = (self.flags & 0b00000011)
>> 251: 
>> 252:             DST_LEN = RNS.Reticulum.TRUNCATED_HASHLENGTH//8
>> 253: 
>> 254:             if self.header_type == Packet.HEADER_2:
>> 255:                 self.transport_id = self.raw[2:DST_LEN+2]
>> 256:                 self.destination_hash = self.raw[DST_LEN+2:2*DST_LEN+2]
>> 257:                 self.context = ord(self.raw[2*DST_LEN+2:2*DST_LEN+3])
>> 258:                 self.data = self.raw[2*DST_LEN+3:]
>> 259:             else:
>> 260:                 self.transport_id = None
>> 261:                 self.destination_hash = self.raw[2:DST_LEN+2]
>> 262:                 self.context = ord(self.raw[DST_LEN+2:DST_LEN+3])
>> 263:                 self.data = self.raw[DST_LEN+3:]
>> 264: 
>> 265:             self.packed = False
>> 266:             self.update_hash()
>> 267:             return True
>> 268: 
>> 269:         except Exception as e:
>> 270:             RNS.log("Received malformed packet, dropping it. The contained exception was: "+str(e), RNS.LOG_EXTREME)
>> 271:             return False
>> 272: 
   273:     def send(self):
   274:         """
   275:         Sends the packet.
   276:         
   277:         :returns: A :ref:`RNS.PacketReceipt<api-packetreceipt>` instance if *create_receipt* was set to *True* when the packet was instantiated, if not returns *None*. If the packet could not be sent *False* is returned.
   278:         """
   279:         if not self.sent:
   280:             if self.destination.type == RNS.Destination.LINK:
   281:                 if self.destination.status == RNS.Link.CLOSED:
   282:                     RNS.log("Attempt to transmit over a closed link, dropping packet", RNS.LOG_DEBUG)
```

    </details>
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
  - RNS/Reticulum.py (`HEADER_MINSIZE`) lines 147–154 (definition)
    <details>
      <summary>Show code: RNS/Reticulum.py:147–154 — HEADER_MINSIZE — definition</summary>

```py
147:     TRUNCATED_HASHLENGTH = 128
148: 
149:     HEADER_MINSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*1
150:     HEADER_MAXSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*2
151:     IFAC_MIN_SIZE    = 1
152:     IFAC_SALT        = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
153:     
154:     MDU              = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   137:     """
   138:     Minimum bitrate required across a medium for Reticulum to be able
   139:     to successfully establish links. Currently 5 bits per second.
   140:     """
   141: 
   142:     # TODO: Let Reticulum somehow continously build a map of per-hop
   143:     # latencies and use this map for global timeout calculation.
   144:     DEFAULT_PER_HOP_TIMEOUT = 6
   145: 
   146:     # Length of truncated hashes in bits.
>> 147:     TRUNCATED_HASHLENGTH = 128
>> 148: 
>> 149:     HEADER_MINSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*1
>> 150:     HEADER_MAXSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*2
>> 151:     IFAC_MIN_SIZE    = 1
>> 152:     IFAC_SALT        = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
>> 153:     
>> 154:     MDU              = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
   155: 
   156:     RESOURCE_CACHE   = 24*60*60
   157:     JOB_INTERVAL     = 5*60
   158:     CLEAN_INTERVAL   = 15*60
   159:     PERSIST_INTERVAL = 60*60*12
   160:     GRACIOUS_PERSIST_INTERVAL = 60*5
   161: 
   162:     router           = None
   163:     config           = None
   164:     
```

    </details>
- **Value:** {'number': 19, 'unit': 'bytes'}

## RNS.PKT.CONST.HEADER_MAXSIZE
- **Kind:** constant
- **Normative:** MUST
- **Statement:** The maximum packet header size is 35 bytes (flags, hops, transport_id, destination hash, context).
- **References:**
  - RNS/Reticulum.py (`HEADER_MAXSIZE`) lines 147–154 (definition)
    <details>
      <summary>Show code: RNS/Reticulum.py:147–154 — HEADER_MAXSIZE — definition</summary>

```py
147:     TRUNCATED_HASHLENGTH = 128
148: 
149:     HEADER_MINSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*1
150:     HEADER_MAXSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*2
151:     IFAC_MIN_SIZE    = 1
152:     IFAC_SALT        = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
153:     
154:     MDU              = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   137:     """
   138:     Minimum bitrate required across a medium for Reticulum to be able
   139:     to successfully establish links. Currently 5 bits per second.
   140:     """
   141: 
   142:     # TODO: Let Reticulum somehow continously build a map of per-hop
   143:     # latencies and use this map for global timeout calculation.
   144:     DEFAULT_PER_HOP_TIMEOUT = 6
   145: 
   146:     # Length of truncated hashes in bits.
>> 147:     TRUNCATED_HASHLENGTH = 128
>> 148: 
>> 149:     HEADER_MINSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*1
>> 150:     HEADER_MAXSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*2
>> 151:     IFAC_MIN_SIZE    = 1
>> 152:     IFAC_SALT        = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
>> 153:     
>> 154:     MDU              = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
   155: 
   156:     RESOURCE_CACHE   = 24*60*60
   157:     JOB_INTERVAL     = 5*60
   158:     CLEAN_INTERVAL   = 15*60
   159:     PERSIST_INTERVAL = 60*60*12
   160:     GRACIOUS_PERSIST_INTERVAL = 60*5
   161: 
   162:     router           = None
   163:     config           = None
   164:     
```

    </details>
- **Value:** {'number': 35, 'unit': 'bytes'}

## RNS.PKT.ALG.FLAGS_PACK_UNPACK
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** The flags byte is packed and unpacked as follows: bit 7 IFAC-present (0x80, see RNS.IFAC.CONST.IFAC_FLAG_BIT); bit 6 header type (0=HEADER_1, 1=HEADER_2); bit 5 context flag; bit 4 transport type; bits 3-2 destination type; bits 1-0 packet type. When packing from packet fields, the IFAC bit is not set by the packet layer; transport sets bit 7 on the wire when IFAC is present.
- **References:**
  - RNS/Packet.py (`get_packed_flags`) lines 168–174 (implementation)
    <details>
      <summary>Show code: RNS/Packet.py:168–174 — get_packed_flags — implementation</summary>

```py
168:     def get_packed_flags(self):
169:         if self.context == Packet.LRPROOF:
170:             packed_flags = (self.header_type << 6) | (self.context_flag << 5) | (self.transport_type << 4) | (RNS.Destination.LINK << 2) | self.packet_type
171:         else:
172:             packed_flags = (self.header_type << 6) | (self.context_flag << 5) | (self.transport_type << 4) | (self.destination.type << 2) | self.packet_type
173: 
174:         return packed_flags
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   158:         self.sent_at     = None
   159:         self.packet_hash = None
   160:         self.ratchet_id  = None
   161: 
   162:         self.attached_interface = attached_interface
   163:         self.receiving_interface = None
   164:         self.rssi = None
   165:         self.snr = None
   166:         self.q = None
   167: 
>> 168:     def get_packed_flags(self):
>> 169:         if self.context == Packet.LRPROOF:
>> 170:             packed_flags = (self.header_type << 6) | (self.context_flag << 5) | (self.transport_type << 4) | (RNS.Destination.LINK << 2) | self.packet_type
>> 171:         else:
>> 172:             packed_flags = (self.header_type << 6) | (self.context_flag << 5) | (self.transport_type << 4) | (self.destination.type << 2) | self.packet_type
>> 173: 
>> 174:         return packed_flags
   175: 
   176:     def pack(self):
   177:         self.destination_hash = self.destination.hash
   178:         self.header = b""
   179:         self.header += struct.pack("!B", self.flags)
   180:         self.header += struct.pack("!B", self.hops)
   181: 
   182:         if self.context == Packet.LRPROOF:
   183:             self.header += self.destination.link_id
   184:             self.ciphertext = self.data
```

    </details>
  - RNS/Packet.py (`unpack`) lines 241–252 (implementation)
    <details>
      <summary>Show code: RNS/Packet.py:241–252 — unpack — implementation</summary>

```py
241:     def unpack(self):
242:         try:
243:             self.flags = self.raw[0]
244:             self.hops  = self.raw[1]
245: 
246:             self.header_type      = (self.flags & 0b01000000) >> 6
247:             self.context_flag     = (self.flags & 0b00100000) >> 5
248:             self.transport_type   = (self.flags & 0b00010000) >> 4
249:             self.destination_type = (self.flags & 0b00001100) >> 2
250:             self.packet_type      = (self.flags & 0b00000011)
251: 
252:             DST_LEN = RNS.Reticulum.TRUNCATED_HASHLENGTH//8
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   231:         self.header += bytes([self.context])
   232:         self.raw = self.header + self.ciphertext
   233: 
   234:         if len(self.raw) > self.MTU:
   235:             raise IOError("Packet size of "+str(len(self.raw))+" exceeds MTU of "+str(self.MTU)+" bytes")
   236: 
   237:         self.packed = True
   238:         self.update_hash()
   239: 
   240: 
>> 241:     def unpack(self):
>> 242:         try:
>> 243:             self.flags = self.raw[0]
>> 244:             self.hops  = self.raw[1]
>> 245: 
>> 246:             self.header_type      = (self.flags & 0b01000000) >> 6
>> 247:             self.context_flag     = (self.flags & 0b00100000) >> 5
>> 248:             self.transport_type   = (self.flags & 0b00010000) >> 4
>> 249:             self.destination_type = (self.flags & 0b00001100) >> 2
>> 250:             self.packet_type      = (self.flags & 0b00000011)
>> 251: 
>> 252:             DST_LEN = RNS.Reticulum.TRUNCATED_HASHLENGTH//8
   253: 
   254:             if self.header_type == Packet.HEADER_2:
   255:                 self.transport_id = self.raw[2:DST_LEN+2]
   256:                 self.destination_hash = self.raw[DST_LEN+2:2*DST_LEN+2]
   257:                 self.context = ord(self.raw[2*DST_LEN+2:2*DST_LEN+3])
   258:                 self.data = self.raw[2*DST_LEN+3:]
   259:             else:
   260:                 self.transport_id = None
   261:                 self.destination_hash = self.raw[2:DST_LEN+2]
   262:                 self.context = ord(self.raw[DST_LEN+2:DST_LEN+3])
```

    </details>
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
  - RNS/Packet.py (`get_hashable_part`) lines 353–359 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:353–359 — get_hashable_part — definition</summary>

```py
353: 
354:     def get_hashable_part(self):
355:         hashable_part = bytes([self.raw[0] & 0b00001111])
356:         if self.header_type == Packet.HEADER_2:
357:             hashable_part += self.raw[(RNS.Identity.TRUNCATED_HASHLENGTH//8)+2:]
358:         else:
359:             hashable_part += self.raw[2:]
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   343:         return self.receipt.validate_proof(proof)
   344: 
   345:     def update_hash(self):
   346:         self.packet_hash = self.get_hash()
   347: 
   348:     def get_hash(self):
   349:         return RNS.Identity.full_hash(self.get_hashable_part())
   350: 
   351:     def getTruncatedHash(self):
   352:         return RNS.Identity.truncated_hash(self.get_hashable_part())
>> 353: 
>> 354:     def get_hashable_part(self):
>> 355:         hashable_part = bytes([self.raw[0] & 0b00001111])
>> 356:         if self.header_type == Packet.HEADER_2:
>> 357:             hashable_part += self.raw[(RNS.Identity.TRUNCATED_HASHLENGTH//8)+2:]
>> 358:         else:
>> 359:             hashable_part += self.raw[2:]
   360: 
   361:         return hashable_part
   362: 
   363:     def get_rssi(self):
   364:         """
   365:         :returns: The physical layer *Received Signal Strength Indication* if available, otherwise ``None``.
   366:         """
   367:         if self.rssi != None:
   368:             return self.rssi
   369:         else:
```

    </details>
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
  - RNS/Identity.py (`truncated_hash`) lines 247–256 (definition)
    <details>
      <summary>Show code: RNS/Identity.py:247–256 — truncated_hash — definition</summary>

```py
247: 
248:     @staticmethod
249:     def truncated_hash(data):
250:         """
251:         Get a truncated SHA-256 hash of passed data.
252: 
253:         :param data: Data to be hashed as *bytes*.
254:         :returns: Truncated SHA-256 hash as *bytes*.
255:         """
256:         return Identity.full_hash(data)[:(Identity.TRUNCATED_HASHLENGTH//8)]
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   237: 
   238:     @staticmethod
   239:     def full_hash(data):
   240:         """
   241:         Get a SHA-256 hash of passed data.
   242: 
   243:         :param data: Data to be hashed as *bytes*.
   244:         :returns: SHA-256 hash as *bytes*.
   245:         """
   246:         return RNS.Cryptography.sha256(data)
>> 247: 
>> 248:     @staticmethod
>> 249:     def truncated_hash(data):
>> 250:         """
>> 251:         Get a truncated SHA-256 hash of passed data.
>> 252: 
>> 253:         :param data: Data to be hashed as *bytes*.
>> 254:         :returns: Truncated SHA-256 hash as *bytes*.
>> 255:         """
>> 256:         return Identity.full_hash(data)[:(Identity.TRUNCATED_HASHLENGTH//8)]
   257: 
   258:     @staticmethod
   259:     def get_random_hash():
   260:         """
   261:         Get a random SHA-256 hash.
   262: 
   263:         :param data: Data to be hashed as *bytes*.
   264:         :returns: Truncated SHA-256 hash of random data as *bytes*.
   265:         """
   266:         return Identity.truncated_hash(os.urandom(Identity.TRUNCATED_HASHLENGTH//8))
```

    </details>
  - RNS/Identity.py (`full_hash`) lines 238–246 (derivation)
    <details>
      <summary>Show code: RNS/Identity.py:238–246 — full_hash — derivation</summary>

```py
238:     @staticmethod
239:     def full_hash(data):
240:         """
241:         Get a SHA-256 hash of passed data.
242: 
243:         :param data: Data to be hashed as *bytes*.
244:         :returns: SHA-256 hash as *bytes*.
245:         """
246:         return RNS.Cryptography.sha256(data)
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   228:                     if len(known_destination) == RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
   229:                         Identity.known_destinations[known_destination] = loaded_known_destinations[known_destination]
   230: 
   231:                 RNS.log("Loaded "+str(len(Identity.known_destinations))+" known destination from storage", RNS.LOG_VERBOSE)
   232: 
   233:             except Exception as e:
   234:                 RNS.log("Error loading known destinations from disk, file will be recreated on exit", RNS.LOG_ERROR)
   235:         else:
   236:             RNS.log("Destinations file does not exist, no known destinations loaded", RNS.LOG_VERBOSE)
   237: 
>> 238:     @staticmethod
>> 239:     def full_hash(data):
>> 240:         """
>> 241:         Get a SHA-256 hash of passed data.
>> 242: 
>> 243:         :param data: Data to be hashed as *bytes*.
>> 244:         :returns: SHA-256 hash as *bytes*.
>> 245:         """
>> 246:         return RNS.Cryptography.sha256(data)
   247: 
   248:     @staticmethod
   249:     def truncated_hash(data):
   250:         """
   251:         Get a truncated SHA-256 hash of passed data.
   252: 
   253:         :param data: Data to be hashed as *bytes*.
   254:         :returns: Truncated SHA-256 hash as *bytes*.
   255:         """
   256:         return Identity.full_hash(data)[:(Identity.TRUNCATED_HASHLENGTH//8)]
```

    </details>
- **Steps:**
  - Compute full_hash = SHA-256(data).
  - Return full_hash[0:(TRUNCATED_HASHLENGTH//8)]; TRUNCATED_HASHLENGTH is 128 bits.

## RNS.LNK.ALG.LINK_ID_FROM_LINKREQUEST
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** Link ID is the truncated hash (first 16 bytes of SHA-256) of the hashable part with signalling bytes stripped when payload length exceeds 64 bytes.
- **References:**
  - RNS/Link.py (`link_id_from_lr_packet`) lines 340–346 (definition)
    <details>
      <summary>Show code: RNS/Link.py:340–346 — link_id_from_lr_packet — definition</summary>

```py
340:     @staticmethod
341:     def link_id_from_lr_packet(packet):
342:         hashable_part = packet.get_hashable_part()
343:         if len(packet.data) > Link.ECPUBSIZE:
344:             diff = len(packet.data) - Link.ECPUBSIZE
345:             hashable_part = hashable_part[:-diff]
346: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   330:     def load_peer(self, peer_pub_bytes, peer_sig_pub_bytes):
   331:         self.peer_pub_bytes = peer_pub_bytes
   332:         self.peer_pub = X25519PublicKey.from_public_bytes(self.peer_pub_bytes)
   333: 
   334:         self.peer_sig_pub_bytes = peer_sig_pub_bytes
   335:         self.peer_sig_pub = Ed25519PublicKey.from_public_bytes(self.peer_sig_pub_bytes)
   336: 
   337:         if not hasattr(self.peer_pub, "curve"):
   338:             self.peer_pub.curve = Link.CURVE
   339: 
>> 340:     @staticmethod
>> 341:     def link_id_from_lr_packet(packet):
>> 342:         hashable_part = packet.get_hashable_part()
>> 343:         if len(packet.data) > Link.ECPUBSIZE:
>> 344:             diff = len(packet.data) - Link.ECPUBSIZE
>> 345:             hashable_part = hashable_part[:-diff]
>> 346: 
   347:         return RNS.Identity.truncated_hash(hashable_part)
   348: 
   349:     def set_link_id(self, packet):
   350:         self.link_id = Link.link_id_from_lr_packet(packet)
   351:         self.hash = self.link_id
   352: 
   353:     def handshake(self):
   354:         if self.status == Link.PENDING and self.prv != None:
   355:             self.status = Link.HANDSHAKE
   356:             self.shared_key = self.prv.exchange(self.peer_pub)
```

    </details>
- **Steps:**
  - Obtain hashable_part = packet.get_hashable_part().
  - If len(packet.data) > ECPUBSIZE (64), set hashable_part = hashable_part[:-diff] where diff = len(packet.data) - ECPUBSIZE.
  - Return RNS.Identity.truncated_hash(hashable_part).

## RNS.LNK.CONST.LINK_MTU_SIZE
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Signalling bytes are exactly 3 bytes on the wire.
- **References:**
  - RNS/Link.py (`LINK_MTU_SIZE`) lines 78–81 (definition)
    <details>
      <summary>Show code: RNS/Link.py:78–81 — LINK_MTU_SIZE — definition</summary>

```py
78:     """
79: 
80:     LINK_MTU_SIZE            = 3
81:     TRAFFIC_TIMEOUT_MIN_MS   = 5
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   68:     """
   69: 
   70:     ECPUBSIZE         = 32+32
   71:     KEYSIZE           = 32
   72: 
   73:     MDU = math.floor((RNS.Reticulum.MTU-RNS.Reticulum.IFAC_MIN_SIZE-RNS.Reticulum.HEADER_MINSIZE-RNS.Identity.TOKEN_OVERHEAD)/RNS.Identity.AES128_BLOCKSIZE)*RNS.Identity.AES128_BLOCKSIZE - 1
   74: 
   75:     ESTABLISHMENT_TIMEOUT_PER_HOP = RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT
   76:     """
   77:     Timeout for link establishment in seconds per hop to destination.
>> 78:     """
>> 79: 
>> 80:     LINK_MTU_SIZE            = 3
>> 81:     TRAFFIC_TIMEOUT_MIN_MS   = 5
   82:     TRAFFIC_TIMEOUT_FACTOR   = 6
   83:     KEEPALIVE_MAX_RTT        = 1.75
   84:     KEEPALIVE_TIMEOUT_FACTOR = 4
   85:     """
   86:     RTT timeout factor used in link timeout calculation.
   87:     """
   88:     STALE_GRACE = 5
   89:     """
   90:     Grace period in seconds used in link timeout calculation.
   91:     """
```

    </details>
- **Value:** {'number': 3, 'unit': 'bytes'}

## RNS.LNK.CONST.MTU_BYTEMASK
- **Kind:** constant
- **Normative:** MUST
- **Statement:** The MTU value in signalling bytes is encoded in 21 bits; the byte mask for the MTU field is 0x1FFFFF.
- **References:**
  - RNS/Link.py (`MTU_BYTEMASK`) lines 144–145 (definition)
    <details>
      <summary>Show code: RNS/Link.py:144–145 — MTU_BYTEMASK — definition</summary>

```py
144:     MTU_BYTEMASK        = 0x1FFFFF
145:     MODE_BYTEMASK       = 0xE0
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   134:     MODE_DEFAULT        =  MODE_AES256_CBC
   135:     MODE_DESCRIPTIONS   = {MODE_AES128_CBC: "AES_128_CBC",
   136:                            MODE_AES256_CBC: "AES_256_CBC",
   137:                            MODE_AES256_GCM: "MODE_AES256_GCM",
   138:                            MODE_OTP_RESERVED: "MODE_OTP_RESERVED",
   139:                            MODE_PQ_RESERVED_1: "MODE_PQ_RESERVED_1",
   140:                            MODE_PQ_RESERVED_2: "MODE_PQ_RESERVED_2",
   141:                            MODE_PQ_RESERVED_3: "MODE_PQ_RESERVED_3",
   142:                            MODE_PQ_RESERVED_4: "MODE_PQ_RESERVED_4"}
   143: 
>> 144:     MTU_BYTEMASK        = 0x1FFFFF
>> 145:     MODE_BYTEMASK       = 0xE0
   146: 
   147:     @staticmethod
   148:     def signalling_bytes(mtu, mode):
   149:         if not mode in Link.ENABLED_MODES: raise TypeError(f"Requested link mode {Link.MODE_DESCRIPTIONS[mode]} not enabled")
   150:         signalling_value = (mtu & Link.MTU_BYTEMASK)+(((mode<<5) & Link.MODE_BYTEMASK)<<16)
   151:         return struct.pack(">I", signalling_value)[1:]
   152: 
   153:     @staticmethod
   154:     def mtu_from_lr_packet(packet):
   155:         if len(packet.data) == Link.ECPUBSIZE+Link.LINK_MTU_SIZE:
```

    </details>
- **Value:** {'number': 2097151, 'unit': 'byte mask', 'format': '0x1FFFFF', 'max_reasonable': 2097151}

## RNS.LNK.CONST.MODE_BYTEMASK
- **Kind:** constant
- **Normative:** MUST
- **Statement:** The mode value in signalling bytes occupies the top 3 bits of the first byte; the byte mask is 0xE0.
- **References:**
  - RNS/Link.py (`MODE_BYTEMASK`) lines 144–145 (definition)
    <details>
      <summary>Show code: RNS/Link.py:144–145 — MODE_BYTEMASK — definition</summary>

```py
144:     MTU_BYTEMASK        = 0x1FFFFF
145:     MODE_BYTEMASK       = 0xE0
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   134:     MODE_DEFAULT        =  MODE_AES256_CBC
   135:     MODE_DESCRIPTIONS   = {MODE_AES128_CBC: "AES_128_CBC",
   136:                            MODE_AES256_CBC: "AES_256_CBC",
   137:                            MODE_AES256_GCM: "MODE_AES256_GCM",
   138:                            MODE_OTP_RESERVED: "MODE_OTP_RESERVED",
   139:                            MODE_PQ_RESERVED_1: "MODE_PQ_RESERVED_1",
   140:                            MODE_PQ_RESERVED_2: "MODE_PQ_RESERVED_2",
   141:                            MODE_PQ_RESERVED_3: "MODE_PQ_RESERVED_3",
   142:                            MODE_PQ_RESERVED_4: "MODE_PQ_RESERVED_4"}
   143: 
>> 144:     MTU_BYTEMASK        = 0x1FFFFF
>> 145:     MODE_BYTEMASK       = 0xE0
   146: 
   147:     @staticmethod
   148:     def signalling_bytes(mtu, mode):
   149:         if not mode in Link.ENABLED_MODES: raise TypeError(f"Requested link mode {Link.MODE_DESCRIPTIONS[mode]} not enabled")
   150:         signalling_value = (mtu & Link.MTU_BYTEMASK)+(((mode<<5) & Link.MODE_BYTEMASK)<<16)
   151:         return struct.pack(">I", signalling_value)[1:]
   152: 
   153:     @staticmethod
   154:     def mtu_from_lr_packet(packet):
   155:         if len(packet.data) == Link.ECPUBSIZE+Link.LINK_MTU_SIZE:
```

    </details>
- **Value:** {'number': 224, 'unit': 'byte mask', 'format': '0xE0'}

## RNS.LNK.ALG.SIGNALLING_ENCODE
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** Signalling bytes encode MTU (21 bits) and mode (3 bits) as three big-endian bytes; byte0 = (mode<<5)|(MTU>>16), byte1 = (MTU>>8)&0xFF, byte2 = MTU&0xFF.
- **References:**
  - RNS/Link.py (`signalling_bytes`) lines 146–150 (definition)
    <details>
      <summary>Show code: RNS/Link.py:146–150 — signalling_bytes — definition</summary>

```py
146: 
147:     @staticmethod
148:     def signalling_bytes(mtu, mode):
149:         if not mode in Link.ENABLED_MODES: raise TypeError(f"Requested link mode {Link.MODE_DESCRIPTIONS[mode]} not enabled")
150:         signalling_value = (mtu & Link.MTU_BYTEMASK)+(((mode<<5) & Link.MODE_BYTEMASK)<<16)
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   136:                            MODE_AES256_CBC: "AES_256_CBC",
   137:                            MODE_AES256_GCM: "MODE_AES256_GCM",
   138:                            MODE_OTP_RESERVED: "MODE_OTP_RESERVED",
   139:                            MODE_PQ_RESERVED_1: "MODE_PQ_RESERVED_1",
   140:                            MODE_PQ_RESERVED_2: "MODE_PQ_RESERVED_2",
   141:                            MODE_PQ_RESERVED_3: "MODE_PQ_RESERVED_3",
   142:                            MODE_PQ_RESERVED_4: "MODE_PQ_RESERVED_4"}
   143: 
   144:     MTU_BYTEMASK        = 0x1FFFFF
   145:     MODE_BYTEMASK       = 0xE0
>> 146: 
>> 147:     @staticmethod
>> 148:     def signalling_bytes(mtu, mode):
>> 149:         if not mode in Link.ENABLED_MODES: raise TypeError(f"Requested link mode {Link.MODE_DESCRIPTIONS[mode]} not enabled")
>> 150:         signalling_value = (mtu & Link.MTU_BYTEMASK)+(((mode<<5) & Link.MODE_BYTEMASK)<<16)
   151:         return struct.pack(">I", signalling_value)[1:]
   152: 
   153:     @staticmethod
   154:     def mtu_from_lr_packet(packet):
   155:         if len(packet.data) == Link.ECPUBSIZE+Link.LINK_MTU_SIZE:
   156:             return (packet.data[Link.ECPUBSIZE] << 16) + (packet.data[Link.ECPUBSIZE+1] << 8) + (packet.data[Link.ECPUBSIZE+2]) & Link.MTU_BYTEMASK
   157:         else: return None
   158: 
   159:     @staticmethod
   160:     def mtu_from_lp_packet(packet):
```

    </details>
- **Steps:**
  - Pack signalling_value = (mtu & MTU_BYTEMASK) + (((mode<<5) & MODE_BYTEMASK)<<16).
  - Pack as big-endian 32-bit unsigned integer and take bytes [1:4] (drop high byte).
  - Return the 3-byte sequence.

## RNS.LNK.ALG.SIGNALLING_DECODE
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** Signalling bytes decode as mode = (byte0>>5)&0x07 and MTU = ((byte0&0x1F)<<16)|(byte1<<8)|byte2.
- **References:**
  - RNS/Link.py (`mtu_from_lr_packet`) lines 152–156 (implementation)
    <details>
      <summary>Show code: RNS/Link.py:152–156 — mtu_from_lr_packet — implementation</summary>

```py
152: 
153:     @staticmethod
154:     def mtu_from_lr_packet(packet):
155:         if len(packet.data) == Link.ECPUBSIZE+Link.LINK_MTU_SIZE:
156:             return (packet.data[Link.ECPUBSIZE] << 16) + (packet.data[Link.ECPUBSIZE+1] << 8) + (packet.data[Link.ECPUBSIZE+2]) & Link.MTU_BYTEMASK
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   142:                            MODE_PQ_RESERVED_4: "MODE_PQ_RESERVED_4"}
   143: 
   144:     MTU_BYTEMASK        = 0x1FFFFF
   145:     MODE_BYTEMASK       = 0xE0
   146: 
   147:     @staticmethod
   148:     def signalling_bytes(mtu, mode):
   149:         if not mode in Link.ENABLED_MODES: raise TypeError(f"Requested link mode {Link.MODE_DESCRIPTIONS[mode]} not enabled")
   150:         signalling_value = (mtu & Link.MTU_BYTEMASK)+(((mode<<5) & Link.MODE_BYTEMASK)<<16)
   151:         return struct.pack(">I", signalling_value)[1:]
>> 152: 
>> 153:     @staticmethod
>> 154:     def mtu_from_lr_packet(packet):
>> 155:         if len(packet.data) == Link.ECPUBSIZE+Link.LINK_MTU_SIZE:
>> 156:             return (packet.data[Link.ECPUBSIZE] << 16) + (packet.data[Link.ECPUBSIZE+1] << 8) + (packet.data[Link.ECPUBSIZE+2]) & Link.MTU_BYTEMASK
   157:         else: return None
   158: 
   159:     @staticmethod
   160:     def mtu_from_lp_packet(packet):
   161:         if len(packet.data) == RNS.Identity.SIGLENGTH//8+Link.ECPUBSIZE//2+Link.LINK_MTU_SIZE:
   162:             mtu_bytes = packet.data[RNS.Identity.SIGLENGTH//8+Link.ECPUBSIZE//2:RNS.Identity.SIGLENGTH//8+Link.ECPUBSIZE//2+Link.LINK_MTU_SIZE]
   163:             return (mtu_bytes[0] << 16) + (mtu_bytes[1] << 8) + (mtu_bytes[2]) & Link.MTU_BYTEMASK
   164:         else: return None
   165: 
   166:     @staticmethod
```

    </details>
  - RNS/Link.py (`mode_from_lr_packet`) lines 172–176 (implementation)
    <details>
      <summary>Show code: RNS/Link.py:172–176 — mode_from_lr_packet — implementation</summary>

```py
172:     def mode_from_lr_packet(packet):
173:         if len(packet.data) > Link.ECPUBSIZE:
174:             mode = (packet.data[Link.ECPUBSIZE] & Link.MODE_BYTEMASK) >> 5
175:             return mode
176:         else: return Link.MODE_DEFAULT
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   162:             mtu_bytes = packet.data[RNS.Identity.SIGLENGTH//8+Link.ECPUBSIZE//2:RNS.Identity.SIGLENGTH//8+Link.ECPUBSIZE//2+Link.LINK_MTU_SIZE]
   163:             return (mtu_bytes[0] << 16) + (mtu_bytes[1] << 8) + (mtu_bytes[2]) & Link.MTU_BYTEMASK
   164:         else: return None
   165: 
   166:     @staticmethod
   167:     def mode_byte(mode):
   168:         if mode in Link.ENABLED_MODES: return (mode << 5) & Link.MODE_BYTEMASK
   169:         else: raise TypeError(f"Requested link mode {mode} not enabled")
   170: 
   171:     @staticmethod
>> 172:     def mode_from_lr_packet(packet):
>> 173:         if len(packet.data) > Link.ECPUBSIZE:
>> 174:             mode = (packet.data[Link.ECPUBSIZE] & Link.MODE_BYTEMASK) >> 5
>> 175:             return mode
>> 176:         else: return Link.MODE_DEFAULT
   177: 
   178:     @staticmethod
   179:     def mode_from_lp_packet(packet):
   180:         if len(packet.data) > RNS.Identity.SIGLENGTH//8+Link.ECPUBSIZE//2:
   181:             mode = packet.data[RNS.Identity.SIGLENGTH//8+Link.ECPUBSIZE//2] >> 5
   182:             return mode
   183:         else: return Link.MODE_DEFAULT
   184: 
   185:     @staticmethod
   186:     def validate_request(owner, data, packet):
```

    </details>
- **Steps:**
  - Mode is (first_byte & MODE_BYTEMASK) >> 5.
  - MTU is (byte0<<16 + byte1<<8 + byte2) & MTU_BYTEMASK.

## RNS.IFAC.CONST.IFAC_FLAG_BIT
- **Kind:** constant
- **Normative:** MUST
- **Statement:** The IFAC-present flag is bit 7 of the flags byte; value 0x80 when IFAC is present.
- **References:**
  - RNS/Transport.py (`new_header`) lines 907–912 (implementation)
    <details>
      <summary>Show code: RNS/Transport.py:907–912 — new_header — implementation</summary>

```py
907: 
908:                 # Set IFAC flag
909:                 new_header = bytes([raw[0] | 0x80, raw[1]])
910: 
911:                 # Assemble new payload with IFAC
912:                 new_raw    = new_header+ifac+raw[2:]
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   897:                 # Calculate packet access code
   898:                 ifac = interface.ifac_identity.sign(raw)[-interface.ifac_size:]
   899: 
   900:                 # Generate mask
   901:                 mask = RNS.Cryptography.hkdf(
   902:                     length=len(raw)+interface.ifac_size,
   903:                     derive_from=ifac,
   904:                     salt=interface.ifac_key,
   905:                     context=None,
   906:                 )
>> 907: 
>> 908:                 # Set IFAC flag
>> 909:                 new_header = bytes([raw[0] | 0x80, raw[1]])
>> 910: 
>> 911:                 # Assemble new payload with IFAC
>> 912:                 new_raw    = new_header+ifac+raw[2:]
   913:                 
   914:                 # Mask payload
   915:                 i = 0; masked_raw = b""
   916:                 for byte in new_raw:
   917:                     if i == 0:
   918:                         # Mask first header byte, but make sure the
   919:                         # IFAC flag is still set
   920:                         masked_raw += bytes([byte ^ mask[i] | 0x80])
   921:                     elif i == 1 or i > interface.ifac_size+1:
   922:                         # Mask second header byte and payload
```

    </details>
- **Value:** {'number': 128, 'unit': 'byte mask', 'format': '0x80'}

## RNS.IFAC.CONST.IFAC_SALT
- **Kind:** constant
- **Normative:** MUST
- **Statement:** The IFAC key derivation uses a 32-byte salt with hex value adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8.
- **References:**
  - RNS/Reticulum.py (`IFAC_SALT`) lines 147–154 (definition)
    <details>
      <summary>Show code: RNS/Reticulum.py:147–154 — IFAC_SALT — definition</summary>

```py
147:     TRUNCATED_HASHLENGTH = 128
148: 
149:     HEADER_MINSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*1
150:     HEADER_MAXSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*2
151:     IFAC_MIN_SIZE    = 1
152:     IFAC_SALT        = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
153:     
154:     MDU              = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   137:     """
   138:     Minimum bitrate required across a medium for Reticulum to be able
   139:     to successfully establish links. Currently 5 bits per second.
   140:     """
   141: 
   142:     # TODO: Let Reticulum somehow continously build a map of per-hop
   143:     # latencies and use this map for global timeout calculation.
   144:     DEFAULT_PER_HOP_TIMEOUT = 6
   145: 
   146:     # Length of truncated hashes in bits.
>> 147:     TRUNCATED_HASHLENGTH = 128
>> 148: 
>> 149:     HEADER_MINSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*1
>> 150:     HEADER_MAXSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*2
>> 151:     IFAC_MIN_SIZE    = 1
>> 152:     IFAC_SALT        = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
>> 153:     
>> 154:     MDU              = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
   155: 
   156:     RESOURCE_CACHE   = 24*60*60
   157:     JOB_INTERVAL     = 5*60
   158:     CLEAN_INTERVAL   = 15*60
   159:     PERSIST_INTERVAL = 60*60*12
   160:     GRACIOUS_PERSIST_INTERVAL = 60*5
   161: 
   162:     router           = None
   163:     config           = None
   164:     
```

    </details>
- **Value:** {'number': 'adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8', 'unit': 'bytes', 'format': 'hex'}

## RNS.IFAC.ALG.OUTBOUND_INSERT_AND_MASK
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** Outbound IFAC: sign raw packet, take last ifac_size bytes as IFAC, insert after byte 1, set bit 7 of byte 0, then mask with HKDF-derived mask. Mask bytes [0], [1], and [2+ifac_size .. end); do not mask bytes [2 .. 2+ifac_size) (the IFAC bytes).
- **References:**
  - RNS/Transport.py (`transmit`) lines 894–928 (implementation)
    <details>
      <summary>Show code: RNS/Transport.py:894–928 — transmit — implementation</summary>

```py
894:     def transmit(interface, raw):
895:         try:
896:             if hasattr(interface, "ifac_identity") and interface.ifac_identity != None:
897:                 # Calculate packet access code
898:                 ifac = interface.ifac_identity.sign(raw)[-interface.ifac_size:]
899: 
900:                 # Generate mask
901:                 mask = RNS.Cryptography.hkdf(
902:                     length=len(raw)+interface.ifac_size,
903:                     derive_from=ifac,
904:                     salt=interface.ifac_key,
905:                     context=None,
906:                 )
907: 
908:                 # Set IFAC flag
909:                 new_header = bytes([raw[0] | 0x80, raw[1]])
910: 
911:                 # Assemble new payload with IFAC
912:                 new_raw    = new_header+ifac+raw[2:]
913:                 
914:                 # Mask payload
915:                 i = 0; masked_raw = b""
916:                 for byte in new_raw:
917:                     if i == 0:
918:                         # Mask first header byte, but make sure the
919:                         # IFAC flag is still set
920:                         masked_raw += bytes([byte ^ mask[i] | 0x80])
921:                     elif i == 1 or i > interface.ifac_size+1:
922:                         # Mask second header byte and payload
923:                         masked_raw += bytes([byte ^ mask[i]])
924:                     else:
925:                         # Don't mask the IFAC itself
926:                         masked_raw += bytes([byte])
927:                     i += 1
928: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   884: 
   885:         for destination_hash in path_requests:
   886:             blocked_if = path_requests[destination_hash]
   887:             if blocked_if == None: Transport.request_path(destination_hash)
   888:             else:
   889:                 for interface in Transport.interfaces:
   890:                     if interface != blocked_if: Transport.request_path(destination_hash, on_interface=interface)
   891:                     else: pass
   892: 
   893:     @staticmethod
>> 894:     def transmit(interface, raw):
>> 895:         try:
>> 896:             if hasattr(interface, "ifac_identity") and interface.ifac_identity != None:
>> 897:                 # Calculate packet access code
>> 898:                 ifac = interface.ifac_identity.sign(raw)[-interface.ifac_size:]
>> 899: 
>> 900:                 # Generate mask
>> 901:                 mask = RNS.Cryptography.hkdf(
>> 902:                     length=len(raw)+interface.ifac_size,
>> 903:                     derive_from=ifac,
>> 904:                     salt=interface.ifac_key,
>> 905:                     context=None,
>> 906:                 )
>> 907: 
>> 908:                 # Set IFAC flag
>> 909:                 new_header = bytes([raw[0] | 0x80, raw[1]])
>> 910: 
>> 911:                 # Assemble new payload with IFAC
>> 912:                 new_raw    = new_header+ifac+raw[2:]
>> 913:                 
>> 914:                 # Mask payload
>> 915:                 i = 0; masked_raw = b""
>> 916:                 for byte in new_raw:
>> 917:                     if i == 0:
>> 918:                         # Mask first header byte, but make sure the
>> 919:                         # IFAC flag is still set
>> 920:                         masked_raw += bytes([byte ^ mask[i] | 0x80])
>> 921:                     elif i == 1 or i > interface.ifac_size+1:
>> 922:                         # Mask second header byte and payload
>> 923:                         masked_raw += bytes([byte ^ mask[i]])
>> 924:                     else:
>> 925:                         # Don't mask the IFAC itself
>> 926:                         masked_raw += bytes([byte])
>> 927:                     i += 1
>> 928: 
   929:                 # Send it
   930:                 interface.process_outgoing(masked_raw)
   931: 
   932:             else:
   933:                 interface.process_outgoing(raw)
   934: 
   935:         except Exception as e:
   936:             RNS.log("Error while transmitting on "+str(interface)+". The contained exception was: "+str(e), RNS.LOG_ERROR)
   937: 
   938:     @staticmethod
```

    </details>
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
  - RNS/Transport.py (`inbound`) lines 1241–1295 (implementation)
    <details>
      <summary>Show code: RNS/Transport.py:1241–1295 — inbound — implementation</summary>

```py
1241:     def inbound(raw, interface=None):
1242:         # If interface access codes are enabled,
1243:         # we must authenticate each packet.
1244:         if len(raw) > 2:
1245:             if interface != None and hasattr(interface, "ifac_identity") and interface.ifac_identity != None:
1246:                 # Check that IFAC flag is set
1247:                 if raw[0] & 0x80 == 0x80:
1248:                     if len(raw) > 2+interface.ifac_size:
1249:                         # Extract IFAC
1250:                         ifac = raw[2:2+interface.ifac_size]
1251: 
1252:                         # Generate mask
1253:                         mask = RNS.Cryptography.hkdf(
1254:                             length=len(raw),
1255:                             derive_from=ifac,
1256:                             salt=interface.ifac_key,
1257:                             context=None,
1258:                         )
1259: 
1260:                         # Unmask payload
1261:                         i = 0; unmasked_raw = b""
1262:                         for byte in raw:
1263:                             if i <= 1 or i > interface.ifac_size+1:
1264:                                 # Unmask header bytes and payload
1265:                                 unmasked_raw += bytes([byte ^ mask[i]])
1266:                             else:
1267:                                 # Don't unmask IFAC itself
1268:                                 unmasked_raw += bytes([byte])
1269:                             i += 1
1270:                         raw = unmasked_raw
1271: 
1272:                         # Unset IFAC flag
1273:                         new_header = bytes([raw[0] & 0x7f, raw[1]])
1274: 
1275:                         # Re-assemble packet
1276:                         new_raw = new_header+raw[2+interface.ifac_size:]
1277: 
1278:                         # Calculate expected IFAC
1279:                         expected_ifac = interface.ifac_identity.sign(new_raw)[-interface.ifac_size:]
1280: 
1281:                         # Check it
1282:                         if ifac == expected_ifac:
1283:                             raw = new_raw
1284:                         else:
1285:                             return
1286: 
1287:                     else:
1288:                         return
1289: 
1290:                 else:
1291:                     # If the IFAC flag is not set, but should be,
1292:                     # drop the packet.
1293:                     return
1294: 
1295:             else:
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   1231:                 if packet.destination_type == RNS.Destination.SINGLE:
   1232:                     return True
   1233:                 else:
   1234:                     RNS.log("Dropped invalid announce packet", RNS.LOG_DEBUG)
   1235:                     return False
   1236: 
   1237:         RNS.log("Filtered packet with hash "+RNS.prettyhexrep(packet.packet_hash), RNS.LOG_EXTREME)
   1238:         return False
   1239: 
   1240:     @staticmethod
>> 1241:     def inbound(raw, interface=None):
>> 1242:         # If interface access codes are enabled,
>> 1243:         # we must authenticate each packet.
>> 1244:         if len(raw) > 2:
>> 1245:             if interface != None and hasattr(interface, "ifac_identity") and interface.ifac_identity != None:
>> 1246:                 # Check that IFAC flag is set
>> 1247:                 if raw[0] & 0x80 == 0x80:
>> 1248:                     if len(raw) > 2+interface.ifac_size:
>> 1249:                         # Extract IFAC
>> 1250:                         ifac = raw[2:2+interface.ifac_size]
>> 1251: 
>> 1252:                         # Generate mask
>> 1253:                         mask = RNS.Cryptography.hkdf(
>> 1254:                             length=len(raw),
>> 1255:                             derive_from=ifac,
>> 1256:                             salt=interface.ifac_key,
>> 1257:                             context=None,
>> 1258:                         )
>> 1259: 
>> 1260:                         # Unmask payload
>> 1261:                         i = 0; unmasked_raw = b""
>> 1262:                         for byte in raw:
>> 1263:                             if i <= 1 or i > interface.ifac_size+1:
>> 1264:                                 # Unmask header bytes and payload
>> 1265:                                 unmasked_raw += bytes([byte ^ mask[i]])
>> 1266:                             else:
>> 1267:                                 # Don't unmask IFAC itself
>> 1268:                                 unmasked_raw += bytes([byte])
>> 1269:                             i += 1
>> 1270:                         raw = unmasked_raw
>> 1271: 
>> 1272:                         # Unset IFAC flag
>> 1273:                         new_header = bytes([raw[0] & 0x7f, raw[1]])
>> 1274: 
>> 1275:                         # Re-assemble packet
>> 1276:                         new_raw = new_header+raw[2+interface.ifac_size:]
>> 1277: 
>> 1278:                         # Calculate expected IFAC
>> 1279:                         expected_ifac = interface.ifac_identity.sign(new_raw)[-interface.ifac_size:]
>> 1280: 
>> 1281:                         # Check it
>> 1282:                         if ifac == expected_ifac:
>> 1283:                             raw = new_raw
>> 1284:                         else:
>> 1285:                             return
>> 1286: 
>> 1287:                     else:
>> 1288:                         return
>> 1289: 
>> 1290:                 else:
>> 1291:                     # If the IFAC flag is not set, but should be,
>> 1292:                     # drop the packet.
>> 1293:                     return
>> 1294: 
>> 1295:             else:
   1296:                 # If the interface does not have IFAC enabled,
   1297:                 # check the received packet IFAC flag.
   1298:                 if raw[0] & 0x80 == 0x80:
   1299:                     # If the flag is set, drop the packet
   1300:                     return
   1301: 
   1302:         else:
   1303:             return
   1304: 
   1305:         while (Transport.jobs_running):
```

    </details>
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
  - RNS/Packet.py (`NONE`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — NONE — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 0, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 1 denotes packet is part of a resource.
- **References:**
  - RNS/Packet.py (`RESOURCE`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — RESOURCE — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 1, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE_ADV
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 2 denotes resource advertisement.
- **References:**
  - RNS/Packet.py (`RESOURCE_ADV`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — RESOURCE_ADV — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 2, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE_REQ
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 3 denotes resource part request.
- **References:**
  - RNS/Packet.py (`RESOURCE_REQ`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — RESOURCE_REQ — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 3, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE_HMU
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 4 denotes resource hashmap update.
- **References:**
  - RNS/Packet.py (`RESOURCE_HMU`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — RESOURCE_HMU — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 4, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE_PRF
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 5 denotes resource proof.
- **References:**
  - RNS/Packet.py (`RESOURCE_PRF`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — RESOURCE_PRF — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 5, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE_ICL
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 6 denotes resource initiator cancel.
- **References:**
  - RNS/Packet.py (`RESOURCE_ICL`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — RESOURCE_ICL — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 6, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESOURCE_RCL
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 7 denotes resource receiver cancel.
- **References:**
  - RNS/Packet.py (`RESOURCE_RCL`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — RESOURCE_RCL — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 7, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_CACHE_REQUEST
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 8 denotes cache request.
- **References:**
  - RNS/Packet.py (`CACHE_REQUEST`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — CACHE_REQUEST — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 8, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_REQUEST
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 9 denotes request.
- **References:**
  - RNS/Packet.py (`REQUEST`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — REQUEST — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 9, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_RESPONSE
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 10 denotes response to a request.
- **References:**
  - RNS/Packet.py (`RESPONSE`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — RESPONSE — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 10, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_PATH_RESPONSE
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 11 denotes path response.
- **References:**
  - RNS/Packet.py (`PATH_RESPONSE`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — PATH_RESPONSE — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 11, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_COMMAND
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 12 denotes command.
- **References:**
  - RNS/Packet.py (`COMMAND`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — COMMAND — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 12, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_COMMAND_STATUS
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 13 denotes command status.
- **References:**
  - RNS/Packet.py (`COMMAND_STATUS`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — COMMAND_STATUS — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 13, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_CHANNEL
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 14 denotes link channel data.
- **References:**
  - RNS/Packet.py (`CHANNEL`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — CHANNEL — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 14, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_KEEPALIVE
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 250 denotes keepalive packet.
- **References:**
  - RNS/Packet.py (`KEEPALIVE`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — KEEPALIVE — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 250, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_LINKIDENTIFY
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 251 denotes link peer identification proof.
- **References:**
  - RNS/Packet.py (`LINKIDENTIFY`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — LINKIDENTIFY — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 251, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_LINKCLOSE
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 252 denotes link close message.
- **References:**
  - RNS/Packet.py (`LINKCLOSE`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — LINKCLOSE — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 252, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_LINKPROOF
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 253 denotes link packet proof.
- **References:**
  - RNS/Packet.py (`LINKPROOF`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — LINKPROOF — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 253, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_LRRTT
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 254 denotes link request round-trip time measurement.
- **References:**
  - RNS/Packet.py (`LRRTT`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — LRRTT — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 254, 'unit': 'byte'}

## RNS.PKT.CONST.CTX_LRPROOF
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Context byte value 255 denotes link request proof.
- **References:**
  - RNS/Packet.py (`LRPROOF`) lines 71–92 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:71–92 — LRPROOF — definition</summary>

```py
71:     # Packet context types
72:     NONE           = 0x00   # Generic data packet
73:     RESOURCE       = 0x01   # Packet is part of a resource
74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
81:     REQUEST        = 0x09   # Packet is a request
82:     RESPONSE       = 0x0A   # Packet is a response to a request
83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
84:     COMMAND        = 0x0C   # Packet is a command
85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
86:     CHANNEL        = 0x0E   # Packet contains link channel data
87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
89:     LINKCLOSE      = 0xFC   # Packet is a link close message
90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
92:     LRPROOF        = 0xFF   # Packet is a link request proof
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   61:     ANNOUNCE     = 0x01     # Announces
   62:     LINKREQUEST  = 0x02     # Link requests
   63:     PROOF        = 0x03     # Proofs
   64:     types        = [DATA, ANNOUNCE, LINKREQUEST, PROOF]
   65: 
   66:     # Header types
   67:     HEADER_1     = 0x00     # Normal header format
   68:     HEADER_2     = 0x01     # Header format used for packets in transport
   69:     header_types = [HEADER_1, HEADER_2]
   70: 
>> 71:     # Packet context types
>> 72:     NONE           = 0x00   # Generic data packet
>> 73:     RESOURCE       = 0x01   # Packet is part of a resource
>> 74:     RESOURCE_ADV   = 0x02   # Packet is a resource advertisement
>> 75:     RESOURCE_REQ   = 0x03   # Packet is a resource part request
>> 76:     RESOURCE_HMU   = 0x04   # Packet is a resource hashmap update
>> 77:     RESOURCE_PRF   = 0x05   # Packet is a resource proof
>> 78:     RESOURCE_ICL   = 0x06   # Packet is a resource initiator cancel message
>> 79:     RESOURCE_RCL   = 0x07   # Packet is a resource receiver cancel message
>> 80:     CACHE_REQUEST  = 0x08   # Packet is a cache request
>> 81:     REQUEST        = 0x09   # Packet is a request
>> 82:     RESPONSE       = 0x0A   # Packet is a response to a request
>> 83:     PATH_RESPONSE  = 0x0B   # Packet is a response to a path request
>> 84:     COMMAND        = 0x0C   # Packet is a command
>> 85:     COMMAND_STATUS = 0x0D   # Packet is a status of an executed command
>> 86:     CHANNEL        = 0x0E   # Packet contains link channel data
>> 87:     KEEPALIVE      = 0xFA   # Packet is a keepalive packet
>> 88:     LINKIDENTIFY   = 0xFB   # Packet is a link peer identification proof
>> 89:     LINKCLOSE      = 0xFC   # Packet is a link close message
>> 90:     LINKPROOF      = 0xFD   # Packet is a link packet proof
>> 91:     LRRTT          = 0xFE   # Packet is a link request round-trip time measurement
>> 92:     LRPROOF        = 0xFF   # Packet is a link request proof
   93: 
   94:     # Context flag values
   95:     FLAG_SET       = 0x01
   96:     FLAG_UNSET     = 0x00
   97: 
   98:     # This is used to calculate allowable
   99:     # payload sizes
   100:     HEADER_MAXSIZE = RNS.Reticulum.HEADER_MAXSIZE
   101:     MDU            = RNS.Reticulum.MDU
   102: 
```

    </details>
- **Value:** {'number': 255, 'unit': 'byte'}

## RNS.TRN.CONST.MTU_DEFAULT
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Default physical-layer MTU is 500 bytes; the wire packet length MUST NOT exceed the applicable MTU (interface or link).
- **References:**
  - RNS/Reticulum.py (`MTU`) lines 89–95 (definition)
    <details>
      <summary>Show code: RNS/Reticulum.py:89–95 — MTU — definition</summary>

```py
89:     # Future minimum will probably be locked in at 251 bytes to support
90:     # networks with segments of different MTUs. Absolute minimum is 219.
91:     MTU            = 500
92:     """
93:     The MTU that Reticulum adheres to, and will expect other peers to
94:     adhere to. By default, the MTU is 500 bytes. In custom RNS network
95:     implementations, it is possible to change this value, but doing so will
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   79:     hardware such as modems, TNCs and radios. If a master instance is
   80:     asked to exit, it will not exit until all client processes have
   81:     terminated (unless killed forcibly).
   82: 
   83:     If you are running Reticulum on a system with several different
   84:     programs that use RNS starting and terminating at different times,
   85:     it will be advantageous to run a master RNS instance as a daemon for
   86:     other programs to use on demand.
   87:     """
   88: 
>> 89:     # Future minimum will probably be locked in at 251 bytes to support
>> 90:     # networks with segments of different MTUs. Absolute minimum is 219.
>> 91:     MTU            = 500
>> 92:     """
>> 93:     The MTU that Reticulum adheres to, and will expect other peers to
>> 94:     adhere to. By default, the MTU is 500 bytes. In custom RNS network
>> 95:     implementations, it is possible to change this value, but doing so will
   96:     completely break compatibility with all other RNS networks. An identical
   97:     MTU is a prerequisite for peers to communicate in the same network.
   98: 
   99:     Unless you really know what you are doing, the MTU should be left at
   100:     the default value.
   101:     """
   102: 
   103:     LINK_MTU_DISCOVERY   = True
   104:     """
   105:     Whether automatic link MTU discovery is enabled by default in this
```

    </details>
- **Value:** {'number': 500, 'unit': 'bytes'}

## RNS.TRN.CONST.DST_LEN
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Destination hash, transport id, and link_id are 16 bytes (TRUNCATED_HASHLENGTH//8).
- **References:**
  - RNS/Reticulum.py (`TRUNCATED_HASHLENGTH`) lines 147–154 (definition)
    <details>
      <summary>Show code: RNS/Reticulum.py:147–154 — TRUNCATED_HASHLENGTH — definition</summary>

```py
147:     TRUNCATED_HASHLENGTH = 128
148: 
149:     HEADER_MINSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*1
150:     HEADER_MAXSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*2
151:     IFAC_MIN_SIZE    = 1
152:     IFAC_SALT        = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
153:     
154:     MDU              = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   137:     """
   138:     Minimum bitrate required across a medium for Reticulum to be able
   139:     to successfully establish links. Currently 5 bits per second.
   140:     """
   141: 
   142:     # TODO: Let Reticulum somehow continously build a map of per-hop
   143:     # latencies and use this map for global timeout calculation.
   144:     DEFAULT_PER_HOP_TIMEOUT = 6
   145: 
   146:     # Length of truncated hashes in bits.
>> 147:     TRUNCATED_HASHLENGTH = 128
>> 148: 
>> 149:     HEADER_MINSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*1
>> 150:     HEADER_MAXSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*2
>> 151:     IFAC_MIN_SIZE    = 1
>> 152:     IFAC_SALT        = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
>> 153:     
>> 154:     MDU              = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
   155: 
   156:     RESOURCE_CACHE   = 24*60*60
   157:     JOB_INTERVAL     = 5*60
   158:     CLEAN_INTERVAL   = 15*60
   159:     PERSIST_INTERVAL = 60*60*12
   160:     GRACIOUS_PERSIST_INTERVAL = 60*5
   161: 
   162:     router           = None
   163:     config           = None
   164:     
```

    </details>
- **Value:** {'number': 16, 'unit': 'bytes'}

## RNS.TRN.CONST.IFAC_MIN_SIZE
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Minimum IFAC payload length is 1 byte; interface.ifac_size defines actual length.
- **References:**
  - RNS/Reticulum.py (`IFAC_MIN_SIZE`) lines 147–154 (definition)
    <details>
      <summary>Show code: RNS/Reticulum.py:147–154 — IFAC_MIN_SIZE — definition</summary>

```py
147:     TRUNCATED_HASHLENGTH = 128
148: 
149:     HEADER_MINSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*1
150:     HEADER_MAXSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*2
151:     IFAC_MIN_SIZE    = 1
152:     IFAC_SALT        = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
153:     
154:     MDU              = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   137:     """
   138:     Minimum bitrate required across a medium for Reticulum to be able
   139:     to successfully establish links. Currently 5 bits per second.
   140:     """
   141: 
   142:     # TODO: Let Reticulum somehow continously build a map of per-hop
   143:     # latencies and use this map for global timeout calculation.
   144:     DEFAULT_PER_HOP_TIMEOUT = 6
   145: 
   146:     # Length of truncated hashes in bits.
>> 147:     TRUNCATED_HASHLENGTH = 128
>> 148: 
>> 149:     HEADER_MINSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*1
>> 150:     HEADER_MAXSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*2
>> 151:     IFAC_MIN_SIZE    = 1
>> 152:     IFAC_SALT        = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
>> 153:     
>> 154:     MDU              = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
   155: 
   156:     RESOURCE_CACHE   = 24*60*60
   157:     JOB_INTERVAL     = 5*60
   158:     CLEAN_INTERVAL   = 15*60
   159:     PERSIST_INTERVAL = 60*60*12
   160:     GRACIOUS_PERSIST_INTERVAL = 60*5
   161: 
   162:     router           = None
   163:     config           = None
   164:     
```

    </details>
- **Value:** {'number': 1, 'unit': 'bytes'}

## RNS.TRN.CONST.MDU
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** MDU (maximum data unit) is MTU minus HEADER_MAXSIZE and IFAC_MIN_SIZE; maximum plaintext in a single packet before encryption overhead.
- **References:**
  - RNS/Reticulum.py (`MDU`) lines 147–154 (definition)
    <details>
      <summary>Show code: RNS/Reticulum.py:147–154 — MDU — definition</summary>

```py
147:     TRUNCATED_HASHLENGTH = 128
148: 
149:     HEADER_MINSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*1
150:     HEADER_MAXSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*2
151:     IFAC_MIN_SIZE    = 1
152:     IFAC_SALT        = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
153:     
154:     MDU              = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   137:     """
   138:     Minimum bitrate required across a medium for Reticulum to be able
   139:     to successfully establish links. Currently 5 bits per second.
   140:     """
   141: 
   142:     # TODO: Let Reticulum somehow continously build a map of per-hop
   143:     # latencies and use this map for global timeout calculation.
   144:     DEFAULT_PER_HOP_TIMEOUT = 6
   145: 
   146:     # Length of truncated hashes in bits.
>> 147:     TRUNCATED_HASHLENGTH = 128
>> 148: 
>> 149:     HEADER_MINSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*1
>> 150:     HEADER_MAXSIZE   = 2+1+(TRUNCATED_HASHLENGTH//8)*2
>> 151:     IFAC_MIN_SIZE    = 1
>> 152:     IFAC_SALT        = bytes.fromhex("adf54d882c9a9b80771eb4995d702d4a3e733391b2a0f53f416d9f907e55cff8")
>> 153:     
>> 154:     MDU              = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE
   155: 
   156:     RESOURCE_CACHE   = 24*60*60
   157:     JOB_INTERVAL     = 5*60
   158:     CLEAN_INTERVAL   = 15*60
   159:     PERSIST_INTERVAL = 60*60*12
   160:     GRACIOUS_PERSIST_INTERVAL = 60*5
   161: 
   162:     router           = None
   163:     config           = None
   164:     
```

    </details>
- **Value:** {'number': 464, 'unit': 'bytes'}

## RNS.PKT.CONST.KEYSIZE_BYTES
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Identity public and private key format is 64 bytes (X25519 32 + Ed25519 32).
- **References:**
  - RNS/Identity.py (`KEYSIZE`) lines 59–89 (definition)
    <details>
      <summary>Show code: RNS/Identity.py:59–89 — KEYSIZE — definition</summary>

```py
59:     KEYSIZE     = 256*2
60:     """
61:     X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
62:     """
63: 
64:     RATCHETSIZE = 256
65:     """
66:     X.25519 ratchet key size in bits.
67:     """
68: 
69:     RATCHET_EXPIRY = 60*60*24*30
70:     """
71:     The expiry time for received ratchets in seconds, defaults to 30 days. Reticulum will always use the most recently
72:     announced ratchet, and remember it for up to ``RATCHET_EXPIRY`` since receiving it, after which it will be discarded.
73:     If a newer ratchet is announced in the meantime, it will be replace the already known ratchet.
74:     """
75: 
76:     # Non-configurable constants
77:     TOKEN_OVERHEAD            = RNS.Cryptography.Token.TOKEN_OVERHEAD
78:     AES128_BLOCKSIZE          = 16          # In bytes
79:     HASHLENGTH                = 256         # In bits
80:     SIGLENGTH                 = KEYSIZE     # In bits
81: 
82:     NAME_HASH_LENGTH          = 80
83:     TRUNCATED_HASHLENGTH      = RNS.Reticulum.TRUNCATED_HASHLENGTH
84:     """
85:     Constant specifying the truncated hash length (in bits) used by Reticulum
86:     for addressable hashes and other purposes. Non-configurable.
87:     """
88: 
89:     DERIVED_KEY_LENGTH        = 512//8
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   49:     for all encrypted communication over Reticulum networks.
   50: 
   51:     :param create_keys: Specifies whether new encryption and signing keys should be generated.
   52:     """
   53: 
   54:     CURVE = "Curve25519"
   55:     """
   56:     The curve used for Elliptic Curve DH key exchanges
   57:     """
   58: 
>> 59:     KEYSIZE     = 256*2
>> 60:     """
>> 61:     X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
>> 62:     """
>> 63: 
>> 64:     RATCHETSIZE = 256
>> 65:     """
>> 66:     X.25519 ratchet key size in bits.
>> 67:     """
>> 68: 
>> 69:     RATCHET_EXPIRY = 60*60*24*30
>> 70:     """
>> 71:     The expiry time for received ratchets in seconds, defaults to 30 days. Reticulum will always use the most recently
>> 72:     announced ratchet, and remember it for up to ``RATCHET_EXPIRY`` since receiving it, after which it will be discarded.
>> 73:     If a newer ratchet is announced in the meantime, it will be replace the already known ratchet.
>> 74:     """
>> 75: 
>> 76:     # Non-configurable constants
>> 77:     TOKEN_OVERHEAD            = RNS.Cryptography.Token.TOKEN_OVERHEAD
>> 78:     AES128_BLOCKSIZE          = 16          # In bytes
>> 79:     HASHLENGTH                = 256         # In bits
>> 80:     SIGLENGTH                 = KEYSIZE     # In bits
>> 81: 
>> 82:     NAME_HASH_LENGTH          = 80
>> 83:     TRUNCATED_HASHLENGTH      = RNS.Reticulum.TRUNCATED_HASHLENGTH
>> 84:     """
>> 85:     Constant specifying the truncated hash length (in bits) used by Reticulum
>> 86:     for addressable hashes and other purposes. Non-configurable.
>> 87:     """
>> 88: 
>> 89:     DERIVED_KEY_LENGTH        = 512//8
   90:     DERIVED_KEY_LENGTH_LEGACY = 256//8
   91: 
   92:     # Storage
   93:     known_destinations = {}
   94:     known_ratchets = {}
   95: 
   96:     ratchet_persist_lock = threading.Lock()
   97: 
   98:     @staticmethod
   99:     def remember(packet_hash, destination_hash, public_key, app_data = None):
```

    </details>
- **Value:** {'number': 64, 'unit': 'bytes'}

## RNS.PKT.CONST.SIGLENGTH_BYTES
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Ed25519 signature length is 64 bytes.
- **References:**
  - RNS/Identity.py (`SIGLENGTH`) lines 59–89 (definition)
    <details>
      <summary>Show code: RNS/Identity.py:59–89 — SIGLENGTH — definition</summary>

```py
59:     KEYSIZE     = 256*2
60:     """
61:     X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
62:     """
63: 
64:     RATCHETSIZE = 256
65:     """
66:     X.25519 ratchet key size in bits.
67:     """
68: 
69:     RATCHET_EXPIRY = 60*60*24*30
70:     """
71:     The expiry time for received ratchets in seconds, defaults to 30 days. Reticulum will always use the most recently
72:     announced ratchet, and remember it for up to ``RATCHET_EXPIRY`` since receiving it, after which it will be discarded.
73:     If a newer ratchet is announced in the meantime, it will be replace the already known ratchet.
74:     """
75: 
76:     # Non-configurable constants
77:     TOKEN_OVERHEAD            = RNS.Cryptography.Token.TOKEN_OVERHEAD
78:     AES128_BLOCKSIZE          = 16          # In bytes
79:     HASHLENGTH                = 256         # In bits
80:     SIGLENGTH                 = KEYSIZE     # In bits
81: 
82:     NAME_HASH_LENGTH          = 80
83:     TRUNCATED_HASHLENGTH      = RNS.Reticulum.TRUNCATED_HASHLENGTH
84:     """
85:     Constant specifying the truncated hash length (in bits) used by Reticulum
86:     for addressable hashes and other purposes. Non-configurable.
87:     """
88: 
89:     DERIVED_KEY_LENGTH        = 512//8
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   49:     for all encrypted communication over Reticulum networks.
   50: 
   51:     :param create_keys: Specifies whether new encryption and signing keys should be generated.
   52:     """
   53: 
   54:     CURVE = "Curve25519"
   55:     """
   56:     The curve used for Elliptic Curve DH key exchanges
   57:     """
   58: 
>> 59:     KEYSIZE     = 256*2
>> 60:     """
>> 61:     X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
>> 62:     """
>> 63: 
>> 64:     RATCHETSIZE = 256
>> 65:     """
>> 66:     X.25519 ratchet key size in bits.
>> 67:     """
>> 68: 
>> 69:     RATCHET_EXPIRY = 60*60*24*30
>> 70:     """
>> 71:     The expiry time for received ratchets in seconds, defaults to 30 days. Reticulum will always use the most recently
>> 72:     announced ratchet, and remember it for up to ``RATCHET_EXPIRY`` since receiving it, after which it will be discarded.
>> 73:     If a newer ratchet is announced in the meantime, it will be replace the already known ratchet.
>> 74:     """
>> 75: 
>> 76:     # Non-configurable constants
>> 77:     TOKEN_OVERHEAD            = RNS.Cryptography.Token.TOKEN_OVERHEAD
>> 78:     AES128_BLOCKSIZE          = 16          # In bytes
>> 79:     HASHLENGTH                = 256         # In bits
>> 80:     SIGLENGTH                 = KEYSIZE     # In bits
>> 81: 
>> 82:     NAME_HASH_LENGTH          = 80
>> 83:     TRUNCATED_HASHLENGTH      = RNS.Reticulum.TRUNCATED_HASHLENGTH
>> 84:     """
>> 85:     Constant specifying the truncated hash length (in bits) used by Reticulum
>> 86:     for addressable hashes and other purposes. Non-configurable.
>> 87:     """
>> 88: 
>> 89:     DERIVED_KEY_LENGTH        = 512//8
   90:     DERIVED_KEY_LENGTH_LEGACY = 256//8
   91: 
   92:     # Storage
   93:     known_destinations = {}
   94:     known_ratchets = {}
   95: 
   96:     ratchet_persist_lock = threading.Lock()
   97: 
   98:     @staticmethod
   99:     def remember(packet_hash, destination_hash, public_key, app_data = None):
```

    </details>
- **Value:** {'number': 64, 'unit': 'bytes'}

## RNS.PKT.CONST.HASHLENGTH_BYTES
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Full SHA-256 hash length is 32 bytes.
- **References:**
  - RNS/Identity.py (`HASHLENGTH`) lines 59–89 (definition)
    <details>
      <summary>Show code: RNS/Identity.py:59–89 — HASHLENGTH — definition</summary>

```py
59:     KEYSIZE     = 256*2
60:     """
61:     X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
62:     """
63: 
64:     RATCHETSIZE = 256
65:     """
66:     X.25519 ratchet key size in bits.
67:     """
68: 
69:     RATCHET_EXPIRY = 60*60*24*30
70:     """
71:     The expiry time for received ratchets in seconds, defaults to 30 days. Reticulum will always use the most recently
72:     announced ratchet, and remember it for up to ``RATCHET_EXPIRY`` since receiving it, after which it will be discarded.
73:     If a newer ratchet is announced in the meantime, it will be replace the already known ratchet.
74:     """
75: 
76:     # Non-configurable constants
77:     TOKEN_OVERHEAD            = RNS.Cryptography.Token.TOKEN_OVERHEAD
78:     AES128_BLOCKSIZE          = 16          # In bytes
79:     HASHLENGTH                = 256         # In bits
80:     SIGLENGTH                 = KEYSIZE     # In bits
81: 
82:     NAME_HASH_LENGTH          = 80
83:     TRUNCATED_HASHLENGTH      = RNS.Reticulum.TRUNCATED_HASHLENGTH
84:     """
85:     Constant specifying the truncated hash length (in bits) used by Reticulum
86:     for addressable hashes and other purposes. Non-configurable.
87:     """
88: 
89:     DERIVED_KEY_LENGTH        = 512//8
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   49:     for all encrypted communication over Reticulum networks.
   50: 
   51:     :param create_keys: Specifies whether new encryption and signing keys should be generated.
   52:     """
   53: 
   54:     CURVE = "Curve25519"
   55:     """
   56:     The curve used for Elliptic Curve DH key exchanges
   57:     """
   58: 
>> 59:     KEYSIZE     = 256*2
>> 60:     """
>> 61:     X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
>> 62:     """
>> 63: 
>> 64:     RATCHETSIZE = 256
>> 65:     """
>> 66:     X.25519 ratchet key size in bits.
>> 67:     """
>> 68: 
>> 69:     RATCHET_EXPIRY = 60*60*24*30
>> 70:     """
>> 71:     The expiry time for received ratchets in seconds, defaults to 30 days. Reticulum will always use the most recently
>> 72:     announced ratchet, and remember it for up to ``RATCHET_EXPIRY`` since receiving it, after which it will be discarded.
>> 73:     If a newer ratchet is announced in the meantime, it will be replace the already known ratchet.
>> 74:     """
>> 75: 
>> 76:     # Non-configurable constants
>> 77:     TOKEN_OVERHEAD            = RNS.Cryptography.Token.TOKEN_OVERHEAD
>> 78:     AES128_BLOCKSIZE          = 16          # In bytes
>> 79:     HASHLENGTH                = 256         # In bits
>> 80:     SIGLENGTH                 = KEYSIZE     # In bits
>> 81: 
>> 82:     NAME_HASH_LENGTH          = 80
>> 83:     TRUNCATED_HASHLENGTH      = RNS.Reticulum.TRUNCATED_HASHLENGTH
>> 84:     """
>> 85:     Constant specifying the truncated hash length (in bits) used by Reticulum
>> 86:     for addressable hashes and other purposes. Non-configurable.
>> 87:     """
>> 88: 
>> 89:     DERIVED_KEY_LENGTH        = 512//8
   90:     DERIVED_KEY_LENGTH_LEGACY = 256//8
   91: 
   92:     # Storage
   93:     known_destinations = {}
   94:     known_ratchets = {}
   95: 
   96:     ratchet_persist_lock = threading.Lock()
   97: 
   98:     @staticmethod
   99:     def remember(packet_hash, destination_hash, public_key, app_data = None):
```

    </details>
- **Value:** {'number': 32, 'unit': 'bytes'}

## RNS.PKT.CONST.RATCHETSIZE_BYTES
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Ratchet public key is 32 bytes (RATCHETSIZE//8).
- **References:**
  - RNS/Identity.py (`RATCHETSIZE`) lines 59–89 (definition)
    <details>
      <summary>Show code: RNS/Identity.py:59–89 — RATCHETSIZE — definition</summary>

```py
59:     KEYSIZE     = 256*2
60:     """
61:     X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
62:     """
63: 
64:     RATCHETSIZE = 256
65:     """
66:     X.25519 ratchet key size in bits.
67:     """
68: 
69:     RATCHET_EXPIRY = 60*60*24*30
70:     """
71:     The expiry time for received ratchets in seconds, defaults to 30 days. Reticulum will always use the most recently
72:     announced ratchet, and remember it for up to ``RATCHET_EXPIRY`` since receiving it, after which it will be discarded.
73:     If a newer ratchet is announced in the meantime, it will be replace the already known ratchet.
74:     """
75: 
76:     # Non-configurable constants
77:     TOKEN_OVERHEAD            = RNS.Cryptography.Token.TOKEN_OVERHEAD
78:     AES128_BLOCKSIZE          = 16          # In bytes
79:     HASHLENGTH                = 256         # In bits
80:     SIGLENGTH                 = KEYSIZE     # In bits
81: 
82:     NAME_HASH_LENGTH          = 80
83:     TRUNCATED_HASHLENGTH      = RNS.Reticulum.TRUNCATED_HASHLENGTH
84:     """
85:     Constant specifying the truncated hash length (in bits) used by Reticulum
86:     for addressable hashes and other purposes. Non-configurable.
87:     """
88: 
89:     DERIVED_KEY_LENGTH        = 512//8
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   49:     for all encrypted communication over Reticulum networks.
   50: 
   51:     :param create_keys: Specifies whether new encryption and signing keys should be generated.
   52:     """
   53: 
   54:     CURVE = "Curve25519"
   55:     """
   56:     The curve used for Elliptic Curve DH key exchanges
   57:     """
   58: 
>> 59:     KEYSIZE     = 256*2
>> 60:     """
>> 61:     X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
>> 62:     """
>> 63: 
>> 64:     RATCHETSIZE = 256
>> 65:     """
>> 66:     X.25519 ratchet key size in bits.
>> 67:     """
>> 68: 
>> 69:     RATCHET_EXPIRY = 60*60*24*30
>> 70:     """
>> 71:     The expiry time for received ratchets in seconds, defaults to 30 days. Reticulum will always use the most recently
>> 72:     announced ratchet, and remember it for up to ``RATCHET_EXPIRY`` since receiving it, after which it will be discarded.
>> 73:     If a newer ratchet is announced in the meantime, it will be replace the already known ratchet.
>> 74:     """
>> 75: 
>> 76:     # Non-configurable constants
>> 77:     TOKEN_OVERHEAD            = RNS.Cryptography.Token.TOKEN_OVERHEAD
>> 78:     AES128_BLOCKSIZE          = 16          # In bytes
>> 79:     HASHLENGTH                = 256         # In bits
>> 80:     SIGLENGTH                 = KEYSIZE     # In bits
>> 81: 
>> 82:     NAME_HASH_LENGTH          = 80
>> 83:     TRUNCATED_HASHLENGTH      = RNS.Reticulum.TRUNCATED_HASHLENGTH
>> 84:     """
>> 85:     Constant specifying the truncated hash length (in bits) used by Reticulum
>> 86:     for addressable hashes and other purposes. Non-configurable.
>> 87:     """
>> 88: 
>> 89:     DERIVED_KEY_LENGTH        = 512//8
   90:     DERIVED_KEY_LENGTH_LEGACY = 256//8
   91: 
   92:     # Storage
   93:     known_destinations = {}
   94:     known_ratchets = {}
   95: 
   96:     ratchet_persist_lock = threading.Lock()
   97: 
   98:     @staticmethod
   99:     def remember(packet_hash, destination_hash, public_key, app_data = None):
```

    </details>
- **Value:** {'number': 32, 'unit': 'bytes'}

## RNS.PKT.CONST.NAME_HASH_LENGTH_BYTES
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Name hash and announce random hash are 10 bytes (NAME_HASH_LENGTH//8).
- **References:**
  - RNS/Identity.py (`NAME_HASH_LENGTH`) lines 59–89 (definition)
    <details>
      <summary>Show code: RNS/Identity.py:59–89 — NAME_HASH_LENGTH — definition</summary>

```py
59:     KEYSIZE     = 256*2
60:     """
61:     X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
62:     """
63: 
64:     RATCHETSIZE = 256
65:     """
66:     X.25519 ratchet key size in bits.
67:     """
68: 
69:     RATCHET_EXPIRY = 60*60*24*30
70:     """
71:     The expiry time for received ratchets in seconds, defaults to 30 days. Reticulum will always use the most recently
72:     announced ratchet, and remember it for up to ``RATCHET_EXPIRY`` since receiving it, after which it will be discarded.
73:     If a newer ratchet is announced in the meantime, it will be replace the already known ratchet.
74:     """
75: 
76:     # Non-configurable constants
77:     TOKEN_OVERHEAD            = RNS.Cryptography.Token.TOKEN_OVERHEAD
78:     AES128_BLOCKSIZE          = 16          # In bytes
79:     HASHLENGTH                = 256         # In bits
80:     SIGLENGTH                 = KEYSIZE     # In bits
81: 
82:     NAME_HASH_LENGTH          = 80
83:     TRUNCATED_HASHLENGTH      = RNS.Reticulum.TRUNCATED_HASHLENGTH
84:     """
85:     Constant specifying the truncated hash length (in bits) used by Reticulum
86:     for addressable hashes and other purposes. Non-configurable.
87:     """
88: 
89:     DERIVED_KEY_LENGTH        = 512//8
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   49:     for all encrypted communication over Reticulum networks.
   50: 
   51:     :param create_keys: Specifies whether new encryption and signing keys should be generated.
   52:     """
   53: 
   54:     CURVE = "Curve25519"
   55:     """
   56:     The curve used for Elliptic Curve DH key exchanges
   57:     """
   58: 
>> 59:     KEYSIZE     = 256*2
>> 60:     """
>> 61:     X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
>> 62:     """
>> 63: 
>> 64:     RATCHETSIZE = 256
>> 65:     """
>> 66:     X.25519 ratchet key size in bits.
>> 67:     """
>> 68: 
>> 69:     RATCHET_EXPIRY = 60*60*24*30
>> 70:     """
>> 71:     The expiry time for received ratchets in seconds, defaults to 30 days. Reticulum will always use the most recently
>> 72:     announced ratchet, and remember it for up to ``RATCHET_EXPIRY`` since receiving it, after which it will be discarded.
>> 73:     If a newer ratchet is announced in the meantime, it will be replace the already known ratchet.
>> 74:     """
>> 75: 
>> 76:     # Non-configurable constants
>> 77:     TOKEN_OVERHEAD            = RNS.Cryptography.Token.TOKEN_OVERHEAD
>> 78:     AES128_BLOCKSIZE          = 16          # In bytes
>> 79:     HASHLENGTH                = 256         # In bits
>> 80:     SIGLENGTH                 = KEYSIZE     # In bits
>> 81: 
>> 82:     NAME_HASH_LENGTH          = 80
>> 83:     TRUNCATED_HASHLENGTH      = RNS.Reticulum.TRUNCATED_HASHLENGTH
>> 84:     """
>> 85:     Constant specifying the truncated hash length (in bits) used by Reticulum
>> 86:     for addressable hashes and other purposes. Non-configurable.
>> 87:     """
>> 88: 
>> 89:     DERIVED_KEY_LENGTH        = 512//8
   90:     DERIVED_KEY_LENGTH_LEGACY = 256//8
   91: 
   92:     # Storage
   93:     known_destinations = {}
   94:     known_ratchets = {}
   95: 
   96:     ratchet_persist_lock = threading.Lock()
   97: 
   98:     @staticmethod
   99:     def remember(packet_hash, destination_hash, public_key, app_data = None):
```

    </details>
- **Value:** {'number': 10, 'unit': 'bytes'}

## RNS.PKT.CONST.TOKEN_OVERHEAD
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Token overhead is 48 bytes (IV 16 + HMAC 32).
- **References:**
  - RNS/Cryptography/Token.py (`TOKEN_OVERHEAD`) lines 48–52 (definition)
    <details>
      <summary>Show code: RNS/Cryptography/Token.py:48–52 — TOKEN_OVERHEAD — definition</summary>

```py
48:     implementation, since they incur overhead and leak initiator metadata.
49:     """
50:     TOKEN_OVERHEAD  = 48 # Bytes
51: 
52:     @staticmethod
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   38: from RNS.Cryptography.AES import AES_256_CBC
   39: 
   40: class Token():
   41:     """
   42:     This class provides a slightly modified implementation of the Fernet spec
   43:     found at: https://github.com/fernet/spec/blob/master/Spec.md
   44: 
   45:     According to the spec, a Fernet token includes a one byte VERSION and
   46:     eight byte TIMESTAMP field at the start of each token. These fields are
   47:     not relevant to Reticulum. They are therefore stripped from this
>> 48:     implementation, since they incur overhead and leak initiator metadata.
>> 49:     """
>> 50:     TOKEN_OVERHEAD  = 48 # Bytes
>> 51: 
>> 52:     @staticmethod
   53:     def generate_key(mode=AES_256_CBC):
   54:         if   mode == AES_128_CBC: return os.urandom(32)
   55:         elif mode == AES_256_CBC: return os.urandom(64)
   56:         else: raise TypeError(f"Invalid token mode: {mode}")
   57: 
   58:     def __init__(self, key=None, mode=AES):
   59:         if key == None: raise ValueError("Token key cannot be None")
   60: 
   61:         if mode == AES:
   62:             if len(key) == 32:
```

    </details>
- **Value:** {'number': 48, 'unit': 'bytes'}

## RNS.PKT.CONST.AES128_BLOCKSIZE
- **Kind:** constant
- **Normative:** MUST
- **Statement:** AES block size is 16 bytes (used for padding and ciphertext alignment).
- **References:**
  - RNS/Identity.py (`AES128_BLOCKSIZE`) lines 59–89 (definition)
    <details>
      <summary>Show code: RNS/Identity.py:59–89 — AES128_BLOCKSIZE — definition</summary>

```py
59:     KEYSIZE     = 256*2
60:     """
61:     X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
62:     """
63: 
64:     RATCHETSIZE = 256
65:     """
66:     X.25519 ratchet key size in bits.
67:     """
68: 
69:     RATCHET_EXPIRY = 60*60*24*30
70:     """
71:     The expiry time for received ratchets in seconds, defaults to 30 days. Reticulum will always use the most recently
72:     announced ratchet, and remember it for up to ``RATCHET_EXPIRY`` since receiving it, after which it will be discarded.
73:     If a newer ratchet is announced in the meantime, it will be replace the already known ratchet.
74:     """
75: 
76:     # Non-configurable constants
77:     TOKEN_OVERHEAD            = RNS.Cryptography.Token.TOKEN_OVERHEAD
78:     AES128_BLOCKSIZE          = 16          # In bytes
79:     HASHLENGTH                = 256         # In bits
80:     SIGLENGTH                 = KEYSIZE     # In bits
81: 
82:     NAME_HASH_LENGTH          = 80
83:     TRUNCATED_HASHLENGTH      = RNS.Reticulum.TRUNCATED_HASHLENGTH
84:     """
85:     Constant specifying the truncated hash length (in bits) used by Reticulum
86:     for addressable hashes and other purposes. Non-configurable.
87:     """
88: 
89:     DERIVED_KEY_LENGTH        = 512//8
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   49:     for all encrypted communication over Reticulum networks.
   50: 
   51:     :param create_keys: Specifies whether new encryption and signing keys should be generated.
   52:     """
   53: 
   54:     CURVE = "Curve25519"
   55:     """
   56:     The curve used for Elliptic Curve DH key exchanges
   57:     """
   58: 
>> 59:     KEYSIZE     = 256*2
>> 60:     """
>> 61:     X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
>> 62:     """
>> 63: 
>> 64:     RATCHETSIZE = 256
>> 65:     """
>> 66:     X.25519 ratchet key size in bits.
>> 67:     """
>> 68: 
>> 69:     RATCHET_EXPIRY = 60*60*24*30
>> 70:     """
>> 71:     The expiry time for received ratchets in seconds, defaults to 30 days. Reticulum will always use the most recently
>> 72:     announced ratchet, and remember it for up to ``RATCHET_EXPIRY`` since receiving it, after which it will be discarded.
>> 73:     If a newer ratchet is announced in the meantime, it will be replace the already known ratchet.
>> 74:     """
>> 75: 
>> 76:     # Non-configurable constants
>> 77:     TOKEN_OVERHEAD            = RNS.Cryptography.Token.TOKEN_OVERHEAD
>> 78:     AES128_BLOCKSIZE          = 16          # In bytes
>> 79:     HASHLENGTH                = 256         # In bits
>> 80:     SIGLENGTH                 = KEYSIZE     # In bits
>> 81: 
>> 82:     NAME_HASH_LENGTH          = 80
>> 83:     TRUNCATED_HASHLENGTH      = RNS.Reticulum.TRUNCATED_HASHLENGTH
>> 84:     """
>> 85:     Constant specifying the truncated hash length (in bits) used by Reticulum
>> 86:     for addressable hashes and other purposes. Non-configurable.
>> 87:     """
>> 88: 
>> 89:     DERIVED_KEY_LENGTH        = 512//8
   90:     DERIVED_KEY_LENGTH_LEGACY = 256//8
   91: 
   92:     # Storage
   93:     known_destinations = {}
   94:     known_ratchets = {}
   95: 
   96:     ratchet_persist_lock = threading.Lock()
   97: 
   98:     @staticmethod
   99:     def remember(packet_hash, destination_hash, public_key, app_data = None):
```

    </details>
- **Value:** {'number': 16, 'unit': 'bytes'}

## RNS.RES.CONST.MAPHASH_LEN
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Resource map hash (part hash) is 4 bytes; first 4 bytes of full_hash(part_data+random_hash).
- **References:**
  - RNS/Resource.py (`MAPHASH_LEN`) lines 100–106 (definition)
    <details>
      <summary>Show code: RNS/Resource.py:100–106 — MAPHASH_LEN — definition</summary>

```py
100: 
101:     # Number of bytes in a map hash
102:     MAPHASH_LEN          = 4
103:     SDU                  = RNS.Packet.MDU
104:     RANDOM_HASH_SIZE     = 4
105: 
106:     # This is an indication of what the
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   90:     # If the RTT rate is lower than this value,
   91:     # the window size will be capped at .
   92:     # The default is 50 Kbps (the value is stored in
   93:     # bytes per second, hence the "/ 8").
   94:     RATE_VERY_SLOW       = (2*1000) / 8
   95: 
   96:     # The minimum allowed flexibility of the window size.
   97:     # The difference between window_max and window_min
   98:     # will never be smaller than this value.
   99:     WINDOW_FLEXIBILITY   = 4
>> 100: 
>> 101:     # Number of bytes in a map hash
>> 102:     MAPHASH_LEN          = 4
>> 103:     SDU                  = RNS.Packet.MDU
>> 104:     RANDOM_HASH_SIZE     = 4
>> 105: 
>> 106:     # This is an indication of what the
   107:     # maximum size a resource should be, if
   108:     # it is to be handled within reasonable
   109:     # time constraint, even on small systems.
   110:     #
   111:     # This constant will be used when determining
   112:     # how to sequence the sending of large resources.
   113:     #
   114:     # Capped at 16777215 (0xFFFFFF) per segment to
   115:     # fit in 3 bytes in resource advertisements.
   116:     MAX_EFFICIENT_SIZE      = 1 * 1024 * 1024 - 1
```

    </details>
- **Value:** {'number': 4, 'unit': 'bytes'}

## RNS.LNK.CONST.ECPUBSIZE
- **Kind:** constant
- **Normative:** MUST
- **Statement:** Link request/response key material is 64 bytes (Initiator X25519 32 + Ed25519 32).
- **References:**
  - RNS/Link.py (`ECPUBSIZE`) lines 70–80 (definition)
    <details>
      <summary>Show code: RNS/Link.py:70–80 — ECPUBSIZE — definition</summary>

```py
70:     ECPUBSIZE         = 32+32
71:     KEYSIZE           = 32
72: 
73:     MDU = math.floor((RNS.Reticulum.MTU-RNS.Reticulum.IFAC_MIN_SIZE-RNS.Reticulum.HEADER_MINSIZE-RNS.Identity.TOKEN_OVERHEAD)/RNS.Identity.AES128_BLOCKSIZE)*RNS.Identity.AES128_BLOCKSIZE - 1
74: 
75:     ESTABLISHMENT_TIMEOUT_PER_HOP = RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT
76:     """
77:     Timeout for link establishment in seconds per hop to destination.
78:     """
79: 
80:     LINK_MTU_SIZE            = 3
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   60: 
   61:     :param destination: A :ref:`RNS.Destination<api-destination>` instance which to establish a link to.
   62:     :param established_callback: An optional function or method with the signature *callback(link)* to be called when the link has been established.
   63:     :param closed_callback: An optional function or method with the signature *callback(link)* to be called when the link is closed.
   64:     """
   65:     CURVE = RNS.Identity.CURVE
   66:     """
   67:     The curve used for Elliptic Curve DH key exchanges
   68:     """
   69: 
>> 70:     ECPUBSIZE         = 32+32
>> 71:     KEYSIZE           = 32
>> 72: 
>> 73:     MDU = math.floor((RNS.Reticulum.MTU-RNS.Reticulum.IFAC_MIN_SIZE-RNS.Reticulum.HEADER_MINSIZE-RNS.Identity.TOKEN_OVERHEAD)/RNS.Identity.AES128_BLOCKSIZE)*RNS.Identity.AES128_BLOCKSIZE - 1
>> 74: 
>> 75:     ESTABLISHMENT_TIMEOUT_PER_HOP = RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT
>> 76:     """
>> 77:     Timeout for link establishment in seconds per hop to destination.
>> 78:     """
>> 79: 
>> 80:     LINK_MTU_SIZE            = 3
   81:     TRAFFIC_TIMEOUT_MIN_MS   = 5
   82:     TRAFFIC_TIMEOUT_FACTOR   = 6
   83:     KEEPALIVE_MAX_RTT        = 1.75
   84:     KEEPALIVE_TIMEOUT_FACTOR = 4
   85:     """
   86:     RTT timeout factor used in link timeout calculation.
   87:     """
   88:     STALE_GRACE = 5
   89:     """
   90:     Grace period in seconds used in link timeout calculation.
```

    </details>
- **Value:** {'number': 64, 'unit': 'bytes'}

## RNS.PKT.ALG.DESTINATION_HASH_FROM_NAME
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** Destination hash (16 bytes) is derived from human-readable name and optional identity: expand_name (app_name + aspects, + identity.hexhash if present), name_hash = SHA-256(expand_name(None, app_name, *aspects).encode())[:10], addr_hash_material = name_hash [+ identity.hash if identity], destination_hash = SHA-256(addr_hash_material)[:16].
- **References:**
  - RNS/Destination.py (`hash`) lines 96–130 (definition)
    <details>
      <summary>Show code: RNS/Destination.py:96–130 — hash — definition</summary>

```py
96:     def expand_name(identity, app_name, *aspects):
97:         """
98:         :returns: A string containing the full human-readable name of the destination, for an app_name and a number of aspects.
99:         """
100: 
101:         # Check input values and build name string
102:         if "." in app_name: raise ValueError("Dots can't be used in app names")
103: 
104:         name = app_name
105:         for aspect in aspects:
106:             if "." in aspect: raise ValueError("Dots can't be used in aspects")
107:             name += "." + aspect
108: 
109:         if identity != None:
110:             name += "." + identity.hexhash
111: 
112:         return name
113: 
114: 
115:     @staticmethod
116:     def hash(identity, app_name, *aspects):
117:         """
118:         :returns: A destination name in adressable hash form, for an app_name and a number of aspects.
119:         """
120:         name_hash = RNS.Identity.full_hash(Destination.expand_name(None, app_name, *aspects).encode("utf-8"))[:(RNS.Identity.NAME_HASH_LENGTH//8)]
121:         addr_hash_material = name_hash
122:         if identity != None:
123:             if isinstance(identity, RNS.Identity):
124:                 addr_hash_material += identity.hash
125:             elif isinstance(identity, bytes) and len(identity) == RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
126:                 addr_hash_material += identity
127:             else:
128:                 raise TypeError("Invalid material supplied for destination hash calculation")
129: 
130:         return RNS.Identity.full_hash(addr_hash_material)[:RNS.Reticulum.TRUNCATED_HASHLENGTH//8]
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   86:     """
   87:     The default number of generated ratchet keys a destination will retain, if it has ratchets enabled.
   88:     """
   89: 
   90:     RATCHET_INTERVAL = 30*60
   91:     """
   92:     The minimum interval between rotating ratchet keys, in seconds.
   93:     """
   94: 
   95:     @staticmethod
>> 96:     def expand_name(identity, app_name, *aspects):
>> 97:         """
>> 98:         :returns: A string containing the full human-readable name of the destination, for an app_name and a number of aspects.
>> 99:         """
>> 100: 
>> 101:         # Check input values and build name string
>> 102:         if "." in app_name: raise ValueError("Dots can't be used in app names")
>> 103: 
>> 104:         name = app_name
>> 105:         for aspect in aspects:
>> 106:             if "." in aspect: raise ValueError("Dots can't be used in aspects")
>> 107:             name += "." + aspect
>> 108: 
>> 109:         if identity != None:
>> 110:             name += "." + identity.hexhash
>> 111: 
>> 112:         return name
>> 113: 
>> 114: 
>> 115:     @staticmethod
>> 116:     def hash(identity, app_name, *aspects):
>> 117:         """
>> 118:         :returns: A destination name in adressable hash form, for an app_name and a number of aspects.
>> 119:         """
>> 120:         name_hash = RNS.Identity.full_hash(Destination.expand_name(None, app_name, *aspects).encode("utf-8"))[:(RNS.Identity.NAME_HASH_LENGTH//8)]
>> 121:         addr_hash_material = name_hash
>> 122:         if identity != None:
>> 123:             if isinstance(identity, RNS.Identity):
>> 124:                 addr_hash_material += identity.hash
>> 125:             elif isinstance(identity, bytes) and len(identity) == RNS.Reticulum.TRUNCATED_HASHLENGTH//8:
>> 126:                 addr_hash_material += identity
>> 127:             else:
>> 128:                 raise TypeError("Invalid material supplied for destination hash calculation")
>> 129: 
>> 130:         return RNS.Identity.full_hash(addr_hash_material)[:RNS.Reticulum.TRUNCATED_HASHLENGTH//8]
   131: 
   132:     @staticmethod
   133:     def app_and_aspects_from_name(full_name):
   134:         """
   135:         :returns: A tuple containing the app name and a list of aspects, for a full-name string.
   136:         """
   137:         components = full_name.split(".")
   138:         return (components[0], components[1:])
   139: 
   140:     @staticmethod
```

    </details>
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
  - RNS/Transport.py (`BROADCAST`) lines 49–54 (definition)
    <details>
      <summary>Show code: RNS/Transport.py:49–54 — BROADCAST — definition</summary>

```py
49:     # Constants
50:     BROADCAST                   = 0x00;
51:     TRANSPORT                   = 0x01;
52:     RELAY                       = 0x02;
53:     TUNNEL                      = 0x03;
54:     types                       = [BROADCAST, TRANSPORT, RELAY, TUNNEL]
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   39: from time import sleep
   40: from threading import Lock
   41: from .vendor import umsgpack as umsgpack
   42: from RNS.Interfaces.BackboneInterface import BackboneInterface
   43: 
   44: class Transport:
   45:     """
   46:     Through static methods of this class you can interact with the
   47:     Transport system of Reticulum.
   48:     """
>> 49:     # Constants
>> 50:     BROADCAST                   = 0x00;
>> 51:     TRANSPORT                   = 0x01;
>> 52:     RELAY                       = 0x02;
>> 53:     TUNNEL                      = 0x03;
>> 54:     types                       = [BROADCAST, TRANSPORT, RELAY, TUNNEL]
   55: 
   56:     REACHABILITY_UNREACHABLE    = 0x00
   57:     REACHABILITY_DIRECT         = 0x01
   58:     REACHABILITY_TRANSPORT      = 0x02
   59: 
   60:     APP_NAME = "rnstransport"
   61: 
   62:     PATHFINDER_M                = 128          # Max hops
   63:     """
   64:     Maximum amount of hops that Reticulum will transport a packet.
```

    </details>
- **Value:** {'number': 0, 'unit': 'byte'}

## RNS.PKT.CONST.TRANSPORT_TRANSPORT
- **Kind:** constant
- **Normative:** NOTE
- **Statement:** Flags byte bit 4 value 1 denotes TRANSPORT transport type on the wire.
- **References:**
  - RNS/Transport.py (`TRANSPORT`) lines 49–54 (definition)
    <details>
      <summary>Show code: RNS/Transport.py:49–54 — TRANSPORT — definition</summary>

```py
49:     # Constants
50:     BROADCAST                   = 0x00;
51:     TRANSPORT                   = 0x01;
52:     RELAY                       = 0x02;
53:     TUNNEL                      = 0x03;
54:     types                       = [BROADCAST, TRANSPORT, RELAY, TUNNEL]
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   39: from time import sleep
   40: from threading import Lock
   41: from .vendor import umsgpack as umsgpack
   42: from RNS.Interfaces.BackboneInterface import BackboneInterface
   43: 
   44: class Transport:
   45:     """
   46:     Through static methods of this class you can interact with the
   47:     Transport system of Reticulum.
   48:     """
>> 49:     # Constants
>> 50:     BROADCAST                   = 0x00;
>> 51:     TRANSPORT                   = 0x01;
>> 52:     RELAY                       = 0x02;
>> 53:     TUNNEL                      = 0x03;
>> 54:     types                       = [BROADCAST, TRANSPORT, RELAY, TUNNEL]
   55: 
   56:     REACHABILITY_UNREACHABLE    = 0x00
   57:     REACHABILITY_DIRECT         = 0x01
   58:     REACHABILITY_TRANSPORT      = 0x02
   59: 
   60:     APP_NAME = "rnstransport"
   61: 
   62:     PATHFINDER_M                = 128          # Max hops
   63:     """
   64:     Maximum amount of hops that Reticulum will transport a packet.
```

    </details>
- **Value:** {'number': 1, 'unit': 'byte'}

## RNS.TRN.BEHAV.HDLC_FRAMING
- **Kind:** behaviour
- **Normative:** MUST
- **Statement:** HDLC framing (TCP, Serial, Pipe, Weave): packets delimited by FLAG 0x7E. Escape 0x7E to 0x7D 0x5E, 0x7D to 0x7D 0x5D. Unescape then extract frame between FLAG bytes.
- **References:**
  - RNS/Interfaces/TCPInterface.py (`HDLC`) lines 44–53 (definition)
    <details>
      <summary>Show code: RNS/Interfaces/TCPInterface.py:44–53 — HDLC — definition</summary>

```py
44: class HDLC():
45:     FLAG              = 0x7E
46:     ESC               = 0x7D
47:     ESC_MASK          = 0x20
48: 
49:     @staticmethod
50:     def escape(data):
51:         data = data.replace(bytes([HDLC.ESC]), bytes([HDLC.ESC, HDLC.ESC^HDLC.ESC_MASK]))
52:         data = data.replace(bytes([HDLC.FLAG]), bytes([HDLC.ESC, HDLC.FLAG^HDLC.ESC_MASK]))
53:         return data
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   34: import platform
   35: import socket
   36: import time
   37: import sys
   38: import os
   39: import RNS
   40: 
   41: class TCPInterface():
   42:     HW_MTU            = 262144
   43: 
>> 44: class HDLC():
>> 45:     FLAG              = 0x7E
>> 46:     ESC               = 0x7D
>> 47:     ESC_MASK          = 0x20
>> 48: 
>> 49:     @staticmethod
>> 50:     def escape(data):
>> 51:         data = data.replace(bytes([HDLC.ESC]), bytes([HDLC.ESC, HDLC.ESC^HDLC.ESC_MASK]))
>> 52:         data = data.replace(bytes([HDLC.FLAG]), bytes([HDLC.ESC, HDLC.FLAG^HDLC.ESC_MASK]))
>> 53:         return data
   54: 
   55: class KISS():
   56:     FEND              = 0xC0
   57:     FESC              = 0xDB
   58:     TFEND             = 0xDC
   59:     TFESC             = 0xDD
   60:     CMD_DATA          = 0x00
   61:     CMD_UNKNOWN       = 0xFE
   62: 
   63:     @staticmethod
```

    </details>

## RNS.TRN.BEHAV.KISS_FRAMING
- **Kind:** behaviour
- **Normative:** MUST
- **Statement:** KISS framing (packet radio): packets delimited by FEND 0xC0; command byte 0x00 (CMD_DATA) prepended before escaping. Escape 0xC0 to 0xDB 0xDC, 0xDB to 0xDB 0xDD. Unescape then payload is data after command byte between FEND boundaries.
- **References:**
  - RNS/Interfaces/TCPInterface.py (`KISS`) lines 55–66 (definition)
    <details>
      <summary>Show code: RNS/Interfaces/TCPInterface.py:55–66 — KISS — definition</summary>

```py
55: class KISS():
56:     FEND              = 0xC0
57:     FESC              = 0xDB
58:     TFEND             = 0xDC
59:     TFESC             = 0xDD
60:     CMD_DATA          = 0x00
61:     CMD_UNKNOWN       = 0xFE
62: 
63:     @staticmethod
64:     def escape(data):
65:         data = data.replace(bytes([0xdb]), bytes([0xdb, 0xdd]))
66:         data = data.replace(bytes([0xc0]), bytes([0xdb, 0xdc]))
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   45:     FLAG              = 0x7E
   46:     ESC               = 0x7D
   47:     ESC_MASK          = 0x20
   48: 
   49:     @staticmethod
   50:     def escape(data):
   51:         data = data.replace(bytes([HDLC.ESC]), bytes([HDLC.ESC, HDLC.ESC^HDLC.ESC_MASK]))
   52:         data = data.replace(bytes([HDLC.FLAG]), bytes([HDLC.ESC, HDLC.FLAG^HDLC.ESC_MASK]))
   53:         return data
   54: 
>> 55: class KISS():
>> 56:     FEND              = 0xC0
>> 57:     FESC              = 0xDB
>> 58:     TFEND             = 0xDC
>> 59:     TFESC             = 0xDD
>> 60:     CMD_DATA          = 0x00
>> 61:     CMD_UNKNOWN       = 0xFE
>> 62: 
>> 63:     @staticmethod
>> 64:     def escape(data):
>> 65:         data = data.replace(bytes([0xdb]), bytes([0xdb, 0xdd]))
>> 66:         data = data.replace(bytes([0xc0]), bytes([0xdb, 0xdc]))
   67:         return data
   68: 
   69: class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
   70:     pass
   71: 
   72: class ThreadingTCP6Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
   73:     address_family = socket.AF_INET6
   74: 
   75: class TCPClientInterface(Interface):
   76:     BITRATE_GUESS = 10*1000*1000
```

    </details>
  - RNS/Interfaces/KISSInterface.py (`KISS`) lines 38–57 (implementation)
    <details>
      <summary>Show code: RNS/Interfaces/KISSInterface.py:38–57 — KISS — implementation</summary>

```py
38: class KISS():
39:     FEND              = 0xC0
40:     FESC              = 0xDB
41:     TFEND             = 0xDC
42:     TFESC             = 0xDD
43:     CMD_UNKNOWN       = 0xFE
44:     CMD_DATA          = 0x00
45:     CMD_TXDELAY       = 0x01
46:     CMD_P             = 0x02
47:     CMD_SLOTTIME      = 0x03
48:     CMD_TXTAIL        = 0x04
49:     CMD_FULLDUPLEX    = 0x05
50:     CMD_SETHARDWARE   = 0x06
51:     CMD_READY         = 0x0F
52:     CMD_RETURN        = 0xFF
53: 
54:     @staticmethod
55:     def escape(data):
56:         data = data.replace(bytes([0xdb]), bytes([0xdb, 0xdd]))
57:         data = data.replace(bytes([0xc0]), bytes([0xdb, 0xdc]))
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   28: # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   29: # SOFTWARE.
   30: 
   31: from RNS.Interfaces.Interface import Interface
   32: from time import sleep
   33: import sys
   34: import threading
   35: import time
   36: import RNS
   37: 
>> 38: class KISS():
>> 39:     FEND              = 0xC0
>> 40:     FESC              = 0xDB
>> 41:     TFEND             = 0xDC
>> 42:     TFESC             = 0xDD
>> 43:     CMD_UNKNOWN       = 0xFE
>> 44:     CMD_DATA          = 0x00
>> 45:     CMD_TXDELAY       = 0x01
>> 46:     CMD_P             = 0x02
>> 47:     CMD_SLOTTIME      = 0x03
>> 48:     CMD_TXTAIL        = 0x04
>> 49:     CMD_FULLDUPLEX    = 0x05
>> 50:     CMD_SETHARDWARE   = 0x06
>> 51:     CMD_READY         = 0x0F
>> 52:     CMD_RETURN        = 0xFF
>> 53: 
>> 54:     @staticmethod
>> 55:     def escape(data):
>> 56:         data = data.replace(bytes([0xdb]), bytes([0xdb, 0xdd]))
>> 57:         data = data.replace(bytes([0xc0]), bytes([0xdb, 0xdc]))
   58:         return data
   59: 
   60: class KISSInterface(Interface):
   61:     MAX_CHUNK = 32768
   62:     BITRATE_GUESS = 1200
   63:     DEFAULT_IFAC_SIZE = 8
   64: 
   65:     owner    = None
   66:     port     = None
   67:     speed    = None
```

    </details>

## RNS.TRN.BEHAV.RAW_UDP
- **Kind:** behaviour
- **Normative:** NOTE
- **Statement:** UDPInterface sends on-wire packet bytes raw inside UDP payload; one datagram equals one packet (no HDLC or KISS).
- **References:**
  - RNS/Interfaces/UDPInterface.py (`UDPInterface`) lines 40–46 (definition)
    <details>
      <summary>Show code: RNS/Interfaces/UDPInterface.py:40–46 — UDPInterface — definition</summary>

```py
40: class UDPInterface(Interface):
41:     BITRATE_GUESS = 10*1000*1000
42:     DEFAULT_IFAC_SIZE = 16
43: 
44:     @staticmethod
45:     def get_address_for_if(name):
46:         from RNS.Interfaces import netinfo
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   30: 
   31: from RNS.Interfaces.Interface import Interface
   32: import socketserver
   33: import threading
   34: import socket
   35: import time
   36: import sys
   37: import RNS
   38: 
   39: 
>> 40: class UDPInterface(Interface):
>> 41:     BITRATE_GUESS = 10*1000*1000
>> 42:     DEFAULT_IFAC_SIZE = 16
>> 43: 
>> 44:     @staticmethod
>> 45:     def get_address_for_if(name):
>> 46:         from RNS.Interfaces import netinfo
   47:         ifaddr = netinfo.ifaddresses(name)
   48:         return ifaddr[netinfo.AF_INET][0]["addr"]
   49: 
   50:     @staticmethod
   51:     def get_broadcast_for_if(name):
   52:         from RNS.Interfaces import netinfo
   53:         ifaddr = netinfo.ifaddresses(name)
   54:         return ifaddr[netinfo.AF_INET][0]["broadcast"]
   55: 
   56:     def __init__(self, owner, configuration):
```

    </details>

## RNS.PKT.RULE.WELLFORMED_PACKET
- **Kind:** validation_rule
- **Normative:** MUST
- **Statement:** After IFAC removal (if present), packet MUST be parseable as HEADER_1 or HEADER_2 and length MUST be at least HEADER_MINSIZE or HEADER_MAXSIZE respectively. Malformed packets MUST be discarded.
- **References:**
  - RNS/Transport.py (`inbound`) lines 1241–1250 (implementation)
    <details>
      <summary>Show code: RNS/Transport.py:1241–1250 — inbound — implementation</summary>

```py
1241:     def inbound(raw, interface=None):
1242:         # If interface access codes are enabled,
1243:         # we must authenticate each packet.
1244:         if len(raw) > 2:
1245:             if interface != None and hasattr(interface, "ifac_identity") and interface.ifac_identity != None:
1246:                 # Check that IFAC flag is set
1247:                 if raw[0] & 0x80 == 0x80:
1248:                     if len(raw) > 2+interface.ifac_size:
1249:                         # Extract IFAC
1250:                         ifac = raw[2:2+interface.ifac_size]
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   1231:                 if packet.destination_type == RNS.Destination.SINGLE:
   1232:                     return True
   1233:                 else:
   1234:                     RNS.log("Dropped invalid announce packet", RNS.LOG_DEBUG)
   1235:                     return False
   1236: 
   1237:         RNS.log("Filtered packet with hash "+RNS.prettyhexrep(packet.packet_hash), RNS.LOG_EXTREME)
   1238:         return False
   1239: 
   1240:     @staticmethod
>> 1241:     def inbound(raw, interface=None):
>> 1242:         # If interface access codes are enabled,
>> 1243:         # we must authenticate each packet.
>> 1244:         if len(raw) > 2:
>> 1245:             if interface != None and hasattr(interface, "ifac_identity") and interface.ifac_identity != None:
>> 1246:                 # Check that IFAC flag is set
>> 1247:                 if raw[0] & 0x80 == 0x80:
>> 1248:                     if len(raw) > 2+interface.ifac_size:
>> 1249:                         # Extract IFAC
>> 1250:                         ifac = raw[2:2+interface.ifac_size]
   1251: 
   1252:                         # Generate mask
   1253:                         mask = RNS.Cryptography.hkdf(
   1254:                             length=len(raw),
   1255:                             derive_from=ifac,
   1256:                             salt=interface.ifac_key,
   1257:                             context=None,
   1258:                         )
   1259: 
   1260:                         # Unmask payload
```

    </details>

## RNS.PKT.RULE.UNKNOWN_CONTEXT_OPAQUE
- **Kind:** validation_rule
- **Normative:** MUST
- **Statement:** Unknown context or packet type values MAY appear on the wire; implementations MUST NOT assign semantics to unknown values and MUST treat payload as opaque (drop or forward without interpreting).
- **References:**
  - RNS/Transport.py (`inbound`) lines 1241–1250 (dispatch)
    <details>
      <summary>Show code: RNS/Transport.py:1241–1250 — inbound — dispatch</summary>

```py
1241:     def inbound(raw, interface=None):
1242:         # If interface access codes are enabled,
1243:         # we must authenticate each packet.
1244:         if len(raw) > 2:
1245:             if interface != None and hasattr(interface, "ifac_identity") and interface.ifac_identity != None:
1246:                 # Check that IFAC flag is set
1247:                 if raw[0] & 0x80 == 0x80:
1248:                     if len(raw) > 2+interface.ifac_size:
1249:                         # Extract IFAC
1250:                         ifac = raw[2:2+interface.ifac_size]
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   1231:                 if packet.destination_type == RNS.Destination.SINGLE:
   1232:                     return True
   1233:                 else:
   1234:                     RNS.log("Dropped invalid announce packet", RNS.LOG_DEBUG)
   1235:                     return False
   1236: 
   1237:         RNS.log("Filtered packet with hash "+RNS.prettyhexrep(packet.packet_hash), RNS.LOG_EXTREME)
   1238:         return False
   1239: 
   1240:     @staticmethod
>> 1241:     def inbound(raw, interface=None):
>> 1242:         # If interface access codes are enabled,
>> 1243:         # we must authenticate each packet.
>> 1244:         if len(raw) > 2:
>> 1245:             if interface != None and hasattr(interface, "ifac_identity") and interface.ifac_identity != None:
>> 1246:                 # Check that IFAC flag is set
>> 1247:                 if raw[0] & 0x80 == 0x80:
>> 1248:                     if len(raw) > 2+interface.ifac_size:
>> 1249:                         # Extract IFAC
>> 1250:                         ifac = raw[2:2+interface.ifac_size]
   1251: 
   1252:                         # Generate mask
   1253:                         mask = RNS.Cryptography.hkdf(
   1254:                             length=len(raw),
   1255:                             derive_from=ifac,
   1256:                             salt=interface.ifac_key,
   1257:                             context=None,
   1258:                         )
   1259: 
   1260:                         # Unmask payload
```

    </details>

## RNS.PKT.LAYOUT.PROOF_EXPLICIT
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Explicit proof payload: Packet_Hash (32 bytes) + Signature (64 bytes); total 96 bytes. Receiver validates hash matches proved packet and signature over hash.
- **References:**
  - RNS/Packet.py (`EXPL_LENGTH`) lines 413–414 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:413–414 — EXPL_LENGTH — definition</summary>

```py
413:     EXPL_LENGTH = RNS.Identity.HASHLENGTH//8+RNS.Identity.SIGLENGTH//8
414:     IMPL_LENGTH = RNS.Identity.SIGLENGTH//8
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   403:     of this class are never created manually, but always returned from
   404:     the *send()* method of a :ref:`RNS.Packet<api-packet>` instance.
   405:     """
   406:     # Receipt status constants
   407:     FAILED    = 0x00
   408:     SENT      = 0x01
   409:     DELIVERED = 0x02
   410:     CULLED    = 0xFF
   411: 
   412: 
>> 413:     EXPL_LENGTH = RNS.Identity.HASHLENGTH//8+RNS.Identity.SIGLENGTH//8
>> 414:     IMPL_LENGTH = RNS.Identity.SIGLENGTH//8
   415: 
   416:     # Creates a new packet receipt from a sent packet
   417:     def __init__(self, packet):
   418:         self.hash           = packet.get_hash()
   419:         self.truncated_hash = packet.getTruncatedHash()
   420:         self.sent           = True
   421:         self.sent_at        = time.time()
   422:         self.proved         = False
   423:         self.status         = PacketReceipt.SENT
   424:         self.destination    = packet.destination
```

    </details>
- **Layout fields:**
  - packet_hash: offset 0, length 32
  - signature: offset 32, length 64

## RNS.PKT.LAYOUT.PROOF_IMPLICIT
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Implicit proof payload: Signature (64 bytes) only. Receiver infers proved packet by validating signature against pending packets.
- **References:**
  - RNS/Packet.py (`IMPL_LENGTH`) lines 413–414 (definition)
    <details>
      <summary>Show code: RNS/Packet.py:413–414 — IMPL_LENGTH — definition</summary>

```py
413:     EXPL_LENGTH = RNS.Identity.HASHLENGTH//8+RNS.Identity.SIGLENGTH//8
414:     IMPL_LENGTH = RNS.Identity.SIGLENGTH//8
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   403:     of this class are never created manually, but always returned from
   404:     the *send()* method of a :ref:`RNS.Packet<api-packet>` instance.
   405:     """
   406:     # Receipt status constants
   407:     FAILED    = 0x00
   408:     SENT      = 0x01
   409:     DELIVERED = 0x02
   410:     CULLED    = 0xFF
   411: 
   412: 
>> 413:     EXPL_LENGTH = RNS.Identity.HASHLENGTH//8+RNS.Identity.SIGLENGTH//8
>> 414:     IMPL_LENGTH = RNS.Identity.SIGLENGTH//8
   415: 
   416:     # Creates a new packet receipt from a sent packet
   417:     def __init__(self, packet):
   418:         self.hash           = packet.get_hash()
   419:         self.truncated_hash = packet.getTruncatedHash()
   420:         self.sent           = True
   421:         self.sent_at        = time.time()
   422:         self.proved         = False
   423:         self.status         = PacketReceipt.SENT
   424:         self.destination    = packet.destination
```

    </details>
- **Layout fields:**
  - signature: offset 0, length 64

## RNS.LNK.LAYOUT.LINKREQUEST_PAYLOAD
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Link request payload: Initiator X25519 public key (32 bytes) + Initiator Ed25519 public key (32 bytes) + optional Signalling bytes (3 bytes). Total 64 or 67 bytes.
- **References:**
  - RNS/Link.py (`ECPUBSIZE`) lines 70–80 (definition)
    <details>
      <summary>Show code: RNS/Link.py:70–80 — ECPUBSIZE — definition</summary>

```py
70:     ECPUBSIZE         = 32+32
71:     KEYSIZE           = 32
72: 
73:     MDU = math.floor((RNS.Reticulum.MTU-RNS.Reticulum.IFAC_MIN_SIZE-RNS.Reticulum.HEADER_MINSIZE-RNS.Identity.TOKEN_OVERHEAD)/RNS.Identity.AES128_BLOCKSIZE)*RNS.Identity.AES128_BLOCKSIZE - 1
74: 
75:     ESTABLISHMENT_TIMEOUT_PER_HOP = RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT
76:     """
77:     Timeout for link establishment in seconds per hop to destination.
78:     """
79: 
80:     LINK_MTU_SIZE            = 3
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   60: 
   61:     :param destination: A :ref:`RNS.Destination<api-destination>` instance which to establish a link to.
   62:     :param established_callback: An optional function or method with the signature *callback(link)* to be called when the link has been established.
   63:     :param closed_callback: An optional function or method with the signature *callback(link)* to be called when the link is closed.
   64:     """
   65:     CURVE = RNS.Identity.CURVE
   66:     """
   67:     The curve used for Elliptic Curve DH key exchanges
   68:     """
   69: 
>> 70:     ECPUBSIZE         = 32+32
>> 71:     KEYSIZE           = 32
>> 72: 
>> 73:     MDU = math.floor((RNS.Reticulum.MTU-RNS.Reticulum.IFAC_MIN_SIZE-RNS.Reticulum.HEADER_MINSIZE-RNS.Identity.TOKEN_OVERHEAD)/RNS.Identity.AES128_BLOCKSIZE)*RNS.Identity.AES128_BLOCKSIZE - 1
>> 74: 
>> 75:     ESTABLISHMENT_TIMEOUT_PER_HOP = RNS.Reticulum.DEFAULT_PER_HOP_TIMEOUT
>> 76:     """
>> 77:     Timeout for link establishment in seconds per hop to destination.
>> 78:     """
>> 79: 
>> 80:     LINK_MTU_SIZE            = 3
   81:     TRAFFIC_TIMEOUT_MIN_MS   = 5
   82:     TRAFFIC_TIMEOUT_FACTOR   = 6
   83:     KEEPALIVE_MAX_RTT        = 1.75
   84:     KEEPALIVE_TIMEOUT_FACTOR = 4
   85:     """
   86:     RTT timeout factor used in link timeout calculation.
   87:     """
   88:     STALE_GRACE = 5
   89:     """
   90:     Grace period in seconds used in link timeout calculation.
```

    </details>
- **Layout fields:**
  - initiator_x25519: offset 0, length 32
  - initiator_ed25519: offset 32, length 32
  - signalling: offset 64, length 3

## RNS.LNK.LAYOUT.LINKPROOF_PAYLOAD
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Link proof (LRPROOF) payload: Ed25519 Signature (64 bytes) + Responder X25519 public key (32 bytes) + optional Signalling bytes (3 bytes). Signed data = link_id + Responder X25519 + Responder Ed25519 + Signalling.
- **References:**
  - RNS/Link.py (`prove`) lines 371–377 (definition)
    <details>
      <summary>Show code: RNS/Link.py:371–377 — prove — definition</summary>

```py
371:     def prove(self):
372:         signalling_bytes = Link.signalling_bytes(self.mtu, self.mode)
373:         signed_data = self.link_id+self.pub_bytes+self.sig_pub_bytes+signalling_bytes
374:         signature = self.owner.identity.sign(signed_data)
375: 
376:         proof_data = signature+self.pub_bytes+signalling_bytes
377:         proof = RNS.Packet(self, proof_data, packet_type=RNS.Packet.PROOF, context=RNS.Packet.LRPROOF)
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   361: 
   362:             self.derived_key = RNS.Cryptography.hkdf(
   363:                 length=derived_key_length,
   364:                 derive_from=self.shared_key,
   365:                 salt=self.get_salt(),
   366:                 context=self.get_context())
   367: 
   368:         else: RNS.log("Handshake attempt on "+str(self)+" with invalid state "+str(self.status), RNS.LOG_ERROR)
   369: 
   370: 
>> 371:     def prove(self):
>> 372:         signalling_bytes = Link.signalling_bytes(self.mtu, self.mode)
>> 373:         signed_data = self.link_id+self.pub_bytes+self.sig_pub_bytes+signalling_bytes
>> 374:         signature = self.owner.identity.sign(signed_data)
>> 375: 
>> 376:         proof_data = signature+self.pub_bytes+signalling_bytes
>> 377:         proof = RNS.Packet(self, proof_data, packet_type=RNS.Packet.PROOF, context=RNS.Packet.LRPROOF)
   378:         proof.send()
   379:         self.establishment_cost += len(proof.raw)
   380:         self.had_outbound()
   381: 
   382: 
   383:     def prove_packet(self, packet):
   384:         signature = self.sign(packet.packet_hash)
   385:         # TODO: Hardcoded as explicit proof for now
   386:         # if RNS.Reticulum.should_use_implicit_proof():
   387:         #   proof_data = signature
```

    </details>
- **Layout fields:**
  - signature: offset 0, length 64
  - responder_x25519: offset 64, length 32
  - signalling: offset 96, length 3

## RNS.LNK.ALG.LINKPROOF_SIGNED_DATA
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** Link proof signed data is link_id (16 bytes) + Responder X25519 (32) + Responder Ed25519 (32) + Signalling bytes (3). Signature is Ed25519 over that concatenation.
- **References:**
  - RNS/Link.py (`prove`) lines 371–377 (implementation)
    <details>
      <summary>Show code: RNS/Link.py:371–377 — prove — implementation</summary>

```py
371:     def prove(self):
372:         signalling_bytes = Link.signalling_bytes(self.mtu, self.mode)
373:         signed_data = self.link_id+self.pub_bytes+self.sig_pub_bytes+signalling_bytes
374:         signature = self.owner.identity.sign(signed_data)
375: 
376:         proof_data = signature+self.pub_bytes+signalling_bytes
377:         proof = RNS.Packet(self, proof_data, packet_type=RNS.Packet.PROOF, context=RNS.Packet.LRPROOF)
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   361: 
   362:             self.derived_key = RNS.Cryptography.hkdf(
   363:                 length=derived_key_length,
   364:                 derive_from=self.shared_key,
   365:                 salt=self.get_salt(),
   366:                 context=self.get_context())
   367: 
   368:         else: RNS.log("Handshake attempt on "+str(self)+" with invalid state "+str(self.status), RNS.LOG_ERROR)
   369: 
   370: 
>> 371:     def prove(self):
>> 372:         signalling_bytes = Link.signalling_bytes(self.mtu, self.mode)
>> 373:         signed_data = self.link_id+self.pub_bytes+self.sig_pub_bytes+signalling_bytes
>> 374:         signature = self.owner.identity.sign(signed_data)
>> 375: 
>> 376:         proof_data = signature+self.pub_bytes+signalling_bytes
>> 377:         proof = RNS.Packet(self, proof_data, packet_type=RNS.Packet.PROOF, context=RNS.Packet.LRPROOF)
   378:         proof.send()
   379:         self.establishment_cost += len(proof.raw)
   380:         self.had_outbound()
   381: 
   382: 
   383:     def prove_packet(self, packet):
   384:         signature = self.sign(packet.packet_hash)
   385:         # TODO: Hardcoded as explicit proof for now
   386:         # if RNS.Reticulum.should_use_implicit_proof():
   387:         #   proof_data = signature
```

    </details>
- **Steps:**
  - signed_data = link_id + pub_bytes + sig_pub_bytes + signalling_bytes.
  - signature = identity.sign(signed_data).
  - proof_data = signature + pub_bytes + signalling_bytes.

## RNS.PKT.LAYOUT.TOKEN
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Token (encryption envelope): IV (16 bytes) + AES-256-CBC ciphertext (PKCS7-padded) + HMAC-SHA256 (32 bytes, final 32 bytes of token). Total overhead 48 bytes (TOKEN_OVERHEAD).
- **References:**
  - RNS/Cryptography/Token.py (`TOKEN_OVERHEAD`) lines 48–52 (definition)
    <details>
      <summary>Show code: RNS/Cryptography/Token.py:48–52 — TOKEN_OVERHEAD — definition</summary>

```py
48:     implementation, since they incur overhead and leak initiator metadata.
49:     """
50:     TOKEN_OVERHEAD  = 48 # Bytes
51: 
52:     @staticmethod
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   38: from RNS.Cryptography.AES import AES_256_CBC
   39: 
   40: class Token():
   41:     """
   42:     This class provides a slightly modified implementation of the Fernet spec
   43:     found at: https://github.com/fernet/spec/blob/master/Spec.md
   44: 
   45:     According to the spec, a Fernet token includes a one byte VERSION and
   46:     eight byte TIMESTAMP field at the start of each token. These fields are
   47:     not relevant to Reticulum. They are therefore stripped from this
>> 48:     implementation, since they incur overhead and leak initiator metadata.
>> 49:     """
>> 50:     TOKEN_OVERHEAD  = 48 # Bytes
>> 51: 
>> 52:     @staticmethod
   53:     def generate_key(mode=AES_256_CBC):
   54:         if   mode == AES_128_CBC: return os.urandom(32)
   55:         elif mode == AES_256_CBC: return os.urandom(64)
   56:         else: raise TypeError(f"Invalid token mode: {mode}")
   57: 
   58:     def __init__(self, key=None, mode=AES):
   59:         if key == None: raise ValueError("Token key cannot be None")
   60: 
   61:         if mode == AES:
   62:             if len(key) == 32:
```

    </details>
- **Layout fields:**
  - iv: offset 0, length 16
  - ciphertext: offset 16, length 0

## RNS.PKT.ALG.SINGLE_ENCRYPTION
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** SINGLE-destination encryption: Ephemeral X25519 public key (32 bytes) + Token (IV + ciphertext + HMAC). Key derived via HKDF from ECDH shared key, salt = identity truncated hash, length 64, split: first 32 = HMAC key, next 32 = AES key.
- **References:**
  - RNS/Identity.py (`encrypt`) lines 668–690 (implementation)
    <details>
      <summary>Show code: RNS/Identity.py:668–690 — encrypt — implementation</summary>

```py
668:     def encrypt(self, plaintext, ratchet=None):
669:         """
670:         Encrypts information for the identity.
671: 
672:         :param plaintext: The plaintext to be encrypted as *bytes*.
673:         :returns: Ciphertext token as *bytes*.
674:         :raises: *KeyError* if the instance does not hold a public key.
675:         """
676:         if self.pub != None:
677:             ephemeral_key = X25519PrivateKey.generate()
678:             ephemeral_pub_bytes = ephemeral_key.public_key().public_bytes()
679: 
680:             if ratchet != None:
681:                 target_public_key = X25519PublicKey.from_public_bytes(ratchet)
682:             else:
683:                 target_public_key = self.pub
684: 
685:             shared_key = ephemeral_key.exchange(target_public_key)
686:             
687:             derived_key = RNS.Cryptography.hkdf(
688:                 length=Identity.DERIVED_KEY_LENGTH,
689:                 derive_from=shared_key,
690:                 salt=self.get_salt(),
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   658:         except Exception as e:
   659:             RNS.log("Error while loading identity from "+str(path), RNS.LOG_ERROR)
   660:             RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)
   661: 
   662:     def get_salt(self):
   663:         return self.hash
   664: 
   665:     def get_context(self):
   666:         return None
   667: 
>> 668:     def encrypt(self, plaintext, ratchet=None):
>> 669:         """
>> 670:         Encrypts information for the identity.
>> 671: 
>> 672:         :param plaintext: The plaintext to be encrypted as *bytes*.
>> 673:         :returns: Ciphertext token as *bytes*.
>> 674:         :raises: *KeyError* if the instance does not hold a public key.
>> 675:         """
>> 676:         if self.pub != None:
>> 677:             ephemeral_key = X25519PrivateKey.generate()
>> 678:             ephemeral_pub_bytes = ephemeral_key.public_key().public_bytes()
>> 679: 
>> 680:             if ratchet != None:
>> 681:                 target_public_key = X25519PublicKey.from_public_bytes(ratchet)
>> 682:             else:
>> 683:                 target_public_key = self.pub
>> 684: 
>> 685:             shared_key = ephemeral_key.exchange(target_public_key)
>> 686:             
>> 687:             derived_key = RNS.Cryptography.hkdf(
>> 688:                 length=Identity.DERIVED_KEY_LENGTH,
>> 689:                 derive_from=shared_key,
>> 690:                 salt=self.get_salt(),
   691:                 context=self.get_context(),
   692:             )
   693: 
   694:             token = Token(derived_key)
   695:             ciphertext = token.encrypt(plaintext)
   696:             token = ephemeral_pub_bytes+ciphertext
   697: 
   698:             return token
   699:         else:
   700:             raise KeyError("Encryption failed because identity does not hold a public key")
```

    </details>
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
  - RNS/Link.py (`encrypt`) lines 1191–1210 (implementation)
    <details>
      <summary>Show code: RNS/Link.py:1191–1210 — encrypt — implementation</summary>

```py
1191:     def encrypt(self, plaintext):
1192:         try:
1193:             if not self.token:
1194:                 try: self.token = Token(self.derived_key)
1195:                 except Exception as e:
1196:                     RNS.log("Could not instantiate token while performing encryption on link "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)
1197:                     raise e
1198: 
1199:             return self.token.encrypt(plaintext)
1200: 
1201:         except Exception as e:
1202:             RNS.log("Encryption on link "+str(self)+" failed. The contained exception was: "+str(e), RNS.LOG_ERROR)
1203:             raise e
1204: 
1205: 
1206:     def decrypt(self, ciphertext):
1207:         try:
1208:             if not self.token: self.token = Token(self.derived_key)
1209:             return self.token.decrypt(ciphertext)
1210: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   1181:                         resource_hash = packet.data[0:RNS.Identity.HASHLENGTH//8]
   1182:                         for resource in self.outgoing_resources:
   1183:                             if resource_hash == resource.hash:
   1184:                                 def job(): resource.validate_proof(packet.data)
   1185:                                 threading.Thread(target=job, daemon=True).start()
   1186:                                 self.__update_phy_stats(packet, query_shared=True)
   1187: 
   1188:         self.watchdog_lock = False
   1189: 
   1190: 
>> 1191:     def encrypt(self, plaintext):
>> 1192:         try:
>> 1193:             if not self.token:
>> 1194:                 try: self.token = Token(self.derived_key)
>> 1195:                 except Exception as e:
>> 1196:                     RNS.log("Could not instantiate token while performing encryption on link "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)
>> 1197:                     raise e
>> 1198: 
>> 1199:             return self.token.encrypt(plaintext)
>> 1200: 
>> 1201:         except Exception as e:
>> 1202:             RNS.log("Encryption on link "+str(self)+" failed. The contained exception was: "+str(e), RNS.LOG_ERROR)
>> 1203:             raise e
>> 1204: 
>> 1205: 
>> 1206:     def decrypt(self, ciphertext):
>> 1207:         try:
>> 1208:             if not self.token: self.token = Token(self.derived_key)
>> 1209:             return self.token.decrypt(ciphertext)
>> 1210: 
   1211:         except Exception as e:
   1212:             RNS.log("Decryption failed on link "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)
   1213:             return None
   1214: 
   1215: 
   1216:     def sign(self, message):
   1217:         return self.sig_prv.sign(message)
   1218: 
   1219:     def validate(self, signature, message):
   1220:         try:
```

    </details>
- **Steps:**
  - shared_key = X25519(link_prv, peer_pub) or inverse for other side.
  - derived = HKDF(derive_from=shared_key, salt=link_id, context=b'', length=32 or 64).
  - ciphertext = Token(derived).encrypt(plaintext); no ephemeral prefix.

## RNS.PKT.LAYOUT.ANNOUNCE_WITH_RATCHET
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Announce payload with ratchet (context flag 1): PublicKey (64) + NameHash (10) + RandomHash (10) + RatchetKey (32) + Signature (64) + optional App Data. Fixed header 176 bytes.
- **References:**
  - RNS/Identity.py (`validate_announce`) lines 391–424 (definition)
    <details>
      <summary>Show code: RNS/Identity.py:391–424 — validate_announce — definition</summary>

```py
391:     def validate_announce(packet, only_validate_signature=False):
392:         try:
393:             if packet.packet_type == RNS.Packet.ANNOUNCE:
394:                 keysize       = Identity.KEYSIZE//8
395:                 ratchetsize   = Identity.RATCHETSIZE//8
396:                 name_hash_len = Identity.NAME_HASH_LENGTH//8
397:                 sig_len       = Identity.SIGLENGTH//8
398:                 destination_hash = packet.destination_hash
399: 
400:                 # Get public key bytes from announce
401:                 public_key = packet.data[:keysize]
402: 
403:                 # If the packet context flag is set,
404:                 # this announce contains a new ratchet
405:                 if packet.context_flag == RNS.Packet.FLAG_SET:
406:                     name_hash   = packet.data[keysize:keysize+name_hash_len ]
407:                     random_hash = packet.data[keysize+name_hash_len:keysize+name_hash_len+10]
408:                     ratchet     = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+ratchetsize]
409:                     signature   = packet.data[keysize+name_hash_len+10+ratchetsize:keysize+name_hash_len+10+ratchetsize+sig_len]
410:                     app_data    = b""
411:                     if len(packet.data) > keysize+name_hash_len+10+sig_len+ratchetsize:
412:                         app_data = packet.data[keysize+name_hash_len+10+sig_len+ratchetsize:]
413: 
414:                 # If the packet context flag is not set,
415:                 # this announce does not contain a ratchet
416:                 else:
417:                     ratchet     = b""
418:                     name_hash   = packet.data[keysize:keysize+name_hash_len]
419:                     random_hash = packet.data[keysize+name_hash_len:keysize+name_hash_len+10]
420:                     signature   = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+sig_len]
421:                     app_data    = b""
422:                     if len(packet.data) > keysize+name_hash_len+10+sig_len:
423:                         app_data = packet.data[keysize+name_hash_len+10+sig_len:]
424: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   381:                     RNS.log(f"The contained exception was: {e}", RNS.LOG_ERROR)
   382:                     return None
   383: 
   384:         if destination_hash in Identity.known_ratchets:
   385:             return Identity.known_ratchets[destination_hash]
   386:         else:
   387:             RNS.log(f"Could not load ratchet for {RNS.prettyhexrep(destination_hash)}", RNS.LOG_DEBUG)
   388:             return None
   389: 
   390:     @staticmethod
>> 391:     def validate_announce(packet, only_validate_signature=False):
>> 392:         try:
>> 393:             if packet.packet_type == RNS.Packet.ANNOUNCE:
>> 394:                 keysize       = Identity.KEYSIZE//8
>> 395:                 ratchetsize   = Identity.RATCHETSIZE//8
>> 396:                 name_hash_len = Identity.NAME_HASH_LENGTH//8
>> 397:                 sig_len       = Identity.SIGLENGTH//8
>> 398:                 destination_hash = packet.destination_hash
>> 399: 
>> 400:                 # Get public key bytes from announce
>> 401:                 public_key = packet.data[:keysize]
>> 402: 
>> 403:                 # If the packet context flag is set,
>> 404:                 # this announce contains a new ratchet
>> 405:                 if packet.context_flag == RNS.Packet.FLAG_SET:
>> 406:                     name_hash   = packet.data[keysize:keysize+name_hash_len ]
>> 407:                     random_hash = packet.data[keysize+name_hash_len:keysize+name_hash_len+10]
>> 408:                     ratchet     = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+ratchetsize]
>> 409:                     signature   = packet.data[keysize+name_hash_len+10+ratchetsize:keysize+name_hash_len+10+ratchetsize+sig_len]
>> 410:                     app_data    = b""
>> 411:                     if len(packet.data) > keysize+name_hash_len+10+sig_len+ratchetsize:
>> 412:                         app_data = packet.data[keysize+name_hash_len+10+sig_len+ratchetsize:]
>> 413: 
>> 414:                 # If the packet context flag is not set,
>> 415:                 # this announce does not contain a ratchet
>> 416:                 else:
>> 417:                     ratchet     = b""
>> 418:                     name_hash   = packet.data[keysize:keysize+name_hash_len]
>> 419:                     random_hash = packet.data[keysize+name_hash_len:keysize+name_hash_len+10]
>> 420:                     signature   = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+sig_len]
>> 421:                     app_data    = b""
>> 422:                     if len(packet.data) > keysize+name_hash_len+10+sig_len:
>> 423:                         app_data = packet.data[keysize+name_hash_len+10+sig_len:]
>> 424: 
   425:                 signed_data = destination_hash+public_key+name_hash+random_hash+ratchet+app_data
   426: 
   427:                 if not len(packet.data) > Identity.KEYSIZE//8+Identity.NAME_HASH_LENGTH//8+10+Identity.SIGLENGTH//8:
   428:                     app_data = None
   429: 
   430:                 announced_identity = Identity(create_keys=False)
   431:                 announced_identity.load_public_key(public_key)
   432: 
   433:                 if len(RNS.Transport.blackholed_identities) > 0:
   434:                     if announced_identity.hash in RNS.Transport.blackholed_identities:
```

    </details>
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
  - RNS/Identity.py (`validate_announce`) lines 391–424 (definition)
    <details>
      <summary>Show code: RNS/Identity.py:391–424 — validate_announce — definition</summary>

```py
391:     def validate_announce(packet, only_validate_signature=False):
392:         try:
393:             if packet.packet_type == RNS.Packet.ANNOUNCE:
394:                 keysize       = Identity.KEYSIZE//8
395:                 ratchetsize   = Identity.RATCHETSIZE//8
396:                 name_hash_len = Identity.NAME_HASH_LENGTH//8
397:                 sig_len       = Identity.SIGLENGTH//8
398:                 destination_hash = packet.destination_hash
399: 
400:                 # Get public key bytes from announce
401:                 public_key = packet.data[:keysize]
402: 
403:                 # If the packet context flag is set,
404:                 # this announce contains a new ratchet
405:                 if packet.context_flag == RNS.Packet.FLAG_SET:
406:                     name_hash   = packet.data[keysize:keysize+name_hash_len ]
407:                     random_hash = packet.data[keysize+name_hash_len:keysize+name_hash_len+10]
408:                     ratchet     = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+ratchetsize]
409:                     signature   = packet.data[keysize+name_hash_len+10+ratchetsize:keysize+name_hash_len+10+ratchetsize+sig_len]
410:                     app_data    = b""
411:                     if len(packet.data) > keysize+name_hash_len+10+sig_len+ratchetsize:
412:                         app_data = packet.data[keysize+name_hash_len+10+sig_len+ratchetsize:]
413: 
414:                 # If the packet context flag is not set,
415:                 # this announce does not contain a ratchet
416:                 else:
417:                     ratchet     = b""
418:                     name_hash   = packet.data[keysize:keysize+name_hash_len]
419:                     random_hash = packet.data[keysize+name_hash_len:keysize+name_hash_len+10]
420:                     signature   = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+sig_len]
421:                     app_data    = b""
422:                     if len(packet.data) > keysize+name_hash_len+10+sig_len:
423:                         app_data = packet.data[keysize+name_hash_len+10+sig_len:]
424: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   381:                     RNS.log(f"The contained exception was: {e}", RNS.LOG_ERROR)
   382:                     return None
   383: 
   384:         if destination_hash in Identity.known_ratchets:
   385:             return Identity.known_ratchets[destination_hash]
   386:         else:
   387:             RNS.log(f"Could not load ratchet for {RNS.prettyhexrep(destination_hash)}", RNS.LOG_DEBUG)
   388:             return None
   389: 
   390:     @staticmethod
>> 391:     def validate_announce(packet, only_validate_signature=False):
>> 392:         try:
>> 393:             if packet.packet_type == RNS.Packet.ANNOUNCE:
>> 394:                 keysize       = Identity.KEYSIZE//8
>> 395:                 ratchetsize   = Identity.RATCHETSIZE//8
>> 396:                 name_hash_len = Identity.NAME_HASH_LENGTH//8
>> 397:                 sig_len       = Identity.SIGLENGTH//8
>> 398:                 destination_hash = packet.destination_hash
>> 399: 
>> 400:                 # Get public key bytes from announce
>> 401:                 public_key = packet.data[:keysize]
>> 402: 
>> 403:                 # If the packet context flag is set,
>> 404:                 # this announce contains a new ratchet
>> 405:                 if packet.context_flag == RNS.Packet.FLAG_SET:
>> 406:                     name_hash   = packet.data[keysize:keysize+name_hash_len ]
>> 407:                     random_hash = packet.data[keysize+name_hash_len:keysize+name_hash_len+10]
>> 408:                     ratchet     = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+ratchetsize]
>> 409:                     signature   = packet.data[keysize+name_hash_len+10+ratchetsize:keysize+name_hash_len+10+ratchetsize+sig_len]
>> 410:                     app_data    = b""
>> 411:                     if len(packet.data) > keysize+name_hash_len+10+sig_len+ratchetsize:
>> 412:                         app_data = packet.data[keysize+name_hash_len+10+sig_len+ratchetsize:]
>> 413: 
>> 414:                 # If the packet context flag is not set,
>> 415:                 # this announce does not contain a ratchet
>> 416:                 else:
>> 417:                     ratchet     = b""
>> 418:                     name_hash   = packet.data[keysize:keysize+name_hash_len]
>> 419:                     random_hash = packet.data[keysize+name_hash_len:keysize+name_hash_len+10]
>> 420:                     signature   = packet.data[keysize+name_hash_len+10:keysize+name_hash_len+10+sig_len]
>> 421:                     app_data    = b""
>> 422:                     if len(packet.data) > keysize+name_hash_len+10+sig_len:
>> 423:                         app_data = packet.data[keysize+name_hash_len+10+sig_len:]
>> 424: 
   425:                 signed_data = destination_hash+public_key+name_hash+random_hash+ratchet+app_data
   426: 
   427:                 if not len(packet.data) > Identity.KEYSIZE//8+Identity.NAME_HASH_LENGTH//8+10+Identity.SIGLENGTH//8:
   428:                     app_data = None
   429: 
   430:                 announced_identity = Identity(create_keys=False)
   431:                 announced_identity.load_public_key(public_key)
   432: 
   433:                 if len(RNS.Transport.blackholed_identities) > 0:
   434:                     if announced_identity.hash in RNS.Transport.blackholed_identities:
```

    </details>
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
  - RNS/Link.py (`KEEPALIVE`) lines 850–856 (implementation)
    <details>
      <summary>Show code: RNS/Link.py:850–856 — KEEPALIVE — implementation</summary>

```py
850:         self.stale_time = self.keepalive * Link.STALE_FACTOR
851:     
852:     def send_keepalive(self):
853:         keepalive_packet = RNS.Packet(self, bytes([0xFF]), context=RNS.Packet.KEEPALIVE)
854:         keepalive_packet.send()
855:         self.had_outbound(is_keepalive = True)
856: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   840: 
   841:             if packet.rssi != None:
   842:                 self.rssi = packet.rssi
   843:             if packet.snr != None:
   844:                 self.snr = packet.snr
   845:             if packet.q != None:
   846:                 self.q = packet.q
   847: 
   848:     def __update_keepalive(self):
   849:         self.keepalive = max(min(self.rtt*(Link.KEEPALIVE_MAX/Link.KEEPALIVE_MAX_RTT), Link.KEEPALIVE_MAX), Link.KEEPALIVE_MIN)
>> 850:         self.stale_time = self.keepalive * Link.STALE_FACTOR
>> 851:     
>> 852:     def send_keepalive(self):
>> 853:         keepalive_packet = RNS.Packet(self, bytes([0xFF]), context=RNS.Packet.KEEPALIVE)
>> 854:         keepalive_packet.send()
>> 855:         self.had_outbound(is_keepalive = True)
>> 856: 
   857:     def handle_request(self, request_id, unpacked_request):
   858:         if self.status == Link.ACTIVE:
   859:             requested_at = unpacked_request[0]
   860:             path_hash    = unpacked_request[1]
   861:             request_data = unpacked_request[2]
   862: 
   863:             if path_hash in self.destination.request_handlers:
   864:                 request_handler = self.destination.request_handlers[path_hash]
   865:                 path               = request_handler[0]
   866:                 response_generator = request_handler[1]
```

    </details>
- **Value:** {'number': 255, 'unit': 'byte'}

## RNS.LNK.CONST.KEEPALIVE_RESPONDER
- **Kind:** constant
- **Normative:** MUST
- **Statement:** KEEPALIVE payload responder to initiator: single byte 0xFE.
- **References:**
  - RNS/Link.py (`KEEPALIVE`) lines 1151–1158 (implementation)
    <details>
      <summary>Show code: RNS/Link.py:1151–1158 — KEEPALIVE — implementation</summary>

```py
1151:                                     resource._rejected()
1152: 
1153:                     elif packet.context == RNS.Packet.KEEPALIVE:
1154:                         if not self.initiator and packet.data == bytes([0xFF]):
1155:                             keepalive_packet = RNS.Packet(self, bytes([0xFE]), context=RNS.Packet.KEEPALIVE)
1156:                             keepalive_packet.send()
1157:                             self.had_outbound(is_keepalive = True)
1158: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   1141:                                 if resource_hash == resource.hash:
   1142:                                     resource.cancel()
   1143: 
   1144:                     elif packet.context == RNS.Packet.RESOURCE_RCL:
   1145:                         plaintext = self.decrypt(packet.data)
   1146:                         if plaintext != None:
   1147:                             self.__update_phy_stats(packet)
   1148:                             resource_hash = plaintext[:RNS.Identity.HASHLENGTH//8]
   1149:                             for resource in self.outgoing_resources:
   1150:                                 if resource_hash == resource.hash:
>> 1151:                                     resource._rejected()
>> 1152: 
>> 1153:                     elif packet.context == RNS.Packet.KEEPALIVE:
>> 1154:                         if not self.initiator and packet.data == bytes([0xFF]):
>> 1155:                             keepalive_packet = RNS.Packet(self, bytes([0xFE]), context=RNS.Packet.KEEPALIVE)
>> 1156:                             keepalive_packet.send()
>> 1157:                             self.had_outbound(is_keepalive = True)
>> 1158: 
   1159: 
   1160:                     # TODO: find the most efficient way to allow multiple
   1161:                     # transfers at the same time, sending resource hash on
   1162:                     # each packet is a huge overhead. Probably some kind
   1163:                     # of hash -> sequence map
   1164:                     elif packet.context == RNS.Packet.RESOURCE:
   1165:                         for resource in self.incoming_resources:
   1166:                             resource.receive_part(packet)
   1167:                             self.__update_phy_stats(packet)
   1168: 
```

    </details>
- **Value:** {'number': 254, 'unit': 'byte'}

## RNS.LNK.LAYOUT.LINKCLOSE_PAYLOAD
- **Kind:** layout
- **Normative:** MUST
- **Statement:** LINKCLOSE payload: link_id (16 bytes), plaintext (no link encryption).
- **References:**
  - RNS/Link.py (`LINKCLOSE`) lines 693–698 (implementation)
    <details>
      <summary>Show code: RNS/Link.py:693–698 — LINKCLOSE — implementation</summary>

```py
693: 
694:     def __teardown_packet(self):
695:         teardown_packet = RNS.Packet(self, self.link_id, context=RNS.Packet.LINKCLOSE)
696:         teardown_packet.send()
697:         self.had_outbound()
698: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   683:     def get_remote_identity(self):
   684:         """
   685:         :returns: The identity of the remote peer, if it is known. Calling this method will not query the remote initiator to reveal its identity. Returns ``None`` if the link initiator has not already independently called the ``identify(identity)`` method.
   686:         """
   687:         return self.__remote_identity
   688: 
   689:     def had_outbound(self, is_keepalive=False):
   690:         self.last_outbound = time.time()
   691:         if not is_keepalive: self.last_data = self.last_outbound
   692:         else:                self.last_keepalive = self.last_outbound
>> 693: 
>> 694:     def __teardown_packet(self):
>> 695:         teardown_packet = RNS.Packet(self, self.link_id, context=RNS.Packet.LINKCLOSE)
>> 696:         teardown_packet.send()
>> 697:         self.had_outbound()
>> 698: 
   699:     def teardown(self):
   700:         """
   701:         Closes the link and purges encryption keys. New keys will
   702:         be used if a new link to the same destination is established.
   703:         """
   704:         if self.status != Link.PENDING and self.status != Link.CLOSED: self.__teardown_packet()
   705:         self.status = Link.CLOSED
   706:         if self.initiator: self.teardown_reason = Link.INITIATOR_CLOSED
   707:         else: self.teardown_reason = Link.DESTINATION_CLOSED
   708:         self.link_closed()
```

    </details>
- **Layout fields:**
  - link_id: offset 0, length 16

## RNS.LNK.LAYOUT.LINKIDENTIFY_PAYLOAD
- **Kind:** layout
- **Normative:** MUST
- **Statement:** LINKIDENTIFY payload (plaintext before link encrypt): PublicKey (64 bytes) + Signature (64 bytes). Signed data = link_id + identity.get_public_key().
- **References:**
  - RNS/Link.py (`LINKIDENTIFY`) lines 469–476 (implementation)
    <details>
      <summary>Show code: RNS/Link.py:469–476 — LINKIDENTIFY — implementation</summary>

```py
469:             signed_data = self.link_id + identity.get_public_key()
470:             signature = identity.sign(signed_data)
471:             proof_data = identity.get_public_key() + signature
472: 
473:             proof = RNS.Packet(self, proof_data, RNS.Packet.DATA, context = RNS.Packet.LINKIDENTIFY)
474:             proof.send()
475:             self.had_outbound()
476: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   459:     def identify(self, identity):
   460:         """
   461:         Identifies the initiator of the link to the remote peer. This can only happen
   462:         once the link has been established, and is carried out over the encrypted link.
   463:         The identity is only revealed to the remote peer, and initiator anonymity is
   464:         thus preserved. This method can be used for authentication.
   465: 
   466:         :param identity: An RNS.Identity instance to identify as.
   467:         """
   468:         if self.initiator and self.status == Link.ACTIVE:
>> 469:             signed_data = self.link_id + identity.get_public_key()
>> 470:             signature = identity.sign(signed_data)
>> 471:             proof_data = identity.get_public_key() + signature
>> 472: 
>> 473:             proof = RNS.Packet(self, proof_data, RNS.Packet.DATA, context = RNS.Packet.LINKIDENTIFY)
>> 474:             proof.send()
>> 475:             self.had_outbound()
>> 476: 
   477: 
   478:     def request(self, path, data = None, response_callback = None, failed_callback = None, progress_callback = None, timeout = None):
   479:         """
   480:         Sends a request to the remote peer.
   481: 
   482:         :param path: The request path.
   483:         :param response_callback: An optional function or method with the signature *response_callback(request_receipt)* to be called when a response is received. See the :ref:`Request Example<example-request>` for more info.
   484:         :param failed_callback: An optional function or method with the signature *failed_callback(request_receipt)* to be called when a request fails. See the :ref:`Request Example<example-request>` for more info.
   485:         :param progress_callback: An optional function or method with the signature *progress_callback(request_receipt)* to be called when progress is made receiving the response. Progress can be accessed as a float between 0.0 and 1.0 by the *request_receipt.progress* property.
   486:         :param timeout: An optional timeout in seconds for the request. If *None* is supplied it will be calculated based on link RTT.
```

    </details>
- **Layout fields:**
  - public_key: offset 0, length 64
  - signature: offset 64, length 64

## RNS.CHN.LAYOUT.CHANNEL_ENVELOPE
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Channel data (context CHANNEL): envelope is MSGTYPE (2 bytes, >H) + Sequence (2 bytes) + Length (2 bytes) + Message Data (variable). Total 6 bytes overhead. MSGTYPE >= 0xf000 reserved for system.
- **References:**
  - RNS/Channel.py (`pack`) lines 179–197 (definition)
    <details>
      <summary>Show code: RNS/Channel.py:179–197 — pack — definition</summary>

```py
179:     def unpack(self, message_factories: dict[int, Type]) -> MessageBase:
180:         msgtype, self.sequence, length = struct.unpack(">HHH", self.raw[:6])
181:         raw = self.raw[6:]
182:         ctor = message_factories.get(msgtype, None)
183:         if ctor is None:
184:             raise ChannelException(CEType.ME_NOT_REGISTERED, f"Unable to find constructor for Channel MSGTYPE {hex(msgtype)}")
185:         message = ctor()
186:         message.unpack(raw)
187:         self.unpacked = True
188:         self.message = message
189: 
190:         return message
191: 
192:     def pack(self) -> bytes:
193:         if self.message.__class__.MSGTYPE is None:
194:             raise ChannelException(CEType.ME_NO_MSG_TYPE, f"{self.message.__class__} lacks MSGTYPE")
195:         data = self.message.pack()
196:         self.raw = struct.pack(">HHH", self.message.MSGTYPE, self.sequence, len(data)) + data
197:         self.packed = True
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   169: 
   170: 
   171: MessageCallbackType = NewType("MessageCallbackType", Callable[[MessageBase], bool])
   172: 
   173: 
   174: class Envelope:
   175:     """
   176:     Internal wrapper used to transport messages over a channel and
   177:     track its state within the channel framework.
   178:     """
>> 179:     def unpack(self, message_factories: dict[int, Type]) -> MessageBase:
>> 180:         msgtype, self.sequence, length = struct.unpack(">HHH", self.raw[:6])
>> 181:         raw = self.raw[6:]
>> 182:         ctor = message_factories.get(msgtype, None)
>> 183:         if ctor is None:
>> 184:             raise ChannelException(CEType.ME_NOT_REGISTERED, f"Unable to find constructor for Channel MSGTYPE {hex(msgtype)}")
>> 185:         message = ctor()
>> 186:         message.unpack(raw)
>> 187:         self.unpacked = True
>> 188:         self.message = message
>> 189: 
>> 190:         return message
>> 191: 
>> 192:     def pack(self) -> bytes:
>> 193:         if self.message.__class__.MSGTYPE is None:
>> 194:             raise ChannelException(CEType.ME_NO_MSG_TYPE, f"{self.message.__class__} lacks MSGTYPE")
>> 195:         data = self.message.pack()
>> 196:         self.raw = struct.pack(">HHH", self.message.MSGTYPE, self.sequence, len(data)) + data
>> 197:         self.packed = True
   198:         return self.raw
   199: 
   200:     def __init__(self, outlet: ChannelOutletBase, message: MessageBase = None, raw: bytes = None, sequence: int = None):
   201:         self.ts = time.time()
   202:         self.id = id(self)
   203:         self.message = message
   204:         self.raw = raw
   205:         self.packet: TPacket = None
   206:         self.sequence = sequence
   207:         self.outlet = outlet
```

    </details>
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
  - RNS/Transport.py (`path_request_handler`) lines 2646–2672 (implementation)
    <details>
      <summary>Show code: RNS/Transport.py:2646–2672 — path_request_handler — implementation</summary>

```py
2646:     def path_request_handler(data, packet):
2647:         try:
2648:             # If there is at least bytes enough for a destination
2649:             # hash in the packet, we assume those bytes are the
2650:             # destination being requested.
2651:             if len(data) >= RNS.Identity.TRUNCATED_HASHLENGTH//8:
2652:                 destination_hash = data[:RNS.Identity.TRUNCATED_HASHLENGTH//8]
2653:                 # If there is also enough bytes for a transport
2654:                 # instance ID and at least one tag byte, we
2655:                 # assume the next bytes to be the trasport ID
2656:                 # of the requesting transport instance.
2657:                 if len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8)*2:
2658:                     requesting_transport_instance = data[RNS.Identity.TRUNCATED_HASHLENGTH//8:(RNS.Identity.TRUNCATED_HASHLENGTH//8)*2]
2659:                 else:
2660:                     requesting_transport_instance = None
2661: 
2662:                 tag_bytes = None
2663:                 if len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8)*2:
2664:                     tag_bytes = data[RNS.Identity.TRUNCATED_HASHLENGTH//8*2:]
2665: 
2666:                 elif len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8):
2667:                     tag_bytes = data[RNS.Identity.TRUNCATED_HASHLENGTH//8:]
2668: 
2669:                 if tag_bytes != None:
2670:                     if len(tag_bytes) > RNS.Identity.TRUNCATED_HASHLENGTH//8:
2671:                         tag_bytes = tag_bytes[:RNS.Identity.TRUNCATED_HASHLENGTH//8]
2672: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   2636: 
   2637:                     return response
   2638: 
   2639:             except Exception as e:
   2640:                 RNS.log("An error occurred while processing remote status request from "+str(remote_identity), RNS.LOG_ERROR)
   2641:                 RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)
   2642: 
   2643:             return None
   2644: 
   2645:     @staticmethod
>> 2646:     def path_request_handler(data, packet):
>> 2647:         try:
>> 2648:             # If there is at least bytes enough for a destination
>> 2649:             # hash in the packet, we assume those bytes are the
>> 2650:             # destination being requested.
>> 2651:             if len(data) >= RNS.Identity.TRUNCATED_HASHLENGTH//8:
>> 2652:                 destination_hash = data[:RNS.Identity.TRUNCATED_HASHLENGTH//8]
>> 2653:                 # If there is also enough bytes for a transport
>> 2654:                 # instance ID and at least one tag byte, we
>> 2655:                 # assume the next bytes to be the trasport ID
>> 2656:                 # of the requesting transport instance.
>> 2657:                 if len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8)*2:
>> 2658:                     requesting_transport_instance = data[RNS.Identity.TRUNCATED_HASHLENGTH//8:(RNS.Identity.TRUNCATED_HASHLENGTH//8)*2]
>> 2659:                 else:
>> 2660:                     requesting_transport_instance = None
>> 2661: 
>> 2662:                 tag_bytes = None
>> 2663:                 if len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8)*2:
>> 2664:                     tag_bytes = data[RNS.Identity.TRUNCATED_HASHLENGTH//8*2:]
>> 2665: 
>> 2666:                 elif len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8):
>> 2667:                     tag_bytes = data[RNS.Identity.TRUNCATED_HASHLENGTH//8:]
>> 2668: 
>> 2669:                 if tag_bytes != None:
>> 2670:                     if len(tag_bytes) > RNS.Identity.TRUNCATED_HASHLENGTH//8:
>> 2671:                         tag_bytes = tag_bytes[:RNS.Identity.TRUNCATED_HASHLENGTH//8]
>> 2672: 
   2673:                     unique_tag = destination_hash+tag_bytes
   2674: 
   2675:                     if not unique_tag in Transport.discovery_pr_tags:
   2676:                         Transport.discovery_pr_tags.append(unique_tag)
   2677: 
   2678:                         Transport.path_request(
   2679:                             destination_hash,
   2680:                             Transport.from_local_client(packet),
   2681:                             packet.receiving_interface,
   2682:                             requestor_transport_id = requesting_transport_instance,
```

    </details>
- **Layout fields:**
  - destination_hash: offset 0, length 16
  - request_tag: offset 16, length 16

## RNS.TRN.LAYOUT.PATH_REQUEST_TRANSPORT
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Path request (transport to transport): Destination Hash (16) + Requesting Transport Instance ID (16) + Request Tag (16).
- **References:**
  - RNS/Transport.py (`path_request_handler`) lines 2646–2672 (implementation)
    <details>
      <summary>Show code: RNS/Transport.py:2646–2672 — path_request_handler — implementation</summary>

```py
2646:     def path_request_handler(data, packet):
2647:         try:
2648:             # If there is at least bytes enough for a destination
2649:             # hash in the packet, we assume those bytes are the
2650:             # destination being requested.
2651:             if len(data) >= RNS.Identity.TRUNCATED_HASHLENGTH//8:
2652:                 destination_hash = data[:RNS.Identity.TRUNCATED_HASHLENGTH//8]
2653:                 # If there is also enough bytes for a transport
2654:                 # instance ID and at least one tag byte, we
2655:                 # assume the next bytes to be the trasport ID
2656:                 # of the requesting transport instance.
2657:                 if len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8)*2:
2658:                     requesting_transport_instance = data[RNS.Identity.TRUNCATED_HASHLENGTH//8:(RNS.Identity.TRUNCATED_HASHLENGTH//8)*2]
2659:                 else:
2660:                     requesting_transport_instance = None
2661: 
2662:                 tag_bytes = None
2663:                 if len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8)*2:
2664:                     tag_bytes = data[RNS.Identity.TRUNCATED_HASHLENGTH//8*2:]
2665: 
2666:                 elif len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8):
2667:                     tag_bytes = data[RNS.Identity.TRUNCATED_HASHLENGTH//8:]
2668: 
2669:                 if tag_bytes != None:
2670:                     if len(tag_bytes) > RNS.Identity.TRUNCATED_HASHLENGTH//8:
2671:                         tag_bytes = tag_bytes[:RNS.Identity.TRUNCATED_HASHLENGTH//8]
2672: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   2636: 
   2637:                     return response
   2638: 
   2639:             except Exception as e:
   2640:                 RNS.log("An error occurred while processing remote status request from "+str(remote_identity), RNS.LOG_ERROR)
   2641:                 RNS.log("The contained exception was: "+str(e), RNS.LOG_ERROR)
   2642: 
   2643:             return None
   2644: 
   2645:     @staticmethod
>> 2646:     def path_request_handler(data, packet):
>> 2647:         try:
>> 2648:             # If there is at least bytes enough for a destination
>> 2649:             # hash in the packet, we assume those bytes are the
>> 2650:             # destination being requested.
>> 2651:             if len(data) >= RNS.Identity.TRUNCATED_HASHLENGTH//8:
>> 2652:                 destination_hash = data[:RNS.Identity.TRUNCATED_HASHLENGTH//8]
>> 2653:                 # If there is also enough bytes for a transport
>> 2654:                 # instance ID and at least one tag byte, we
>> 2655:                 # assume the next bytes to be the trasport ID
>> 2656:                 # of the requesting transport instance.
>> 2657:                 if len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8)*2:
>> 2658:                     requesting_transport_instance = data[RNS.Identity.TRUNCATED_HASHLENGTH//8:(RNS.Identity.TRUNCATED_HASHLENGTH//8)*2]
>> 2659:                 else:
>> 2660:                     requesting_transport_instance = None
>> 2661: 
>> 2662:                 tag_bytes = None
>> 2663:                 if len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8)*2:
>> 2664:                     tag_bytes = data[RNS.Identity.TRUNCATED_HASHLENGTH//8*2:]
>> 2665: 
>> 2666:                 elif len(data) > (RNS.Identity.TRUNCATED_HASHLENGTH//8):
>> 2667:                     tag_bytes = data[RNS.Identity.TRUNCATED_HASHLENGTH//8:]
>> 2668: 
>> 2669:                 if tag_bytes != None:
>> 2670:                     if len(tag_bytes) > RNS.Identity.TRUNCATED_HASHLENGTH//8:
>> 2671:                         tag_bytes = tag_bytes[:RNS.Identity.TRUNCATED_HASHLENGTH//8]
>> 2672: 
   2673:                     unique_tag = destination_hash+tag_bytes
   2674: 
   2675:                     if not unique_tag in Transport.discovery_pr_tags:
   2676:                         Transport.discovery_pr_tags.append(unique_tag)
   2677: 
   2678:                         Transport.path_request(
   2679:                             destination_hash,
   2680:                             Transport.from_local_client(packet),
   2681:                             packet.receiving_interface,
   2682:                             requestor_transport_id = requesting_transport_instance,
```

    </details>
- **Layout fields:**
  - destination_hash: offset 0, length 16
  - requesting_transport_id: offset 16, length 16
  - request_tag: offset 32, length 16

## RNS.TRN.LAYOUT.TUNNEL_SYNTHESIS
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Tunnel synthesis payload: Public Key (64) + Interface Hash (32) + Random Hash (16) + Signature (64). Signed data = public_key + interface_hash + random_hash.
- **References:**
  - RNS/Transport.py (`synthesize_tunnel`) lines 2120–2132 (implementation)
    <details>
      <summary>Show code: RNS/Transport.py:2120–2132 — synthesize_tunnel — implementation</summary>

```py
2120:     def synthesize_tunnel(interface):
2121:         interface_hash = interface.get_hash()
2122:         public_key     = RNS.Transport.identity.get_public_key()
2123:         random_hash    = RNS.Identity.get_random_hash()
2124:         
2125:         tunnel_id_data = public_key+interface_hash
2126:         tunnel_id      = RNS.Identity.full_hash(tunnel_id_data)
2127: 
2128:         signed_data    = tunnel_id_data+random_hash
2129:         signature      = Transport.identity.sign(signed_data)
2130:         
2131:         data           = signed_data+signature
2132: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   2110:                             # to check every single outstanding receipt
   2111:                             receipt_validated = receipt.validate_proof_packet(packet)
   2112: 
   2113:                         if receipt_validated:
   2114:                             if receipt in Transport.receipts:
   2115:                                 Transport.receipts.remove(receipt)
   2116: 
   2117:         Transport.jobs_locked = False
   2118: 
   2119:     @staticmethod
>> 2120:     def synthesize_tunnel(interface):
>> 2121:         interface_hash = interface.get_hash()
>> 2122:         public_key     = RNS.Transport.identity.get_public_key()
>> 2123:         random_hash    = RNS.Identity.get_random_hash()
>> 2124:         
>> 2125:         tunnel_id_data = public_key+interface_hash
>> 2126:         tunnel_id      = RNS.Identity.full_hash(tunnel_id_data)
>> 2127: 
>> 2128:         signed_data    = tunnel_id_data+random_hash
>> 2129:         signature      = Transport.identity.sign(signed_data)
>> 2130:         
>> 2131:         data           = signed_data+signature
>> 2132: 
   2133:         tnl_snth_dst   = RNS.Destination(None, RNS.Destination.OUT, RNS.Destination.PLAIN, Transport.APP_NAME, "tunnel", "synthesize")
   2134: 
   2135:         packet = RNS.Packet(tnl_snth_dst, data, packet_type = RNS.Packet.DATA, transport_type = RNS.Transport.BROADCAST, header_type = RNS.Packet.HEADER_1, attached_interface = interface)
   2136:         packet.send()
   2137: 
   2138:         interface.wants_tunnel = False
   2139: 
   2140:     @staticmethod
   2141:     def tunnel_synthesize_handler(data, packet):
   2142:         try:
```

    </details>
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
  - RNS/Resource.py (`ResourceAdvertisement`) lines 1312–1338 (definition)
    <details>
      <summary>Show code: RNS/Resource.py:1312–1338 — ResourceAdvertisement — definition</summary>

```py
1312:         return self.link
1313: 
1314:     def pack(self, segment=0):
1315:         hashmap_start = segment*ResourceAdvertisement.HASHMAP_MAX_LEN
1316:         hashmap_end   = min((segment+1)*(ResourceAdvertisement.HASHMAP_MAX_LEN), self.n)
1317: 
1318:         hashmap = b""
1319:         for i in range(hashmap_start,hashmap_end):
1320:             hashmap += self.m[i*Resource.MAPHASH_LEN:(i+1)*Resource.MAPHASH_LEN]
1321: 
1322:         dictionary = {
1323:             "t": self.t,    # Transfer size
1324:             "d": self.d,    # Data size
1325:             "n": self.n,    # Number of parts
1326:             "h": self.h,    # Resource hash
1327:             "r": self.r,    # Resource random hash
1328:             "o": self.o,    # Original hash
1329:             "i": self.i,    # Segment index
1330:             "l": self.l,    # Total segments
1331:             "q": self.q,    # Request ID
1332:             "f": self.f,    # Resource flags
1333:             "m": hashmap
1334:         }
1335: 
1336:         return umsgpack.packb(dictionary)
1337: 
1338: 
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   1302:     def get_hash(self):
   1303:         return self.h
   1304: 
   1305:     def is_compressed(self):
   1306:         return self.c
   1307: 
   1308:     def has_metadata(self):
   1309:         return self.x
   1310: 
   1311:     def get_link(self):
>> 1312:         return self.link
>> 1313: 
>> 1314:     def pack(self, segment=0):
>> 1315:         hashmap_start = segment*ResourceAdvertisement.HASHMAP_MAX_LEN
>> 1316:         hashmap_end   = min((segment+1)*(ResourceAdvertisement.HASHMAP_MAX_LEN), self.n)
>> 1317: 
>> 1318:         hashmap = b""
>> 1319:         for i in range(hashmap_start,hashmap_end):
>> 1320:             hashmap += self.m[i*Resource.MAPHASH_LEN:(i+1)*Resource.MAPHASH_LEN]
>> 1321: 
>> 1322:         dictionary = {
>> 1323:             "t": self.t,    # Transfer size
>> 1324:             "d": self.d,    # Data size
>> 1325:             "n": self.n,    # Number of parts
>> 1326:             "h": self.h,    # Resource hash
>> 1327:             "r": self.r,    # Resource random hash
>> 1328:             "o": self.o,    # Original hash
>> 1329:             "i": self.i,    # Segment index
>> 1330:             "l": self.l,    # Total segments
>> 1331:             "q": self.q,    # Request ID
>> 1332:             "f": self.f,    # Resource flags
>> 1333:             "m": hashmap
>> 1334:         }
>> 1335: 
>> 1336:         return umsgpack.packb(dictionary)
>> 1337: 
>> 1338: 
   1339:     @staticmethod
   1340:     def unpack(data):
   1341:         dictionary = umsgpack.unpackb(data)
   1342:         
   1343:         adv   = ResourceAdvertisement()
   1344:         adv.t = dictionary["t"]
   1345:         adv.d = dictionary["d"]
   1346:         adv.n = dictionary["n"]
   1347:         adv.h = dictionary["h"]
   1348:         adv.r = dictionary["r"]
```

    </details>
- **Layout fields:**
  - payload: offset 0, length 0

## RNS.RES.LAYOUT.RESOURCE_REQ
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Resource part request (RESOURCE_REQ): Hashmap Exhausted (1 byte) + optional Last Map Hash (4 bytes) + Resource Hash (32 bytes) + Requested Part Hashes (4 bytes each).
- **References:**
  - RNS/Resource.py (`request_next`) lines 918–952 (implementation)
    <details>
      <summary>Show code: RNS/Resource.py:918–952 — request_next — implementation</summary>

```py
918: 
919:     # Called on incoming resource to send a request for more data
920:     def request_next(self):
921:         while self.receiving_part:
922:             sleep(0.001)
923: 
924:         if not self.status == Resource.FAILED:
925:             if not self.waiting_for_hmu:
926:                 self.outstanding_parts = 0
927:                 hashmap_exhausted = Resource.HASHMAP_IS_NOT_EXHAUSTED
928:                 requested_hashes = b""
929: 
930:                 i = 0; pn = self.consecutive_completed_height+1
931:                 search_start = pn
932:                 search_size = self.window
933:                 
934:                 for part in self.parts[search_start:search_start+search_size]:
935:                     if part == None:
936:                         part_hash = self.hashmap[pn]
937:                         if part_hash != None:
938:                             requested_hashes += part_hash
939:                             self.outstanding_parts += 1
940:                             i += 1
941:                         else:
942:                             hashmap_exhausted = Resource.HASHMAP_IS_EXHAUSTED
943: 
944:                     pn += 1
945:                     if i >= self.window or hashmap_exhausted == Resource.HASHMAP_IS_EXHAUSTED:
946:                         break
947: 
948:                 hmu_part = bytes([hashmap_exhausted])
949:                 if hashmap_exhausted == Resource.HASHMAP_IS_EXHAUSTED:
950:                     last_map_hash = self.hashmap[self.hashmap_height-1]
951:                     hmu_part += last_map_hash
952:                     self.waiting_for_hmu = True
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   908: 
   909:                             if self.fast_rate_rounds == 0 and self.req_data_rtt_rate < Resource.RATE_VERY_SLOW and self.very_slow_rate_rounds < Resource.VERY_SLOW_RATE_THRESHOLD:
   910:                                 self.very_slow_rate_rounds += 1
   911: 
   912:                                 if self.very_slow_rate_rounds == Resource.VERY_SLOW_RATE_THRESHOLD:
   913:                                     self.window_max = Resource.WINDOW_MAX_VERY_SLOW
   914: 
   915:                     self.request_next()
   916:             else:
   917:                 self.receiving_part = False
>> 918: 
>> 919:     # Called on incoming resource to send a request for more data
>> 920:     def request_next(self):
>> 921:         while self.receiving_part:
>> 922:             sleep(0.001)
>> 923: 
>> 924:         if not self.status == Resource.FAILED:
>> 925:             if not self.waiting_for_hmu:
>> 926:                 self.outstanding_parts = 0
>> 927:                 hashmap_exhausted = Resource.HASHMAP_IS_NOT_EXHAUSTED
>> 928:                 requested_hashes = b""
>> 929: 
>> 930:                 i = 0; pn = self.consecutive_completed_height+1
>> 931:                 search_start = pn
>> 932:                 search_size = self.window
>> 933:                 
>> 934:                 for part in self.parts[search_start:search_start+search_size]:
>> 935:                     if part == None:
>> 936:                         part_hash = self.hashmap[pn]
>> 937:                         if part_hash != None:
>> 938:                             requested_hashes += part_hash
>> 939:                             self.outstanding_parts += 1
>> 940:                             i += 1
>> 941:                         else:
>> 942:                             hashmap_exhausted = Resource.HASHMAP_IS_EXHAUSTED
>> 943: 
>> 944:                     pn += 1
>> 945:                     if i >= self.window or hashmap_exhausted == Resource.HASHMAP_IS_EXHAUSTED:
>> 946:                         break
>> 947: 
>> 948:                 hmu_part = bytes([hashmap_exhausted])
>> 949:                 if hashmap_exhausted == Resource.HASHMAP_IS_EXHAUSTED:
>> 950:                     last_map_hash = self.hashmap[self.hashmap_height-1]
>> 951:                     hmu_part += last_map_hash
>> 952:                     self.waiting_for_hmu = True
   953: 
   954:                 request_data = hmu_part + self.hash + requested_hashes
   955:                 request_packet = RNS.Packet(self.link, request_data, context = RNS.Packet.RESOURCE_REQ)
   956: 
   957:                 try:
   958:                     request_packet.send()
   959:                     self.last_activity = time.time()
   960:                     self.req_sent = self.last_activity
   961:                     self.req_sent_bytes = len(request_packet.raw)
   962:                     self.req_resp = None
```

    </details>
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
  - RNS/Resource.py (`request`) lines 970–1047 (implementation)
    <details>
      <summary>Show code: RNS/Resource.py:970–1047 — request — implementation</summary>

```py
970:     def request(self, request_data):
971:         if not self.status == Resource.FAILED:
972:             rtt = time.time() - self.adv_sent
973:             if self.rtt == None:
974:                 self.rtt = rtt
975: 
976:             if self.status != Resource.TRANSFERRING:
977:                 self.status = Resource.TRANSFERRING
978:                 self.watchdog_job()
979: 
980:             self.retries_left = self.max_retries
981: 
982:             wants_more_hashmap = True if request_data[0] == Resource.HASHMAP_IS_EXHAUSTED else False
983:             pad = 1+Resource.MAPHASH_LEN if wants_more_hashmap else 1
984: 
985:             requested_hashes = request_data[pad+RNS.Identity.HASHLENGTH//8:]
986: 
987:             # Define the search scope
988:             search_start = self.receiver_min_consecutive_height
989:             search_end   = self.receiver_min_consecutive_height+ResourceAdvertisement.COLLISION_GUARD_SIZE
990: 
991:             map_hashes = []
992:             for i in range(0,len(requested_hashes)//Resource.MAPHASH_LEN):
993:                 map_hash = requested_hashes[i*Resource.MAPHASH_LEN:(i+1)*Resource.MAPHASH_LEN]
994:                 map_hashes.append(map_hash)
995: 
996:             search_scope = self.parts[search_start:search_end]
997:             requested_parts = list(filter(lambda part: part.map_hash in map_hashes, search_scope))
998: 
999:             for part in requested_parts:
1000:                 try:
1001:                     if not part.sent:
1002:                         part.send()
1003:                         self.sent_parts += 1
1004:                     else:
1005:                         part.resend()
1006: 
1007:                     self.last_activity = time.time()
1008:                     self.last_part_sent = self.last_activity
1009: 
1010:                 except Exception as e:
1011:                     RNS.log("Resource could not send parts, cancelling transfer!", RNS.LOG_DEBUG)
1012:                     RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)
1013:                     self.cancel()
1014:             
1015:             if wants_more_hashmap:
1016:                 last_map_hash = request_data[1:Resource.MAPHASH_LEN+1]
1017:                 
1018:                 part_index   = self.receiver_min_consecutive_height
1019:                 search_start = part_index
1020:                 search_end   = self.receiver_min_consecutive_height+ResourceAdvertisement.COLLISION_GUARD_SIZE
1021:                 for part in self.parts[search_start:search_end]:
1022:                     part_index += 1
1023:                     if part.map_hash == last_map_hash:
1024:                         break
1025: 
1026:                 self.receiver_min_consecutive_height = max(part_index-1-Resource.WINDOW_MAX, 0)
1027: 
1028:                 if part_index % ResourceAdvertisement.HASHMAP_MAX_LEN != 0:
1029:                     RNS.log("Resource sequencing error, cancelling transfer!", RNS.LOG_ERROR)
1030:                     self.cancel()
1031:                     return
1032:                 else:
1033:                     segment = part_index // ResourceAdvertisement.HASHMAP_MAX_LEN
1034: 
1035:                 
1036:                 hashmap_start = segment*ResourceAdvertisement.HASHMAP_MAX_LEN
1037:                 hashmap_end   = min((segment+1)*ResourceAdvertisement.HASHMAP_MAX_LEN, len(self.parts))
1038: 
1039:                 hashmap = b""
1040:                 for i in range(hashmap_start,hashmap_end):
1041:                     hashmap += self.hashmap[i*Resource.MAPHASH_LEN:(i+1)*Resource.MAPHASH_LEN]
1042: 
1043:                 hmu = self.hash+umsgpack.packb([segment, hashmap])
1044:                 hmu_packet = RNS.Packet(self.link, hmu, context = RNS.Packet.RESOURCE_HMU)
1045: 
1046:                 try:
1047:                     hmu_packet.send()
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   960:                     self.req_sent = self.last_activity
   961:                     self.req_sent_bytes = len(request_packet.raw)
   962:                     self.req_resp = None
   963: 
   964:                 except Exception as e:
   965:                     RNS.log("Could not send resource request packet, cancelling resource", RNS.LOG_DEBUG)
   966:                     RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)
   967:                     self.cancel()
   968: 
   969:     # Called on outgoing resource to make it send more data
>> 970:     def request(self, request_data):
>> 971:         if not self.status == Resource.FAILED:
>> 972:             rtt = time.time() - self.adv_sent
>> 973:             if self.rtt == None:
>> 974:                 self.rtt = rtt
>> 975: 
>> 976:             if self.status != Resource.TRANSFERRING:
>> 977:                 self.status = Resource.TRANSFERRING
>> 978:                 self.watchdog_job()
>> 979: 
>> 980:             self.retries_left = self.max_retries
>> 981: 
>> 982:             wants_more_hashmap = True if request_data[0] == Resource.HASHMAP_IS_EXHAUSTED else False
>> 983:             pad = 1+Resource.MAPHASH_LEN if wants_more_hashmap else 1
>> 984: 
>> 985:             requested_hashes = request_data[pad+RNS.Identity.HASHLENGTH//8:]
>> 986: 
>> 987:             # Define the search scope
>> 988:             search_start = self.receiver_min_consecutive_height
>> 989:             search_end   = self.receiver_min_consecutive_height+ResourceAdvertisement.COLLISION_GUARD_SIZE
>> 990: 
>> 991:             map_hashes = []
>> 992:             for i in range(0,len(requested_hashes)//Resource.MAPHASH_LEN):
>> 993:                 map_hash = requested_hashes[i*Resource.MAPHASH_LEN:(i+1)*Resource.MAPHASH_LEN]
>> 994:                 map_hashes.append(map_hash)
>> 995: 
>> 996:             search_scope = self.parts[search_start:search_end]
>> 997:             requested_parts = list(filter(lambda part: part.map_hash in map_hashes, search_scope))
>> 998: 
>> 999:             for part in requested_parts:
>> 1000:                 try:
>> 1001:                     if not part.sent:
>> 1002:                         part.send()
>> 1003:                         self.sent_parts += 1
>> 1004:                     else:
>> 1005:                         part.resend()
>> 1006: 
>> 1007:                     self.last_activity = time.time()
>> 1008:                     self.last_part_sent = self.last_activity
>> 1009: 
>> 1010:                 except Exception as e:
>> 1011:                     RNS.log("Resource could not send parts, cancelling transfer!", RNS.LOG_DEBUG)
>> 1012:                     RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)
>> 1013:                     self.cancel()
>> 1014:             
>> 1015:             if wants_more_hashmap:
>> 1016:                 last_map_hash = request_data[1:Resource.MAPHASH_LEN+1]
>> 1017:                 
>> 1018:                 part_index   = self.receiver_min_consecutive_height
>> 1019:                 search_start = part_index
>> 1020:                 search_end   = self.receiver_min_consecutive_height+ResourceAdvertisement.COLLISION_GUARD_SIZE
>> 1021:                 for part in self.parts[search_start:search_end]:
>> 1022:                     part_index += 1
>> 1023:                     if part.map_hash == last_map_hash:
>> 1024:                         break
>> 1025: 
>> 1026:                 self.receiver_min_consecutive_height = max(part_index-1-Resource.WINDOW_MAX, 0)
>> 1027: 
>> 1028:                 if part_index % ResourceAdvertisement.HASHMAP_MAX_LEN != 0:
>> 1029:                     RNS.log("Resource sequencing error, cancelling transfer!", RNS.LOG_ERROR)
>> 1030:                     self.cancel()
>> 1031:                     return
>> 1032:                 else:
>> 1033:                     segment = part_index // ResourceAdvertisement.HASHMAP_MAX_LEN
>> 1034: 
>> 1035:                 
>> 1036:                 hashmap_start = segment*ResourceAdvertisement.HASHMAP_MAX_LEN
>> 1037:                 hashmap_end   = min((segment+1)*ResourceAdvertisement.HASHMAP_MAX_LEN, len(self.parts))
>> 1038: 
>> 1039:                 hashmap = b""
>> 1040:                 for i in range(hashmap_start,hashmap_end):
>> 1041:                     hashmap += self.hashmap[i*Resource.MAPHASH_LEN:(i+1)*Resource.MAPHASH_LEN]
>> 1042: 
>> 1043:                 hmu = self.hash+umsgpack.packb([segment, hashmap])
>> 1044:                 hmu_packet = RNS.Packet(self.link, hmu, context = RNS.Packet.RESOURCE_HMU)
>> 1045: 
>> 1046:                 try:
>> 1047:                     hmu_packet.send()
   1048:                     self.last_activity = time.time()
   1049:                 except Exception as e:
   1050:                     RNS.log("Could not send resource HMU packet, cancelling resource", RNS.LOG_DEBUG)
   1051:                     RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)
   1052:                     self.cancel()
   1053: 
   1054:             if self.sent_parts == len(self.parts):
   1055:                 self.status = Resource.AWAITING_PROOF
   1056:                 self.retries_left = 3
   1057: 
```

    </details>
- **Layout fields:**
  - resource_hash: offset 0, length 32
  - packed_hashmap: offset 32, length 0

## RNS.RES.LAYOUT.RESOURCE_PRF
- **Kind:** layout
- **Normative:** MUST
- **Statement:** Resource proof (RESOURCE_PRF): Resource Hash (32 bytes, full SHA-256) + Proof (32 bytes, full_hash(resource_data+resource_hash)).
- **References:**
  - RNS/Resource.py (`prove`) lines 739–748 (implementation)
    <details>
      <summary>Show code: RNS/Resource.py:739–748 — prove — implementation</summary>

```py
739: 
740: 
741:     def prove(self):
742:         if not self.status == Resource.FAILED:
743:             try:
744:                 proof = RNS.Identity.full_hash(self.data+self.hash)
745:                 proof_data = self.hash+proof
746:                 proof_packet = RNS.Packet(self.link, proof_data, packet_type=RNS.Packet.PROOF, context=RNS.Packet.RESOURCE_PRF)
747:                 proof_packet.send()
748:                 RNS.Transport.cache(proof_packet, force_cache=True)
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   729:                         RNS.log("Error while executing resource assembled callback from "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)
   730: 
   731:                 try:
   732:                     if hasattr(self.data, "close") and callable(self.data.close): self.data.close()
   733:                     if os.path.isfile(self.storagepath): os.unlink(self.storagepath)
   734: 
   735:                 except Exception as e:
   736:                     RNS.log(f"Error while cleaning up resource files, the contained exception was: {e}", RNS.LOG_ERROR)
   737:             else:
   738:                 RNS.log("Resource segment "+str(self.segment_index)+" of "+str(self.total_segments)+" received, waiting for next segment to be announced", RNS.LOG_DEBUG)
>> 739: 
>> 740: 
>> 741:     def prove(self):
>> 742:         if not self.status == Resource.FAILED:
>> 743:             try:
>> 744:                 proof = RNS.Identity.full_hash(self.data+self.hash)
>> 745:                 proof_data = self.hash+proof
>> 746:                 proof_packet = RNS.Packet(self.link, proof_data, packet_type=RNS.Packet.PROOF, context=RNS.Packet.RESOURCE_PRF)
>> 747:                 proof_packet.send()
>> 748:                 RNS.Transport.cache(proof_packet, force_cache=True)
   749:             except Exception as e:
   750:                 RNS.log("Could not send proof packet, cancelling resource", RNS.LOG_DEBUG)
   751:                 RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)
   752:                 self.cancel()
   753: 
   754:     def __prepare_next_segment(self):
   755:         # Prepare the next segment for advertisement
   756:         RNS.log(f"Preparing segment {self.segment_index+1} of {self.total_segments} for resource {self}", RNS.LOG_DEBUG)
   757:         self.preparing_next_segment = True
   758:         self.next_segment = Resource(
```

    </details>
- **Layout fields:**
  - resource_hash: offset 0, length 32
  - proof: offset 32, length 32

## RNS.IFAC.ALG.IFAC_KEY_DERIVATION
- **Kind:** algorithm
- **Normative:** MUST
- **Statement:** IFAC key (interface.ifac_key) is derived with HKDF: length=64, derive_from=ifac_origin_hash (full_hash of ifac origin material), salt=IFAC_SALT (32-byte constant), context=None. ifac_identity = Identity.from_bytes(ifac_key).
- **References:**
  - RNS/Reticulum.py (`ifac_key`) lines 819–826 (implementation)
    <details>
      <summary>Show code: RNS/Reticulum.py:819–826 — ifac_key — implementation</summary>

```py
819: 
820:                         ifac_origin_hash = RNS.Identity.full_hash(ifac_origin)
821:                         interface.ifac_key = RNS.Cryptography.hkdf(
822:                             length=64,
823:                             derive_from=ifac_origin_hash,
824:                             salt=self.ifac_salt,
825:                             context=None
826:                         )
```

    </details>
    <details>
      <summary>Show ±10 lines context</summary>

```py
   809:                     interface.ifac_netkey = ifac_netkey
   810: 
   811:                     if interface.ifac_netname != None or interface.ifac_netkey != None:
   812:                         ifac_origin = b""
   813: 
   814:                         if interface.ifac_netname != None:
   815:                             ifac_origin += RNS.Identity.full_hash(interface.ifac_netname.encode("utf-8"))
   816: 
   817:                         if interface.ifac_netkey != None:
   818:                             ifac_origin += RNS.Identity.full_hash(interface.ifac_netkey.encode("utf-8"))
>> 819: 
>> 820:                         ifac_origin_hash = RNS.Identity.full_hash(ifac_origin)
>> 821:                         interface.ifac_key = RNS.Cryptography.hkdf(
>> 822:                             length=64,
>> 823:                             derive_from=ifac_origin_hash,
>> 824:                             salt=self.ifac_salt,
>> 825:                             context=None
>> 826:                         )
   827: 
   828:                         interface.ifac_identity = RNS.Identity.from_bytes(interface.ifac_key)
   829:                         interface.ifac_signature = interface.ifac_identity.sign(RNS.Identity.full_hash(interface.ifac_key))
   830: 
   831:                     RNS.Transport.interfaces.append(interface)
   832:                     interface.final_init()
   833: 
   834:             interface = None
   835:             if (("interface_enabled" in c) and c.as_bool("interface_enabled") == True) or (("enabled" in c) and c.as_bool("enabled") == True):
   836:                 interface_config = c
```

    </details>
- **Steps:**
  - Build ifac_origin from interface config (ifac_netname, ifac_netkey, etc.); ifac_origin_hash = full_hash(ifac_origin).
  - ifac_key = HKDF(length=64, derive_from=ifac_origin_hash, salt=IFAC_SALT, context=None).
  - ifac_identity = Identity.from_bytes(ifac_key).
