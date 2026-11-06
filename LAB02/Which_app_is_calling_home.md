## Step by step in Wireshark

### 1. Find the connection to the C2 domain

```
tls.handshake.extensions_server_name contains "syncbridge"
```

**Why:**
- Everything after the TLS handshake is encrypted, so the C2 domain is only visible in the Server Name Indication (SNI) of the Client Hello.
- The assignment lists `tls.handshake.extensions_server_name` as a useful field.

**What I did:**
- I applied the filter and clicked the only packet that matched.
- I opened Transport Layer Security → Handshake Protocol: Client Hello.
- I right-clicked **Server Name** and chose **Apply as Column**, so I can read the SNI of every connection directly in the packet list.
- Under Transmission Control Protocol, I right-clicked **[Stream index]** and chose **Apply as Column**. The stream index (`tcp.stream`, also suggested by the assignment) identifies the TCP connection, so I can check that each connection is counted only once.
- At the end of the Client Hello I read the JA4 line.

**Result:**
- Only one packet matched: No. 3570, from 10.20.0.16 to 203.0.113.140, stream 256.
- Server Name: `231018.syncbridge.example`
- JA4: `t13d1516h2_8daaf6152771_9829734ff3cf`

<img width="1118" height="169" alt="Screenshot 2026-11-06 at 12 20 58" src="https://github.com/user-attachments/assets/e82326f1-d516-45a6-a2ac-de2bf25babb8" />

Packet 3570 selected, with the Server Name and Stream index columns in the list and the JA4 line in the Client Hello details.

### 2. Find every connection with the same JA4

```
tls.handshake.ja4 == "t13d1516h2_8daaf6152771_9829734ff3cf"
```

**Why:**
- The PCs also browse the web with their own browsers and the malware may run on more than one PC, so the source IP is not enough. I need to recognise the application, not the PC.
- The JA4 fingerprint describes how the client builds its Client Hello, so it identifies the TLS library that wrote it.
- JA4 ignores GREASE values and sorts cipher suites and extensions, so it does not change when a client shuffles its extensions (JA3 does).
- I used the full JA4 string, not only a part of it. The first two parts (`t13d1516h2_8daaf6152771`) are the same as the Chrome example in the lab slides. Only the last part (`9829734ff3cf`) is different, so filtering on a part would also match Chrome.

**What I did:**
- I applied the filter. It only matches Client Hello packets, because the JA4 is computed from the Client Hello.
- I sorted the list by **No.** in ascending order, so the packets are in capture order.

**Result:**
- 8 packets matched:
  - No. 16, stream 1: `3a2152.abrmbdlt.test`
  - No. 333, stream 24: `2a5daf.nsuftqzdby.test`
  - No. 587, stream 42: `1c627d.vbnbuedl.test`
  - No. 1144, stream 82: `dfe655.gdnendcvtac.test`
  - No. 1414, stream 102: `857cfe.hyqnmvlldn.test`
  - No. 2382, stream 171: `a69bbf.olvqcxfj.example`
  - No. 2576, stream 185: `dedcc7.tvcnvuob.example`
  - No. 3570, stream 256: `231018.syncbridge.example`
- The 8 stream indexes are all different, so these are 8 different connections and none is counted twice.
- The C2 connection from step 1 is one of them. The other domains have random names, as expected from a DGA.

<!-- Drag the step 2 screenshot here -->
The 8 Client Hello packets that match the malware JA4, sorted by No., with their Server Name and Stream index.

### 3. Build the flag

```
tls.handshake.ja4 == "t13d1516h2_8daaf6152771_9829734ff3cf"
```

**What I did:**
- With the same filter still applied, I took the first label of each Server Name (6 hex digits), in capture order.
- I joined the 8 labels into a 48-digit token.

**Result:**
- Labels: `3a2152`, `2a5daf`, `1c627d`, `dfe655`, `857cfe`, `a69bbf`, `dedcc7`, `231018`
- Flag: `netsec{3a21522a5daf1c627ddfe655857cfea69bbfdedcc7231018}`
