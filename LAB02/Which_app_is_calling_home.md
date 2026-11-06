# Who is behind the NAT?

| | |
|---|---|
| **Category** | Network forensics / passive fingerprinting |
| **Attachment** | `capture-3.pcap` (30 minutes, WAN side of the NAT) |
| **Technique used** | SYN signature (p0f-style) |
| **Tools** | Wireshark only |
| **Flag** | `netsec{c9c6deaf53b3c18bd02028fcb19d1198d99c654edc253160}` ✅ |

---

## 1. The problem

A small office reaches its intranet server (`203.0.113.10:80`) through a NAT router. On the WAN side every PC looks the same: the source IP is always `198.51.100.7`, and the NAT rewrites the source ports.

The capture contains exactly one `POST /admin/login`. The goal is to find **every other connection made by the same PC** and collect the `X-Trace: <n>-<6 hex digits>` header from each of its HTTP requests. Sorting the pieces by `n` (1 to 8) and joining them gives a 48-digit token, which is submitted as `netsec{<token>}`.

**The core difficulty:** IP address and port can't tell the PCs apart. We need a fingerprint that comes from the PC itself and that the NAT does not modify.

## 2. Why technique 2 (SYN signature)

The challenge offers three techniques and says any one of them is enough:

| # | Technique | What it needs |
|---|---|---|
| 1 | TCP timestamps (Kohno et al.) | Plot `TSval` against time and find which connections lie on the same line |
| 2 | **SYN signature (p0f)** | **Compare a few fields of each SYN for exact equality** |
| 3 | Round-trip time | Compute the median `ack_rtt` of each connection and group similar values |

### Why the SYN signature survives the NAT

A NAT rewrites only the **source IP** and the **source port**. It also decrements the TTL by 1, but it does that for every PC alike.

Everything else in the SYN is chosen by the PC itself:

- **Initial TTL:** an operating system default (64, 128, …).
- **Window size:** the stack's default receive window.
- **MSS:** derived from the PC's MTU and network configuration.
- **Window scale:** the stack's default shift count.
- **Order of the TCP options:** each OS writes its options in its own fixed order.

These values cross the NAT unchanged and differ from one PC to another. Together they form a fingerprint of the machine behind the NAT, and that is exactly how the passive fingerprinting tool p0f works.

### Why it is the best fit for Wireshark

- Every field we need already exists in Wireshark: `ip.ttl`, `tcp.window_size_value`, `tcp.options.mss_val`, `tcp.options.wscale.shift` and `tcp.option_kind`. Each one can be shown as a column and used in a display filter.
- The comparison is **exact equality**, which is exactly what a display filter does.
- Only **one packet per connection** matters: the SYN.

### Why not the other two

- **Technique 1 (TCP timestamps).** Every PC's `TSval` follows its own line, `TSval = hz · t + offset`. Wireshark can show `TSval` in a column or in an I/O Graph. But separating the PCs means estimating the slope and intercept of every connection and checking which ones line up with the anchor. That is a regression, not a filter, and it is impractical by hand.
- **Technique 3 (round-trip time).** Wireshark computes `tcp.analysis.ack_rtt` for each ACK. The challenge asks for the **median per connection**, though, and Wireshark can't compute per-stream medians. The samples would have to be exported and processed elsewhere, and we would still need a threshold to decide which medians count as "the same".

### The trap

The challenge warns that **single fields are shared by several PCs**. Another PC may have the same TTL, the same window, or even the same values with its options in a different order. The signature identifies a single PC only when **all five fields, option order included, are compared together**.

In practice:
- the four numeric fields go into a display filter;
- the option order is checked by eye in the `Kind` column.

## 3. Step by step (Wireshark)

### Step 1: Find the anchor connection

Display filter:

```
http.request.method == "POST" && http.request.uri == "/admin/login"
```

Result: **packet 682**, `POST /admin/login`, NAT source port 30523, **`tcp.stream` = 67**.
This packet already carries one piece: `X-Trace: 6-98d99c`.

**Why `tcp.stream`:** it is Wireshark's ID for a connection. It tracks SYNs, so it keeps connections apart even when the NAT reuses a port for a different PC later on.

To make it a column, select the packet with a **single** click in the main window, open *Transmission Control Protocol* in the details pane, right-click `[Stream index: 67]` and choose **Apply as Column**.

### Step 2: Read the admin PC's SYN signature

Display filter (the SYN that opened stream 67):

```
tcp.stream == 67 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Result: **packet 679** (t = 567.996 s). Each field below was added as a column with *Apply as Column*:

| Field (Wireshark name) | Where in the details pane | Admin PC value |
|---|---|---|
| `ip.ttl` | Internet Protocol → Time to Live | **63** |
| `tcp.window_size_value` | TCP → Window (*not* "Calculated window size") | **64240** |
| `tcp.options.mss_val` | TCP → Options → Maximum segment size → MSS Value | **1380** |
| `tcp.options.wscale.shift` | TCP → Options → Window scale → Shift count | **2** |
| `tcp.option_kind` | TCP → Options → any option → Kind | **MSS, SACK Permitted, Timestamp, NOP, Window Scale** |

**Why the SYN:** it is the only packet that carries MSS and window scale. Its window value is also the raw OS default, before any scaling is applied.

**Reading the values:**
- TTL 63 is an initial TTL of 64 minus the one hop through the NAT.
- The `Kind` column lists every option in the order it appears, so it captures the "option order" part of the signature.

### Step 3: Find every SYN with the same signature

Display filter:

```
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.ttl == 63 && tcp.window_size_value == 64240 && tcp.options.mss_val == 1380 && tcp.options.wscale.shift == 2
```

The filter can't easily check the option order, so that check was done by hand. Clicking the **Kind** column header sorts the rows, so any SYN with a different option order ends up apart from the others. Only rows whose Kind is exactly `Maximum Segment Size,SACK Permitted,Time Stamp Option,No-Operation,Window Scale` were kept.

Result: **23 SYNs**, all with the identical option order. Their stream indexes:

```
9, 13, 21, 27, 41, 49, 55, 64, 67, 74, 80, 83, 96, 101, 112, 115, 116, 140, 149, 160, 179, 184, 201
```

### Step 4: Collect the X-Trace pieces

Display filter:

```
http.request && tcp.stream in {9, 13, 21, 27, 41, 49, 55, 64, 67, 74, 80, 83, 96, 101, 112, 115, 116, 140, 149, 160, 179, 184, 201}
```

> ⚠️ Recent Wireshark versions require **commas** between set elements. With spaces only (`{9 13 21}`), the filter bar does not turn green.

To read every piece without clicking each packet, open *Hypertext Transfer Protocol* on any request and use *Apply as Column* on the `X-Trace: …` line. This adds a column (`http.request.line`) that shows all header lines of each request, X-Trace included.

Result: **23 HTTP requests**, one per connection.

**Consistency check:** every value of `n` always comes with the same 6 hex digits. That confirms all 23 connections belong to a single PC. If another PC had slipped into the set, some `n` would show two different values.

### Step 5: Build the flag

| n | Piece | Times seen |
|---|---|---|
| 1 | `c9c6de` | 3 |
| 2 | `af53b3` | 3 |
| 3 | `c18bd0` | 3 |
| 4 | `2028fc` | 3 |
| 5 | `b19d11` | 3 |
| 6 | `98d99c` | 3 |
| 7 | `654edc` | 3 |
| 8 | `253160` | 2 |

Joined in order (8 × 6 = 48 hex digits):

```
netsec{c9c6deaf53b3c18bd02028fcb19d1198d99c654edc253160}
```

Submitted: **"Correct flag: challenge solved!"**

## 4. Final table: all connections of the admin's PC

| Stream | Time (s) | Request | n | Piece |
|---|---|---|---|---|
| 9 | 68 | GET /api/people | 5 | b19d11 |
| 13 | 89 | GET / | 1 | c9c6de |
| 21 | 142 | GET /files/ | 2 | af53b3 |
| 27 | 236 | GET /api/mail/inbox | 1 | c9c6de |
| 41 | 354 | GET /wiki/Home | 2 | af53b3 |
| 49 | 417 | GET / | 6 | 98d99c |
| 55 | 457 | GET /api/status | 4 | 2028fc |
| 64 | 499 | GET /api/mail/inbox | 1 | c9c6de |
| **67** | **568** | **POST /admin/login** | **6** | **98d99c** |
| 74 | 621 | GET /api/tickets | 4 | 2028fc |
| 80 | 712 | GET /api/people | 5 | b19d11 |
| 83 | 729 | GET /news | 7 | 654edc |
| 96 | 867 | GET /api/tickets | 4 | 2028fc |
| 101 | 930 | GET /wiki/Home | 3 | c18bd0 |
| 112 | 1015 | GET /api/mail/inbox | 7 | 654edc |
| 115 | 1055 | GET /wiki/Home | 5 | b19d11 |
| 116 | 1080 | GET / | 6 | 98d99c |
| 140 | 1216 | GET /api/people | 7 | 654edc |
| 149 | 1268 | GET /calendar | 3 | c18bd0 |
| 160 | 1345 | GET /api/tickets | 2 | af53b3 |
| 179 | 1482 | GET /api/tickets | 8 | 253160 |
| 184 | 1531 | GET /api/people | 3 | c18bd0 |
| 201 | 1676 | GET /api/people | 8 | 253160 |

All requests share `User-Agent: IntranetSync/2.4` and `Connection: close`, so every connection carries exactly one request.

## 5. Exporting the table from Wireshark

1. Apply the filter whose result you want to save.
2. Choose **File → Export Packet Dissections → As CSV…**
3. Under *Packet Range*, select **All packets** with the **Displayed** column, so only the filtered rows are exported.

The CSV contains the columns currently shown in the packet list, custom ones included.

**Caveat:** columns describe the packet in each row. In the HTTP-request export, Window, MSS, Shift count and Kind show the values of the data packets (e.g. window 16060, no MSS), **not** the SYN signature. To keep the signature, export the Step 3 view (the SYNs) separately.

## 6. Wireshark gotchas met along the way

- **Double-clicking** a packet opens it in a separate "Packet N" window, which has no *Apply as Column* entry. Select packets with a **single click** and use the details pane of the main window instead.
- **Set filters** need commas: `tcp.stream in {9, 13, 21}`.
- **"Window" vs "Calculated window size":** for the signature, use the raw `Window` field (`tcp.window_size_value`).
- **Custom columns follow the packet in each row,** not the connection. SYN-only fields are empty on data packets.

## References

- T. Kohno, A. Broido, K. C. Claffy, *Remote Physical Device Fingerprinting*, IEEE S&P 2005: <https://catalog.caida.org/paper/2005_fingerprinting/>
- M. Zalewski, *p0f v3*: <https://lcamtuf.coredump.cx/p0f3/>
