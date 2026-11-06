## Why I chose technique 2 (SYN signature)

The NAT only rewrites the source IP and port of each PC. The other values in the SYN are set by the PC's operating system and network settings: TTL, window size, MSS, window scale and the order of the TCP options. They pass through the NAT unchanged, so together they work as a fingerprint of the PC.

I preferred it to the other two techniques because in Wireshark it only needs exact comparisons on a single packet per connection, the SYN, and a display filter does that directly. The alternatives need calculations Wireshark doesn't do on its own:
- TCP timestamps would require fitting a line for every connection;
- RTT would require a median for every connection.

Several PCs share single fields, so I always compared all five values together.

## Step by step in Wireshark

### 1. Find the admin login

```
http.request.method == "POST" && http.request.uri == "/admin/login"
```

The login is packet 682, in **stream 67**. I right-clicked `[Stream index]` in the TCP section and chose *Apply as Column*.

### 2. Read the signature of the admin's PC

```
tcp.stream == 67 && tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Technique 2 of the challenge names five values that make up the signature: initial TTL, window size, MSS, window scale and the order of the TCP options. The challenge suggests a Wireshark field for the first four. For the option order I used the Kind field, which lists the options in the order they appear in the SYN.
 
In the SYN I added these fields as columns, each with *Apply as Column*:

- **Time to Live:** 63
- **Window:** 64240
- **MSS Value:** 1380
- **Shift count (window scale):** 2
- **Kind (option order):** MSS, SACK Permitted, Timestamp, NOP, Window Scale

### 3. Find all connections with the same signature

```
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.ttl == 63 && tcp.window_size_value == 64240 && tcp.options.mss_val == 1380 && tcp.options.wscale.shift == 2
```

I sorted the results by the Kind column to check the option order. All of them had the same order as the admin's SYN, so I kept all 23 connections:

`9, 13, 21, 27, 41, 49, 55, 64, 67, 74, 80, 83, 96, 101, 112, 115, 116, 140, 149, 160, 179, 184, 201`

### 4. Read the X-Trace pieces

```
http.request && tcp.stream in {9, 13, 21, 27, 41, 49, 55, 64, 67, 74, 80, 83, 96, 101, 112, 115, 116, 140, 149, 160, 179, 184, 201}
```

I added the `X-Trace` header line as a column (*Apply as Column*) and sorted the rows by it, so I could read every piece directly in the packet list. 
The 23 requests carry only 8 different pieces:

<img width="1392" height="252" alt="Screenshot 2026-11-06 at 11 01 51" src="https://github.com/user-attachments/assets/b8581b8f-d818-4cc5-ac7a-ee4a6d0d1fa1" />

The pieces are grouped from `1-…` to `8-…`, and every `n` always has the same value: this confirms that all 23 connections come from the same PC. The row with the extra `Content-Type` header is the admin login (stream 67).


### 5. Build the flag

- n = 1 → `c9c6de`
- n = 2 → `af53b3`
- n = 3 → `c18bd0`
- n = 4 → `2028fc`
- n = 5 → `b19d11`
- n = 6 → `98d99c`
- n = 7 → `654edc`
- n = 8 → `253160`

Joined in order of `n`:

```
netsec{c9c6deaf53b3c18bd02028fcb19d1198d99c654edc253160}
```
