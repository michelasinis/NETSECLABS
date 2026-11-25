# Key Reinstallation

## Steps

**1.** Filter `eapol`. Victim = `3c:22:fb:d1:fe:f5`.
*How I knew:* a Message 3 is replayed ~25 s after the handshake, alone, to that
client; that's the forced reinstall, and the client receiving it is the victim.

**2.** Filter `wlan.ta == 3c:22:fb:d1:fe:f5 && wlan.fc.protected == 1` and add the
PN column (`wlan.ccmp.extiv`). Collision at PN `0x08`: frames **192** and **425**.
*How I knew:* the PN climbs to `0x09` then restarts at `0x01` (the reset), so each
PN appears twice. I picked `192` (1463 B) as the known side because only a
full-size frame carries the uploaded form; `425` at the same PN is the login.

**3.** Export the ciphertexts:
```bash
tshark -r capture-3.pcap -Y "wlan.ta == 3c:22:fb:d1:fe:f5" \
  -T fields -e frame.number -e wlan.ccmp.extiv -e frame.len -e data.data > frames.txt
```

**4.** XOR the two bodies, then XOR the known form:
```python
frames = {}
for line in open("frames.txt"):
    p = line.strip().split("\t")
    if len(p) >= 4:
        frames[int(p[0])] = bytes.fromhex(p[3])

c1, c2 = frames[192], frames[425]
xor_payload = bytes(a ^ b for a, b in zip(c1[48:-8], c2[48:-8]))   # P1 XOR P2
p1 = open("expense-form.txt", "rb").read()
p2 = bytes(x ^ y for x, y in zip(xor_payload, p1))                 # = login
print(p2.decode("utf-8", errors="replace"))
```
*Why `[48:-8]`:* skip the 48-byte SNAP+IP+TCP headers to land on the TCP payload,
and drop the last 8 bytes (the CCMP MIC). *Why it works:* `C1 XOR C2` cancels the
keystream, then `XOR P1` cancels the form, leaving `P2`.

**5.** Decoded output, with the flag:
```
user=f.romano&password=netsec{c404583e6823216e80adc3885aa0c35c}
```
*Confirmation:* the request decoded cleanly, so
the alignment and the known-plaintext guess were correct.

**Tools:** Wireshark, tshark, Python
