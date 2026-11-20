# Crack the office Wi-Fi

### 1. I extracted the handshake from the capture
```bash
hcxpcapngtool -o acme.hc22000 capture-3.pcap
```
Key output lines:
```
packets inside...........................: 2471
ESSID (total unique).....................: 2
EAPOL pairs written to 22000 hash file...: 4 (RC checked)
EAPOL M12E2 (challenge - ANONCE from M1).: 1
EAPOL M32E2 (authorized - ANONCE from M3): 3
```
Two different ESSIDs and 4 EAPOL pairs: the capture holds handshakes from more than one network/client (the challenge's trap).

### 2. I cracked the passphrase
```bash
hashcat -m 22000 -a 3 acme.hc22000 'Acme?d?d?d?d?d?d'
```
```
Hash.Mode........: 22000 (WPA-PBKDF2-PMKID+EAPOL)
Guess.Mask.......: Acme?d?d?d?d?d?d [10]
Speed.#02........:   152.7 kH/s  (Apple M2 Pro, OpenCL)
Recovered........: 3/4 Digests, 1/2 Salts
Progress.........: 2000000/2000000 (100.00%)
```
Results (`hashcat -m 22000 acme.hc22000 --show`, end of each line):
```
...*41636d652d57694669*...:Acme112284   <- 1 client
...*41636d652d57694669*...:Acme668783   <- 2 clients
...*41636d652d57694669*...:Acme668783
```
3 of 4 pairs cracked (the 4th belongs to the other ESSID, outside the `Acme+6digits` mask).

### 3. Which password is the right one? `Acme668783`
The same ESSID/AP produced two different passphrases. The handshake type decides:
- **M32E2 (authorized):** the AP sent message 3 → the client passed the check → correct password. Two clients associated with `Acme668783`.
- **M12E2 (challenge):** only M1→M2, no M3 → a client that typed a **wrong** password and never associated. This is the decoy `Acme112284` ("not every handshake ends with an associated station").

So the real PSK is **`Acme668783`**; confirmed because it actually decrypts the traffic.

### 4. I decrypted in Wireshark
`Preferences → Protocols → IEEE 802.11`
- Decryption keys → **wpa-pwd**, value `Acme668783:Acme-WiFi` (format `password:SSID`)

### 5. I found the flag
Filter `http` → a **POST `/api/notes`** request to `intranet.acme.test` (host `10.0.0.80`).

<img width="1552" height="219" alt="Screenshot 2026-11-20 at 11 55 56" src="https://github.com/user-attachments/assets/d478edb9-8bb8-41c3-8ea2-d4d15f3a78b7" />

*Follow → HTTP Stream* on that packet: the flag is in the POST body.

<img width="501" height="212" alt="Screenshot 2026-11-20 at 11 56 13" src="https://github.com/user-attachments/assets/d6f0dd30-1fbc-40af-89cd-87a64113a45e" />
