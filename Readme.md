****Overview****

Jormungandr VPN is a post-quantum, authenticated, obfuscated tunneling system written entirely as a single, meticulously-documented Python file.

It uses:

- Kyber-1024 (via liboqs) for post-quantum key exchange

- Dilithium / ML-DSA-65 for certificate-style authentication

- ChaCha20-Poly1305 for symmetric data encryption

- Custom fragmentation, padding buckets, and traffic morphology

- TUN interface networking on Linux

- UDP for the encrypted data channel

- TCP for the Kyber handshake

*Despite being Python, Jormungandr routinely reaches:*

- 128 Mbps throughput

- ~0.8–1.5 ms latency

- <1 second handshake time

#################################################################################################################################################

****Features****

**Post-Quantum Secure**

- Kyber-1024 KEM for key exchange

- ML-DSA-65 (Dilithium) signatures for endpoint trust

- ChaCha20-Poly1305 for AEAD encryption

**Traffic Obfuscation**

- Dynamic bucket sizing (64 / 256 / 512 / 1536 bytes)

- Random padding pulled from a 1536-byte precomputed pool

- Encrypted payload indistinguishable from random noise

- Fragmentation + Reassembly

- Custom fragmentation logic with:

 -- Unique fragment IDs

 -- Chunk ordering

 -- Reassembly buffers

Ensures large ciphertext frames travel safely across UDP

**Minimal Single-File Architecture**

- Entire VPN (server + client + KEX + certificates) in one file

No external system dependencies except:

- Python 3

- liboqs / python-oqs

- cryptography

**TUN Device Management**

- Auto-allocates interface name (snk0, snk1, etc.)

- Sets MTU to 1536 for optimal bucket handling

- Reads and writes raw IP packets directly

#################################################################################################################################################

****Installation****

```bash
sudo apt install python3 python3-pip python3-dev build-essential libssl-dev cmake net-tools
pip install cryptography
pip install python-oqs
pip install netifaces
```

#################################################################################################################################################

****Generating Certificates****

```bash
python3 snek-vpn.py -g /path/to/store/certificates/
```

#################################################################################################################################################

****Server Mode****

```bash
sudo python3 snek-vpn.py -l -x /path/to/authorized/pub/certs/
sudo ifconfig snk0 10.2.0.1 pointopoint 10.2.0.2 up
```

#################################################################################################################################################

****Client Mode****

```bash
sudo python3 snek-vpn.py -c 192.168.0.123 -x /path/to/priv/cert/
sudo ifconfig snk0 10.2.0.2 pointopoint 10.2.0.1 up
```

#################################################################################################################################################

****Optional Flags****

to control keyport (TCP) and dataport (UDP) numbers:

Server:


```bash
sudo python3 snek-vpn.py -l -x /path/to/authorized/pub/certs/ -kp 80 -dp 1024
sudo ifconfig snk0 10.2.0.1 pointopoint 10.2.0.2 up
```

Client:

```bash
sudo python3 snek-vpn.py -c 192.168.0.123 -x /path/to/priv/cert/ -kp 80 -dp 1024
sudo ifconfig snk0 10.2.0.2 pointopoint 10.2.0.1 up
```

#################################################################################################################################################
- William Appleton, 2025
