##########################################################################################
# This is a free and open source VPN project created by William J. Appleton.             #
# This project is released under the MIT license and can be modified and distributed.    #
# This VPN is not considered "production safe" and comes with no warranty.               #
##########################################################################################
#                           *USE AT YOUR OWN RISK*                                       #
##########################################################################################

#Begin Imports
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from concurrent.futures import ThreadPoolExecutor
import oqs, netifaces, random, base64, json, argparse, os, secrets, socket, fcntl, struct, threading
#End Imports

#Start Banner
print("--------------------------------------------------------------------------------")
print("|              Jormungandr Quantum Safe VPN by Mephistopheles                  |")
print("--------------------------------------------------------------------------------")
#End Banner

#Begin Constant Assignment
TUN_PATH = "/dev/net/tun"
interfaces = os.listdir('/sys/class/net/')
iface_count = 0
IFACE_NAME = ""
while not IFACE_NAME:
    testname = "snk" + str(iface_count)
    if testname not in interfaces:
        IFACE_NAME = testname
        print(f"[+] Selected interface name {IFACE_NAME}")
    else:
        iface_count += 1
BUF_SIZE = 4096
NONCE_LEN = 12
HEADER_LEN = 25
CTRL_FLAG = 0x01
FRAG_FLAG = 0x02
FRAG_EXT_LEN = 12
MAX_CHUNK = 1536
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
SIOCSIFMTU = 0x8922
PRECOMP_RANDOM_POOL = os.urandom(1536)
REASSEMBLY = {}
#End Constant Assignment

#Begin System Functions
def create_tun():
    tun = os.open(TUN_PATH, os.O_RDWR)
    ifr = struct.pack('16sH14s', IFACE_NAME.encode(), IFF_TUN | IFF_NO_PI, b'\x00' * 14)
    fcntl.ioctl(tun, TUNSETIFF, ifr)
    print(f"[+] Opened TUN device: {IFACE_NAME}")
    return tun

def set_tun_mtu(iface, mtu):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifr = struct.pack('16sH14s', iface.encode(), mtu, b'\x00' * 14)
    fcntl.ioctl(s, SIOCSIFMTU, ifr)
    s.close()
#End System Functions

#Begin Protocol Functions
def fragmentor(ct, seq, nonce):
    frag_id = secrets.randbits(32)
    total = len(ct)
    frag_cnt = (total + MAX_CHUNK - 1) // MAX_CHUNK
    offset = 0
    frag_idx = 0
    chunked_packets = []
    while offset < total:
        chunk = ct[offset: offset + MAX_CHUNK]
        offset += len(chunk)
        header = bytearray()
        flags = CTRL_FLAG | (FRAG_FLAG if frag_cnt > 1 else 0)
        header += bytes([flags])
        header += struct.pack("<Q", seq)
        header += struct.pack("<I", len(chunk))
        if frag_cnt > 1:
            header += struct.pack("<I", total)
            header += struct.pack("<I", frag_id)
            header += struct.pack("<H", frag_idx)
            header += struct.pack("<H", frag_cnt)
            frag_idx += 1
        seq = (seq + 1) & 0xFFFFFFFFFFFFFFFF
        packet = header + nonce + chunk
        chunked_packets.append(packet)
    return chunked_packets, seq

def defragmentor(frag_id, frag_cnt, frag_idx, chunk):
    if frag_id not in REASSEMBLY:
        REASSEMBLY[frag_id] = [None] * frag_cnt
    REASSEMBLY[frag_id][frag_idx] = chunk
    if all(part is not None for part in REASSEMBLY[frag_id]):
        full_packet = b''.join(REASSEMBLY[frag_id])
        del REASSEMBLY[frag_id]
        return full_packet
    return None

def listen(port_number):
    host = '0.0.0.0'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port_number))
        server_socket.listen(1)
        conn, addr = server_socket.accept()
        with conn:
            data = conn.recv(1)
            if data == bytes([255]):
                server_socket.close()
                return addr[0]

def get_bucket_padding(orig_len, bucket_size):
    pad_len = bucket_size - orig_len
    start = random.randint(0, 1536 - pad_len)
    return PRECOMP_RANDOM_POOL[start:start + pad_len]

def select_bucket(length):
    BUCKETS = [64, 256, 512, 1536]
    for b in BUCKETS:
        if length <= b:
            return b
    return BUCKETS[-1]

def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SystemExit("Connection closed")
        buf.extend(chunk)
    return bytes(buf)

def reader(tun, sock, data_key):
    aead = ChaCha20Poly1305(data_key)
    seq = 0
    while True:
        data = os.read(tun, BUF_SIZE)
        if not data:
            continue
        try:
            orig_len = len(data)
            bucket = select_bucket(orig_len)
            padding = get_bucket_padding(orig_len + 4, bucket)
            prefix = struct.pack(">i", orig_len)
            payload = prefix + data + padding
            nonce = os.urandom(NONCE_LEN)
            ciphertext = aead.encrypt(nonce, payload, b"")
            pkt_arr, seq = fragmentor(ciphertext, seq, nonce)
            for pkt in pkt_arr:
                sock.send(pkt)
        except Exception as e:
            print(f"[!] Reader Send error: {e}")
            break

def writer(tun, sock, data_key):
    aead = ChaCha20Poly1305(data_key)
    buf = b""
    while True:
        try:
            incoming = sock.recv(2048)
            if not incoming:
                print("[!] Writer: socket closed by peer")
                break
            buf += incoming
            while len(buf) >= HEADER_LEN:
                flags = buf[0]
                seq, chunk_len = struct.unpack("<Q I", buf[1:13])
                flags = buf[0]
                seq, chunk_len = struct.unpack("<Q I", buf[1:13])
                pos = 13
                if flags & FRAG_FLAG:
                    if len(buf) < 13 + FRAG_EXT_LEN:
                       break
                    total_ct_len, frag_id = struct.unpack("<I I", buf[pos:pos+8])
                    frag_idx, frag_cnt = struct.unpack("<H H", buf[pos+8:pos+12])
                    pos += FRAG_EXT_LEN
                else:
                    frag_cnt = 1
                    frag_idx = 0
                    frag_id = 0
                nonce = buf[pos : pos + NONCE_LEN]
                pos += NONCE_LEN
                total_needed = pos + chunk_len
                if len(buf) < total_needed:
                    break
                ct_chunk = buf[pos : total_needed]
                buf = buf[total_needed:]
                if frag_cnt > 1:
                    full = defragmentor(frag_id, frag_cnt, frag_idx, ct_chunk)
                    if full is None:
                        continue
                    ciphertext = full
                else:
                    ciphertext = ct_chunk
                decoded = aead.decrypt(nonce, ciphertext, b"")
                if not decoded:
                    continue
                if len(decoded) < 4:
                    continue
                body_len = struct.unpack(">i", decoded[:4])[0]
                if body_len <= 0 or body_len > 1536:
                    continue
                if decoded[4] >> 4 != 4 and decoded[4] >> 4 != 6:
                    continue
                try:
                    packet = decoded[4 : 4 + body_len]
                    if packet[0] >> 4 not in (4, 6):
                        continue
                    os.write(tun, packet)
                except Exception as e:
                    print(f"[!]TUN write failed: {e}")
        except Exception as e:
                return False
#End Protocol Functions

#Begin Key Exchange
def derive_keys(raw_shared: bytes, salt: bytes):
    def hk(info: bytes, ln: int):
        return HKDF(algorithm=hashes.SHA256(), length=ln, salt=salt, info=info).derive(raw_shared)
    return (
        hk(b"VPN handshake v2", 32),
        hk(b"VPN data channel v2", 32),
    )

def getkey_kyber(key_port, data_port, cert_path):
    pub_keys = [os.path.join(cert_path, f) for f in os.listdir(cert_path) if f.endswith(".pub")]
    print("[+] Waiting for peer...")
    endpoint_ip = listen(data_port)
    print(f"[+] Request from peer {endpoint_ip}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(600)
        while True:
            try:
                s.connect((endpoint_ip, key_port))
                break
            except:
                print(".", end="")
        else:
            raise SystemExit("Failed to connect to peer for key exchange.")
        pk_len = struct.unpack("<I", recv_exact(s, 4))[0]
        server_pk = recv_exact(s, pk_len)
        with oqs.KeyEncapsulation("Kyber1024") as kem:
            ct, raw_shared = kem.encap_secret(server_pk)
        s.sendall(struct.pack("<I", len(ct)))
        s.sendall(ct)
        head = recv_exact(s, 16 + NONCE_LEN)
        salt, nonce = head[:16], head[16:]
        clen = struct.unpack("<I", recv_exact(s, 4))[0]
        ct_meta = recv_exact(s, clen)
        handshake_key, data_key = derive_keys(raw_shared, salt)
        meta_bytes = ChaCha20Poly1305(handshake_key).decrypt(nonce, ct_meta, b"")
        meta = json.loads(meta_bytes.decode("utf-8"))
        data_key_sig_b64 = meta["DataKeySig"]
        aad_bytes = base64.b64decode(meta["aad_b64"].encode("utf-8"))
        data_key_sig = base64.b64decode(data_key_sig_b64)
        ok = cert_checker(pub_keys, data_key_sig, data_key)
        if ok:
            return {"peer": endpoint_ip, "data_key": data_key, "aad_bytes": aad_bytes}
        else:
            return False

def sendkey_kyber(port_number, cert_data):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(20)
        try:
            s.bind(('0.0.0.0', port_number))
        except:
            raise SystemExit("Failed to bind to port for key exchange.")
        s.listen(1)
        conn, addr = s.accept()
        conn.settimeout(20)
        with conn, oqs.KeyEncapsulation("Kyber1024") as kem:
            public_key = kem.generate_keypair()
            conn.sendall(struct.pack("<I", len(public_key)))
            conn.sendall(public_key)
            ct_len = struct.unpack("<I", recv_exact(conn, 4))[0]
            ct = recv_exact(conn, ct_len)
            raw_shared = kem.decap_secret(ct)
            salt = os.urandom(16)
            handshake_key, data_key = derive_keys(raw_shared, salt)
            data_key_sig_b64 = cert_signer(cert_data, data_key)
            aad_bytes = os.urandom(16)
            meta = {
                "DataKeySig": data_key_sig_b64,
                "aad_b64": base64.b64encode(aad_bytes).decode("utf-8")
            }
            meta_bytes = json.dumps(meta).encode("utf-8")
            aead = ChaCha20Poly1305(handshake_key)
            nonce = os.urandom(NONCE_LEN)
            ct_meta = aead.encrypt(nonce, meta_bytes, b"")
            conn.sendall(salt + nonce + struct.pack("<I", len(ct_meta)) + ct_meta)
        return {"data_key": data_key, "aad_bytes": aad_bytes}
#End Key Exchange

#Begin Certificate System
def dilithium_generator():
    with oqs.Signature("ML-DSA-65") as sig:
        pub = sig.generate_keypair()
        priv = sig.export_secret_key()
        return priv, pub

def cert_signer(private_key_bytes: bytes, msg) -> str:
    with oqs.Signature("ML-DSA-65", secret_key=private_key_bytes) as sig:
        try:
            signature = sig.sign_with_ctx_str(msg, b"SEPC-HF5")
        except AttributeError:
            signature = sig.sign(msg)
    return base64.b64encode(signature).decode("utf-8")

def cert_checker(pubkeys: list[str], data_sig: bytes, msg: str) -> bool:
    for pk_path in pubkeys:
        print(f"Trying key: {pk_path}")
        pk_bytes = open(pk_path, "rb").read()

        with oqs.Signature("ML-DSA-65") as sig:
            try:
                if sig.verify_with_ctx_str(msg, data_sig, b"SEPC-HF5", pk_bytes):
                    print("OK.")
                    return True
            except AttributeError:
                try:
                    if sig.verify(data_sig, msg, pk_bytes):
                        print("OK.")
                        return True
                except Exception:
                    pass
        print("Fail.")
    return False
#End Certificate System

#Begin Role Functions
def client_mode(tun, port, data_key, peer_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", port))
        s.settimeout(30)
        print(f"[+] Waiting for connection on port {port}...")
        try:
            data, addr = s.recvfrom(1)
        except Exception:
            raise SystemExit("Connection failed! (bad auth?)")
        print(f"[+] Connected to {addr[0]}:{addr[1]}")
        s.connect(addr)
        t1 = threading.Thread(target=reader, args=(tun, s, data_key), daemon=True)
        t2 = threading.Thread(target=writer, args=(tun, s, data_key), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

def server_mode(tun, peer_ip, port, data_key, aad_bytes):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((peer_ip, port))
        s.settimeout(None)
        print(f"[+] Initiating connection to peer. {peer_ip}")
        s.send(b"\xff")
        print("[+] Connected.")
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_reader = executor.submit(reader, tun, s, data_key)
            future_writer = executor.submit(writer, tun, s, data_key)
            result = future_writer.result()
            if result is False:
                return True
            future_reader.cancel()
#End Role Functions

#Begin Main
def main():
    parser = argparse.ArgumentParser(description="SEPC VPN version 3.0")
    parser.add_argument("-c", "--connect", help="Peer IP or DNS")
    parser.add_argument("-l", "--listen", action="store_true")
    parser.add_argument("-kp", "--keyport", help="Port to use for key exchange.")
    parser.add_argument("-dp", "--dataport", help="Port to use for data exchange.")
    parser.add_argument("-x", "--cert", help="Path to dilithium private key or to directory with dilithium public keys.")
    parser.add_argument("-g","--gencert",help="Path to folder for storing the generated dilithium certificate pair.")
    args = parser.parse_args()
    if args.gencert:
        private, public = dilithium_generator()
        pubfile = str(args.gencert) + "/snek-cert.pub"
        privfile = str(args.gencert) + "/snek-cert.priv"
        open(pubfile, "wb").write(public)
        open(privfile, "wb").write(private)
        raise SystemExit("Certificates written")
    if args.keyport:
        key_port = int(args.keyport)
    else:
        key_port = 443
    if args.dataport:
        data_port = int(args.dataport)
    else:
        data_port = 10666
    tun = create_tun()
    set_tun_mtu(IFACE_NAME, 1536)
    if args.connect:
        if not args.cert:
            raise SystemExit("Must specifiy a certificate for client mode!")
        print(f"[+] Connecting to {args.connect}:{key_port}...")
        try:
            with socket.create_connection((args.connect, data_port), timeout=5) as probe:
                probe.sendall(bytes([255]))
        except Exception as e:
            raise SystemExit(f"Failed to probe data port on receiver: {e}")
        cert_data = open(str(args.cert), "rb").read()
        session_keys = sendkey_kyber(key_port, cert_data)
        data_key = session_keys["data_key"]
        aad_bytes = session_keys["aad_bytes"]
        client_mode(tun, data_port, data_key, args.connect)
    else:
        while True:
            if not args.cert:
                raise SystemExit("Must specifiy directory containing approved public keys for server mode!")
            authorized = getkey_kyber(key_port, data_port, args.cert)
            if authorized:
                currentpeer = authorized["peer"]
                data_key = authorized["data_key"]
                aad_bytes = authorized["aad_bytes"]
                server_mode(tun, currentpeer, data_port, data_key, aad_bytes)
            else:
                print(f"Connection not authorized. {currentpeer}")
#End Main

#Begin Init
if __name__ == "__main__":
    main()
#End Init
