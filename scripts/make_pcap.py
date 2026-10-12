"""Write a small benign pcap with no third-party deps: 30 SYNs to ports 1-30 (scan pattern),
one NULL and one XMAS probe, and an HTTP GET carrying the SIEMLAB test marker + Nmap NSE UA."""
import struct, sys

def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def ip(a): return bytes(int(x) for x in a.split("."))

def tcp_pkt(src, dst, sport, dport, flags, seq=1000, ack=0, payload=b""):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
    pseudo = ip(src) + ip(dst) + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    c = csum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack("!H", c) + hdr[18:]
    tot = 20 + len(hdr) + len(payload)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, 1, 0, 64, 6, 0, ip(src), ip(dst))
    iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
    eth = b"\x02\0\0\0\0\x02" + b"\x02\0\0\0\0\x01" + b"\x08\x00"
    return eth + iph + hdr + payload

def build():
    A, V = "192.168.56.10", "192.168.56.20"
    p = [tcp_pkt(A, V, 40000 + i, i, 0x02) for i in range(1, 31)]
    p.append(tcp_pkt(A, V, 41000, 80, 0x00))
    p.append(tcp_pkt(A, V, 41001, 80, 0x29))  # FIN PSH URG
    req = b"GET /SIEMLAB-TEST-7f3a HTTP/1.1\r\nHost: victim\r\nUser-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\r\n\r\n"
    s, c = 50000, 7000
    p += [tcp_pkt(A, V, s, 80, 0x02, c), tcp_pkt(V, A, 80, s, 0x12, 9000, c + 1),
          tcp_pkt(A, V, s, 80, 0x10, c + 1, 9001), tcp_pkt(A, V, s, 80, 0x18, c + 1, 9001, req),
          tcp_pkt(V, A, 80, s, 0x10, 9001, c + 1 + len(req))]
    return p

def write(path):
    pk = build()
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, b in enumerate(pk):
            fh.write(struct.pack("<IIII", 1760000000, i * 1000, len(b), len(b)) + b)
    return len(pk)

if __name__ == "__main__":
    print(write(sys.argv[1] if len(sys.argv) > 1 else "pcaps/siemlab.pcap"), "packets written")
