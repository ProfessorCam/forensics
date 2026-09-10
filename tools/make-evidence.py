#!/usr/bin/env python3
"""
Builds the evidence for the Packet Forensics site: one capture, one flag, three parts.

  site/pcaps/evidence.pcap   about eleven seconds on the lab LAN, captured from a
                             mirror port: ARP, NTP, a ping, a handful of DNS lookups,
                             two HTTP fetches (a page and a photo) and a phone call
  site/answers.js            SHA-256 hashes of the flag and of each part, nothing else

The flag is read from tools/flag.txt (not committed). One line, the parts separated
by "|", for example:

    epicCTF{c4p|tur3d_in_|the_act}

  part 1  is the TXT answer to a DNS lookup                        (Exhibit A)
  part 2  is the ImageDescription in the EXIF data of the photo   (Exhibit B)
  part 3  is spoken in the phone call, plain words, underscores   (Exhibit C)
          read as spaces, the closing brace read out loud

Every byte is written by this script, checksums included, so Wireshark and tcpdump read
the file as an ordinary capture. Needs Pillow (the photo), espeak-ng and ffmpeg (the voices).

Usage:  python3 tools/make-evidence.py
"""
import hashlib, io, os, re, struct, subprocess, sys, time
from PIL import Image, ImageDraw, ImageFont

HERE  = os.path.dirname(os.path.abspath(__file__))
SITE  = os.path.join(HERE, '..', 'site')
PCAPS = os.path.join(SITE, 'pcaps')
BUILD = os.path.join(HERE, 'build')

# ---------- the lab machines (same LAN as the other Packet Lessons sites) ----------
PC2_MAC   = bytes.fromhex('000c297de35c'); PC2_IP   = '192.168.110.60'   # Lab PC 2: the machine under investigation
GW_MAC    = bytes.fromhex('005056c00001'); GW_IP    = '192.168.110.1'    # gateway; also the LAN's DNS and NTP server
SRV_MAC   = bytes.fromhex('000c29a1b2c3'); SRV_IP   = '10.10.20.5'       # Lab Server on the far network: the web server
PHONE_MAC = bytes.fromhex('000c299e7710'); PHONE_IP = '192.168.110.72'   # front desk phone
BCAST     = b'\xff' * 6

T0 = time.mktime((2026, 9, 8, 14, 7, 0, 0, 0, -1))

# ---------- packet building ----------
def ip2b(ip): return bytes(int(x) for x in ip.split('.'))

def checksum(data):
    if len(data) % 2: data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth(dst, src, etype, payload):
    frame = dst + src + struct.pack('!H', etype) + payload
    return frame + b'\0' * max(0, 60 - len(frame))

def ipv4(src, dst, proto, payload, ident, ttl=64, df=True):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000 if df else 0, ttl, proto, 0, ip2b(src), ip2b(dst))
    hdr = hdr[:10] + struct.pack('!H', checksum(hdr)) + hdr[12:]
    return hdr + payload

def udp(src, dst, sport, dport, payload):
    ln = 8 + len(payload)
    seg = struct.pack('!HHHH', sport, dport, ln, 0) + payload
    pseudo = ip2b(src) + ip2b(dst) + struct.pack('!BBH', 0, 17, ln)
    return seg[:6] + struct.pack('!H', checksum(pseudo + seg) or 0xffff) + seg[8:]

def tcp(src, dst, sport, dport, seq, ack, flags, payload=b'', window=64240, options=b''):
    while len(options) % 4: options += b'\x00'
    fl = sum({'F': 1, 'S': 2, 'R': 4, 'P': 8, 'A': 16}[c] for c in flags)
    off = (5 + len(options) // 4) << 4
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, off, fl, window, 0, 0) + options
    seg = hdr + payload
    pseudo = ip2b(src) + ip2b(dst) + struct.pack('!BBH', 0, 6, len(seg))
    return seg[:16] + struct.pack('!H', checksum(pseudo + seg)) + seg[18:]

def icmp_echo(reply, ident, seq, data):
    msg = struct.pack('!BBHHH', 0 if reply else 8, 0, 0, ident, seq) + data
    return msg[:2] + struct.pack('!H', checksum(msg)) + msg[4:]

def arp(op, sha, spa, tha, tpa):
    return struct.pack('!HHBBH', 1, 0x0800, 6, 4, op) + sha + ip2b(spa) + tha + ip2b(tpa)

def dns_name(name):
    return b''.join(bytes([len(l)]) + l.encode() for l in name.split('.')) + b'\0'

def dns_query(xid, name, qtype):
    return struct.pack('!HHHHHH', xid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack('!HH', qtype, 1)

def dns_answer(xid, name, qtype, rdata, ttl=300):
    r = struct.pack('!HHHHHH', xid, 0x8180, 1, 1, 0, 0) + dns_name(name) + struct.pack('!HH', qtype, 1)
    return r + b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, ttl, len(rdata)) + rdata

def txt_rdata(*strings):
    return b''.join(bytes([len(s)]) + s.encode() for s in strings)

def ntp(client):
    if client:
        return struct.pack('!BBBb', 0x23, 0, 6, -20) + b'\0' * 36 + struct.pack('!II', int(T0) + 2208988800, 0x3a2b1c00)
    tx = int(T0) + 2208988800
    return (struct.pack('!BBBb', 0x24, 2, 6, -23) + struct.pack('!iII', 0x1a, 0x0f2b, 0x50505300) +
            struct.pack('!II', tx - 17, 0) + struct.pack('!II', tx, 0x3a2b1c00) + struct.pack('!II', tx, 0x5e001000) + struct.pack('!II', tx, 0x5e0a2000))

class Capture:
    """Collects (time, frame) pairs and writes them in time order."""
    def __init__(self): self.frames = []
    def add(self, t, frame): self.frames.append((t, frame))
    def write(self, path):
        self.frames.sort(key=lambda x: x[0])
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, frame in self.frames:
                sec = int(T0 + t); usec = int(round((T0 + t - sec) * 1e6))
                f.write(struct.pack('<IIII', sec, usec, len(frame), len(frame)) + frame)
        return len(self.frames)

# ---------- the flag ----------
def read_flag():
    path = os.path.join(HERE, 'flag.txt')
    if not os.path.exists(path):
        sys.exit('tools/flag.txt is missing. Put the flag there on one line with the three parts separated by |, e.g.\n  epicCTF{c4p|tur3d_in_|the_act}')
    parts = open(path).read().strip().split('|')
    if len(parts) != 3: sys.exit('flag.txt must have exactly three parts separated by |')
    return parts

def norm_part(s): return re.sub(r'[^a-z0-9]', '', s.lower())
def norm_flag(s): return re.sub(r'\s+', '_', s.strip().lower())
def sha(s): return hashlib.sha256(s.encode()).hexdigest()

# ---------- Exhibit B: the photo ----------
def make_photo(part2):
    W, H = 480, 360
    img = Image.new('RGB', (W, H), (238, 236, 228))
    d = ImageDraw.Draw(img)
    big = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', 26)
    med = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 17)
    small = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 13)
    # the board itself, slightly off-white with a grey frame and a marker tray
    d.rectangle([8, 8, W - 9, H - 9], fill=(250, 250, 246), outline=(150, 150, 150), width=4)
    d.rectangle([60, H - 22, W - 60, H - 12], fill=(120, 120, 120))
    # a topology sketch in blue marker
    blue, red, black = (40, 70, 170), (190, 40, 40), (50, 50, 50)
    boxes = [(50, 120, 'PC 2', '.60'), (200, 120, 'GW', '.1'), (350, 120, 'SRV', '10.10.20.5')]
    for x, y, name, addr in boxes:
        d.rectangle([x, y, x + 90, y + 56], outline=blue, width=3)
        d.text((x + 10, y + 6), name, fill=blue, font=med)
        d.text((x + 10, y + 30), addr, fill=blue, font=small)
    d.line([140, 148, 200, 148], fill=blue, width=3)
    d.line([290, 148, 350, 148], fill=blue, width=3)
    d.line([245, 120, 245, 80], fill=blue, width=3)
    d.ellipse([215, 50, 275, 82], outline=blue, width=3)
    d.text((222, 56), 'LAN', fill=blue, font=small)
    d.text((80, 205), 'mirror port -> Student VM (.50)', fill=blue, font=small)
    d.line([95, 176, 60, 205], fill=blue, width=2)
    # notes in red and black
    d.text((40, 30), 'LAB 3  -  DO NOT ERASE', fill=red, font=big)
    d.text((300, 250), 'back in 10 min', fill=black, font=med)
    d.text((40, 250), 'phone: desk = x72', fill=black, font=med)
    d.line([60, 290, 420, 292], fill=(200, 200, 200), width=6)   # a half-wiped smear
    exif = Image.Exif()
    exif[0x010e] = 'part 2 of 3: ' + part2          # ImageDescription
    exif[0x010f] = 'LabPhone'                        # Make
    exif[0x0110] = 'LabPhone 2 camera'               # Model
    exif[0x0131] = 'Evidence Desk photo app 1.4'     # Software
    exif[0x0132] = '2026:09:08 14:02:17'             # DateTime
    exif[0x013b] = 'front desk'                      # Artist
    buf = io.BytesIO()
    img.save(buf, 'JPEG', quality=72, exif=exif.tobytes())
    data = buf.getvalue()
    os.makedirs(BUILD, exist_ok=True)
    open(os.path.join(BUILD, 'whiteboard.jpg'), 'wb').write(data)
    assert Image.open(io.BytesIO(data)).getexif()[0x010e].endswith(part2)
    return data

# ---------- Exhibit C: the voices ----------
def say(text, voice, name):
    os.makedirs(BUILD, exist_ok=True)
    wav = os.path.join(BUILD, name + '.wav'); ul = os.path.join(BUILD, name + '.ul')
    subprocess.run(['espeak-ng', '-v', voice, '-s', '140', '-w', wav, text], check=True)
    subprocess.run(['ffmpeg', '-loglevel', 'error', '-y', '-i', wav, '-ar', '8000', '-ac', '1', '-f', 'mulaw', ul], check=True)
    return open(ul, 'rb').read()

SILENCE = 0xff   # mu-law zero

def rtp_stream(cap, t_start, src_mac, dst_mac, src_ip, dst_ip, sport, dport, ssrc, seq0, ts0, audio, ident0):
    """One G.711 mu-law stream: a 160-byte packet every 20 ms, timestamps and sequence numbers in step."""
    n = (len(audio) + 159) // 160
    audio = audio + bytes([SILENCE]) * (n * 160 - len(audio))
    for i in range(n):
        hdr = struct.pack('!BBHII', 0x80, (0x80 if i == 0 else 0) | 0, (seq0 + i) & 0xffff, (ts0 + 160 * i) & 0xffffffff, ssrc)
        jitter = ((i * 7919) % 11 - 5) * 0.00003     # a few tens of microseconds either way
        cap.add(t_start + 0.020 * i + jitter, eth(dst_mac, src_mac, 0x0800, ipv4(src_ip, dst_ip, 17, udp(src_ip, dst_ip, sport, dport, hdr + audio[i * 160:(i + 1) * 160]), (ident0 + i) & 0xffff)))
    return n

# ---------- HTTP: one whole request and response, as a real Linux client and nginx would send it ----------
def http_session(cap, t, cport, request, response, ids, sids, close_after):
    """ids / sids: mutable [next IP identification] for the client and the server."""
    cseq, sseq = 0x2b3c4d5e + cport, 0x6f708192 + cport
    mss = b'\x02\x04\x05\xb4'
    def c2s(seg, dt): cap.add(t + dt, eth(GW_MAC, PC2_MAC, 0x0800, ipv4(PC2_IP, SRV_IP, 6, seg, ids[0], ttl=64))); ids[0] += 1
    def s2c(seg, dt): cap.add(t + dt, eth(PC2_MAC, GW_MAC, 0x0800, ipv4(SRV_IP, PC2_IP, 6, seg, sids[0], ttl=63))); sids[0] += 1
    c2s(tcp(PC2_IP, SRV_IP, cport, 80, cseq, 0, 'S', options=mss), 0)
    s2c(tcp(SRV_IP, PC2_IP, 80, cport, sseq, cseq + 1, 'SA', options=mss), 0.00131)
    c2s(tcp(PC2_IP, SRV_IP, cport, 80, cseq + 1, sseq + 1, 'A'), 0.00137)
    c2s(tcp(PC2_IP, SRV_IP, cport, 80, cseq + 1, sseq + 1, 'PA', request), 0.00152)
    cnext, snext = cseq + 1 + len(request), sseq + 1
    dt = 0.00152 + 0.00188
    chunks = [response[i:i + 1460] for i in range(0, len(response), 1460)]
    for i, ch in enumerate(chunks):
        last = i == len(chunks) - 1
        s2c(tcp(SRV_IP, PC2_IP, 80, cport, snext, cnext, 'PA' if last else 'A', ch), dt)
        snext += len(ch); dt += 0.00041
        if i % 2 == 1 or last:                     # the client acknowledges every second segment
            c2s(tcp(PC2_IP, SRV_IP, cport, 80, cnext, snext, 'A'), dt + 0.00009)
    dt += close_after                                # keep-alive: the client hangs up later
    c2s(tcp(PC2_IP, SRV_IP, cport, 80, cnext, snext, 'FA'), dt)
    s2c(tcp(SRV_IP, PC2_IP, 80, cport, snext, cnext + 1, 'FA'), dt + 0.00129)
    c2s(tcp(PC2_IP, SRV_IP, cport, 80, cnext + 1, snext + 1, 'A'), dt + 0.00134)
    return dt + 0.00134

def http_response(ctype, body, extra=''):
    return (b'HTTP/1.1 200 OK\r\nServer: nginx/1.27.0\r\nDate: Tue, 08 Sep 2026 20:07:0' + b'4 GMT\r\nContent-Type: ' + ctype.encode() +
            b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nLast-Modified: Tue, 08 Sep 2026 14:02:40 GMT\r\nConnection: keep-alive\r\n' +
            extra.encode() + b'\r\n' + body)

# ---------- SIP ----------
def sip(start, headers, body=b''):
    return (start + '\r\n' + '\r\n'.join(headers) + '\r\nContent-Length: ' + str(len(body)) + '\r\n\r\n').encode() + body

def sdp(ip, port, who):
    return ('v=0\r\no=' + who + ' 1757340420 1757340420 IN IP4 ' + ip + '\r\ns=call\r\nc=IN IP4 ' + ip + '\r\nt=0 0\r\n' +
            'm=audio ' + str(port) + ' RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\na=sendrecv\r\n').encode()

# ---------- the whole story ----------
def build():
    parts = read_flag()
    flag = ''.join(parts)
    spoken = parts[2].rstrip('}').replace('_', ' ')
    cap = Capture()
    ids, sids, gids, pids = [0x3e80], [0x0000], [0x71a0], [0x0c10]     # IP identification counters per machine

    def pc2_gw_udp(t, sport, dport, payload):
        cap.add(t, eth(GW_MAC, PC2_MAC, 0x0800, ipv4(PC2_IP, GW_IP, 17, udp(PC2_IP, GW_IP, sport, dport, payload), ids[0]))); ids[0] += 1
    def gw_pc2_udp(t, sport, dport, payload):
        cap.add(t, eth(PC2_MAC, GW_MAC, 0x0800, ipv4(GW_IP, PC2_IP, 17, udp(GW_IP, PC2_IP, sport, dport, payload), gids[0]))); gids[0] += 1
    def lookup(t, xid, sport, name, qtype, rdata):
        pc2_gw_udp(t, sport, 53, dns_query(xid, name, qtype))
        gw_pc2_udp(t + 0.0213, 53, sport, dns_answer(xid, name, qtype, rdata))

    # 0.0  Lab PC 2 wakes up: who is the gateway?
    cap.add(0.0, eth(BCAST, PC2_MAC, 0x0806, arp(1, PC2_MAC, PC2_IP, b'\0' * 6, GW_IP)))
    cap.add(0.00041, eth(PC2_MAC, GW_MAC, 0x0806, arp(2, GW_MAC, GW_IP, PC2_MAC, PC2_IP)))
    # 0.2  ordinary background noise: a software update check and the clock
    lookup(0.2107, 0x1a2b, 40111, 'updates.lab.local', 1, ip2b(SRV_IP))
    pc2_gw_udp(0.2400, 123, 123, ntp(True)); gw_pc2_udp(0.2409, 123, 123, ntp(False))
    # 1.0  one ping to the server
    ping_data = struct.pack('!II', 0x66d9e2a1, 0x000a1b2c) + b'\0' * 8 + bytes(range(0x10, 0x38))
    cap.add(1.0031, eth(GW_MAC, PC2_MAC, 0x0800, ipv4(PC2_IP, SRV_IP, 1, icmp_echo(False, 0x1e2f, 1, ping_data), ids[0]))); ids[0] += 1
    cap.add(1.0044, eth(PC2_MAC, GW_MAC, 0x0800, ipv4(SRV_IP, PC2_IP, 1, icmp_echo(True, 0x1e2f, 1, ping_data), sids[0], ttl=63))); sids[0] += 1
    # 2.0  the photo share page
    lookup(2.0410, 0x1a2c, 40112, 'photos.lab.local', 1, ip2b(SRV_IP))
    index = (b'<!doctype html><html><head><title>Lab 3 photo share</title></head><body>\n<h1>Lab 3 photo share</h1>\n'
             b'<p>Whiteboard photos from the lab, newest first.</p>\n<ul>\n<li><a href="/photos/whiteboard.jpg">whiteboard.jpg</a> (8 Sep, front desk)</li>\n'
             b'<li><a href="/photos/rack.jpg">rack.jpg</a> (2 Sep)</li>\n</ul>\n</body></html>\n')
    req1 = (b'GET /index.html HTTP/1.1\r\nHost: photos.lab.local\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0\r\n'
            b'Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nConnection: keep-alive\r\n\r\n')
    http_session(cap, 2.0702, 49210, req1, http_response('text/html', index), ids, sids, 0.6103)
    # 3.5  Exhibit A: a lookup that answers too much
    lookup(3.5124, 0x1a2d, 40113, 'evidence.lab.local', 1, ip2b(SRV_IP))
    lookup(3.5400, 0x1a2e, 40114, 'part1.evidence.lab.local', 16, txt_rdata('part 1 of 3: ' + parts[0]))
    lookup(4.0033, 0x1a2f, 40115, 'desk.lab.local', 1, ip2b(PHONE_IP))
    # 4.5  Exhibit B: the photo
    photo = make_photo(parts[1])
    req2 = (b'GET /photos/whiteboard.jpg HTTP/1.1\r\nHost: photos.lab.local\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0\r\n'
            b'Accept: image/avif,image/webp,*/*\r\nAccept-Language: en-US,en;q=0.5\r\nReferer: http://photos.lab.local/index.html\r\nConnection: keep-alive\r\n\r\n')
    http_session(cap, 4.5210, 49211, req2, http_response('image/jpeg', photo, 'Accept-Ranges: bytes\r\n'), ids, sids, 0.9021)
    # 7.0  Exhibit C: the phone call
    caller = say('Hi, it is me. Part three of the flag is two words: ' + spoken + '. Once more: ' + spoken + '. Then close the curly brace.', 'en-us', 'caller')
    callee = say('Got it. ' + spoken + ', then the closing brace. Thanks.', 'en-us+f3', 'callee')
    t = 7.0
    call_id = '6b8d2f1e4a@192.168.110.60'
    via = 'Via: SIP/2.0/UDP 192.168.110.60:5060;branch=z9hG4bK-3f2a1c;rport'
    frm = 'From: "Lab PC 2" <sip:pc2@lab.local>;tag=a17c4e'
    to0 = 'To: "Front Desk" <sip:desk@lab.local>'
    to1 = to0 + ';tag=b92e01'
    def pc2_phone(t, payload):
        cap.add(t, eth(PHONE_MAC, PC2_MAC, 0x0800, ipv4(PC2_IP, PHONE_IP, 17, udp(PC2_IP, PHONE_IP, 5060, 5060, payload), ids[0]))); ids[0] += 1
    def phone_pc2(t, payload):
        cap.add(t, eth(PC2_MAC, PHONE_MAC, 0x0800, ipv4(PHONE_IP, PC2_IP, 17, udp(PHONE_IP, PC2_IP, 5060, 5060, payload), pids[0]))); pids[0] += 1
    inv_sdp = sdp(PC2_IP, 16384, 'pc2')
    pc2_phone(t, sip('INVITE sip:desk@lab.local SIP/2.0', [via, 'Max-Forwards: 70', frm, to0, 'Contact: <sip:pc2@192.168.110.60:5060>', 'Call-ID: ' + call_id,
                                                          'CSeq: 1 INVITE', 'Subject: part three', 'User-Agent: LabPhone/2.1', 'Allow: INVITE, ACK, BYE, CANCEL, OPTIONS',
                                                          'Content-Type: application/sdp'], inv_sdp))
    phone_pc2(t + 0.018, sip('SIP/2.0 100 Trying', [via, frm, to0, 'Call-ID: ' + call_id, 'CSeq: 1 INVITE']))
    phone_pc2(t + 0.412, sip('SIP/2.0 180 Ringing', [via, frm, to1, 'Call-ID: ' + call_id, 'CSeq: 1 INVITE', 'Contact: <sip:desk@192.168.110.72:5060>']))
    ok_sdp = sdp(PHONE_IP, 20002, 'desk')
    t_ok = t + 2.351
    phone_pc2(t_ok, sip('SIP/2.0 200 OK', [via, frm, to1, 'Call-ID: ' + call_id, 'CSeq: 1 INVITE', 'Contact: <sip:desk@192.168.110.72:5060>',
                                          'User-Agent: DeskPhone/4.0', 'Content-Type: application/sdp'], ok_sdp))
    pc2_phone(t_ok + 0.004, sip('ACK sip:desk@192.168.110.72:5060 SIP/2.0', [via.replace('3f2a1c', '3f2a1d'), 'Max-Forwards: 70', frm, to1, 'Call-ID: ' + call_id, 'CSeq: 1 ACK']))
    # the audio: 0.4 s of silence, the caller speaks, the desk answers, a little silence, hang up
    t_rtp = t_ok + 0.031
    lead, gap, tail = 0.4, 0.35, 0.5
    total = lead + len(caller) / 8000 + gap + len(callee) / 8000 + tail
    n = int(total * 8000)
    a = bytes([SILENCE]) * int(lead * 8000) + caller
    a += bytes([SILENCE]) * (n - len(a))
    b = bytes([SILENCE]) * (int(lead * 8000) + len(caller) + int(gap * 8000)) + callee
    b += bytes([SILENCE]) * (n - len(b))
    rtp_stream(cap, t_rtp, PC2_MAC, PHONE_MAC, PC2_IP, PHONE_IP, 16384, 20002, 0x1e0f3c2a, 4021, 160000, a, ids[0]); ids[0] += 2000
    rtp_stream(cap, t_rtp + 0.0107, PHONE_MAC, PC2_MAC, PHONE_IP, PC2_IP, 20002, 16384, 0x7a45b19c, 812, 88320, b, pids[0]); pids[0] += 2000
    t_bye = t_rtp + total + 0.25
    pc2_phone(t_bye, sip('BYE sip:desk@192.168.110.72:5060 SIP/2.0', [via.replace('3f2a1c', '3f2a1e'), 'Max-Forwards: 70', frm, to1, 'Call-ID: ' + call_id, 'CSeq: 2 BYE']))
    phone_pc2(t_bye + 0.011, sip('SIP/2.0 200 OK', [via.replace('3f2a1c', '3f2a1e'), frm, to1, 'Call-ID: ' + call_id, 'CSeq: 2 BYE']))

    os.makedirs(PCAPS, exist_ok=True)
    n = cap.write(os.path.join(PCAPS, 'evidence.pcap'))
    with open(os.path.join(SITE, 'answers.js'), 'w') as f:
        f.write('/* answers.js - written by tools/make-evidence.py. Only SHA-256 hashes live here; the flag itself does not.\n'
                ' * Parts are compared after lower-casing and dropping everything but letters and digits; the whole flag\n'
                ' * after lower-casing, trimming, and turning spaces into underscores. */\n')
        f.write('var ANSWERS = {\n  parts: [' + ', '.join("'" + sha(norm_part(p)) + "'" for p in parts) + '],\n')
        f.write("  flag: '" + sha(norm_flag(flag)) + "'\n};\n")
    print('wrote site/pcaps/evidence.pcap:', n, 'packets,', os.path.getsize(os.path.join(PCAPS, 'evidence.pcap')), 'bytes')
    print('wrote site/answers.js (hashes only); photo', len(photo), 'bytes; call', round(total, 2), 's')

if __name__ == '__main__':
    build()
