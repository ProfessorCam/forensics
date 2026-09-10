# Packet Forensics

The fourth site in the Packet Lessons family: a capture-the-flag exercise in network forensics.
One capture from the lab LAN (`evidence.pcap`, 1602 packets, 25 seconds) hides a flag of the form
`epicCTF{...}` in three pieces. Students find each piece with a different technique and assemble
the flag. Every piece has an answer box, and the last row checks the whole flag, against SHA-256
hashes only; the flag itself is not in the site.

Rows: **Exhibit A** (a DNS TXT lookup: filtering), **Exhibit B** (a JPEG fetched over HTTP: TCP
reassembly, object export and EXIF metadata), **Exhibit C** (a SIP phone call with two RTP streams:
signalling, and playing the audio back), **Submit the flag**.

The site has four investigation tools built in, so the case can be solved without installing
anything, and every exhibit also says which Wireshark menu does the same job:

- a **display filter** box on every packet table that understands a subset of Wireshark's language
  (`dns`, `http.request`, `sip`, `rtp`, `ip.addr == ...`, `udp.port == ...`, `dns.txt`,
  `frame contains "text"`, `and`/`or`/`not`, parentheses; the full list is in `site/app.js`);
- **export objects**: rebuilds every HTTP response from its TCP segments, shows images and text,
  lists JPEG metadata (EXIF and comments) and printable strings, and saves the file;
- a **call player**: lists SIP dialogs and RTP streams, decodes G.711 in the browser, plays each
  stream or the mixed call, and saves a `.wav`;
- **answer boxes** that hash what the student typed and compare it with `site/answers.js`.

No frameworks, no build step: plain HTML, CSS and JavaScript. Published to GitHub Pages at
<https://professorcam.github.io/forensics/> by `.github/workflows/pages.yml` on every push to `main`.

## Hint level (Simple | Moderate | Engineer)

The buttons at the top right are the same reading-level toggle as on the other Packet Lessons
sites (`site/level.js`, identical on every site), but on this site they control how much help the
text gives: **Simple** walks through every click, **Moderate** names the filters and menus,
**Engineer** states the protocol facts and nothing else. The choice, and which parts have been
found, are remembered in the browser; `index.html?level=simple` (or `moderate`, `engineer`) opens
the site at a given level.

## Run it on the LAN

```sh
docker compose up -d --build
```

Then open <http://127.0.0.1:8082>. Stop it with `docker compose down`. Or, from Docker Hub, in the foreground
(Ctrl+C stops and removes it):

```sh
docker run --rm -it --name forensics --network host professorcryan/forensics
```

Then open <http://127.0.0.1:8082> on that machine, or `http://<its LAN address>:8082` from another
computer on the LAN. The page must be served over HTTP; opening `site/index.html` from disk does
not work because the browser blocks `fetch()` of the capture from `file://` URLs.

## Changing the flag

The flag is **not** in the repository. `tools/make-evidence.py` reads it from `tools/flag.txt`
(ignored by git): one line, the three parts separated by `|`, for example

```
epicCTF{c4p|tur3d_in_|the_act}
```

- part 1 becomes the TXT answer to the DNS lookup `part1.evidence.lab.local`;
- part 2 becomes the EXIF `ImageDescription` of the photo (`part 2 of 3: ...`);
- part 3 is spoken in the call, plain words: underscores are read as spaces and the closing brace is
  read out loud, so keep it to ordinary words that a listener can spell.

Then:

```sh
python3 tools/make-evidence.py      # needs Pillow, espeak-ng and ffmpeg
```

writes `site/pcaps/evidence.pcap` and `site/answers.js` (hashes only), and leaves the intermediate
photo and audio in `tools/build/` (also ignored). Commit the capture and `answers.js`. Parts are
checked after lower-casing and dropping everything but letters and digits; the whole flag after
lower-casing, trimming, and turning spaces into underscores, so `epicctf{c4ptur3d in the act}`
also passes.

## Layout

```
Dockerfile           nginx:alpine + the site directory
docker-compose.yml   one service, host networking, port 8082
nginx.conf           serves site/, sends the .pcap as a download
site/
  index.html         page shell: left <nav>, right <main>
  style.css          layout, tables, tools, answer boxes
  app.js             nav, lesson rendering, display filter, export objects, call player, answer boxes
  lessons.js         ALL teaching content lives here, one object per row, at three hint levels
  level.js           the Simple | Moderate | Engineer toggle and the lv() text resolver
  pcap.js            libpcap parser (Ethernet, ARP, IPv4, ICMP, UDP, TCP, DNS incl. TXT, DHCP, TFTP, NTP, HTTP, SIP/SDP, RTP)
  answers.js         SHA-256 hashes of the flag and its parts, written by the generator
  pcaps/evidence.pcap
tools/make-evidence.py   builds the photo, the voices and the capture
tools/flag.txt           the flag (not committed)
```

## The capture

Every byte is written by `tools/make-evidence.py`, checksums included, so Wireshark and tcpdump
read it as an ordinary capture. The story: a mirror port copies everything Lab PC 2
(192.168.110.60) sends or receives. ARP for the gateway; a DNS lookup and an NTP exchange; a ping
to the Lab Server (10.10.20.5); `GET /index.html` from photos.lab.local; three more lookups,
one of them TXT; `GET /photos/whiteboard.jpg` (20004 bytes in 14 segments); then a SIP call from a
softphone on Lab PC 2 to the front desk phone (192.168.110.72): INVITE, 100, 180, 200 OK, ACK, two
G.711 µ-law RTP streams of 771 packets each, BYE, 200 OK. The voices are espeak-ng, resampled to
8 kHz by ffmpeg.

```sh
tcpdump -nn -r site/pcaps/evidence.pcap 'not (udp and greater 200)'   # everything but the audio
tshark -r site/pcaps/evidence.pcap -Y dns.txt -T fields -e dns.txt
tshark -r site/pcaps/evidence.pcap --export-objects http,out
tshark -q -r site/pcaps/evidence.pcap -z rtp,streams
```

## Checking the parser from the command line

```sh
node -e '
const {parsePcap}=require("./site/pcap.js"); const fs=require("fs");
const b=fs.readFileSync("site/pcaps/evidence.pcap");
for (const p of parsePcap(b.buffer.slice(b.byteOffset,b.byteOffset+b.byteLength)))
  if (p.proto !== "RTP") console.log(p.no, p.time.toFixed(6), p.src, p.dst, p.proto, p.len, p.info);
'
```
