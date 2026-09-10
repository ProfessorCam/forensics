/*
 * lessons.js - the investigation, one object per row in the left column.
 *
 *   id        short word used in the URL hash (#exhibit-a)
 *   stack     7 or 'flag': groups the left column and sets the chip on the row
 *   chip      text of the small chip on the row (DNS, HTTP, VoIP, flag)
 *   part      0, 1 or 2: which part of the flag this row hides (the answer box checks that part)
 *   title     big label in the left column
 *   subtitle  one line under the title
 *   oneLiner  the whole idea in one sentence
 *   facts     [[label, text], ...] the box under the title
 *   sections  [{ h: heading, p: [paragraphs, may contain <b> <code>], ... }]
 *     steps    - [text...] a numbered list
 *     columns  - [{ h, p: [...], cmd, after }] side-by-side instructions
 *     table    - [[cells...], ...] a small table (first row is the header)
 *     packet   - { file, no, note }: one frame from the capture, shown opened
 *     tool     - 'objects' (rebuild files sent over HTTP), 'voip' (list and play calls),
 *                'part' with part: N (answer box for one part), 'flag' (answer box for the whole flag)
 *     after    - paragraphs shown below all of the above
 *   actors    [{ name, addr }] columns of the sequence diagram, left to right
 *   steps     [{ from, to, label, dashed }] to: actor index
 *   lookFor   bullets pointing at concrete things in the packets
 *   captures  [{ file, title, filter, hint }] packet tables at the bottom, each with a display filter preset
 *
 * Reading levels: any prose may be a plain string (the same at every level) or { s, m, e } for
 * Simple / Moderate / Engineer. On this site the levels are hint levels: Simple walks through every
 * click, Moderate names the filters and menus, Engineer states the protocol facts and nothing else.
 * A missing key falls back to m; '' leaves that paragraph out at that level. Refer to other rows as
 * {{row:id}} / {{Row:id}}, which becomes the row's title in quotes when drawn. See level.js.
 */
var SITE = {
  title: 'Packet Forensics',
  image: 'professorcryan/forensics',    /* Docker Hub image of this site */
  port: 8082,
  labNetwork: '192.168.110.0/23',
  /* The machines that appear in the capture. */
  hosts: [
    { name: 'Lab PC 2', mac: '00:0c:29:7d:e3:5c', ip: '192.168.110.60', role: 'the machine under investigation: every packet in the file goes to or from it' },
    { name: 'Gateway', mac: '00:50:56:c0:00:01', ip: '192.168.110.1', role: 'the router, and the LAN’s DNS and NTP server' },
    { name: 'Lab Server', mac: '00:0c:29:a1:b2:c3', ip: '10.10.20.5', role: 'web server on the far network (photos.lab.local), reached through the gateway' },
    { name: 'Front desk phone', mac: '00:0c:29:9e:77:10', ip: '192.168.110.72', role: 'a desk phone on the LAN (desk.lab.local)' },
    { name: 'Student VM', mac: '00:0c:29:4b:1f:a2', ip: '192.168.110.50', role: 'recorded the capture from the switch’s mirror port; sends nothing itself' }
  ],
  /* Top menu. current: true marks the site you are on. */
  menu: [
    { label: 'Frames & Packets', href: 'https://professorcam.github.io/frames/' },
    { label: 'Protocols', href: 'https://professorcam.github.io/pcap/' },
    { label: 'Encryption and Protocols', href: 'https://professorcam.github.io/encryption/' },
    { label: 'Packet Forensics', href: '#', current: true }
  ],
  welcome: {
    lead: {
      s: 'One recording from the lab network. Someone moved a secret out in three pieces. Find the pieces, put them together, and you have the flag.',
      m: 'A single capture from the lab LAN holds three pieces of a flag: one in a DNS answer, one inside a photo fetched over HTTP, one spoken in a phone call. Find all three and assemble them.',
      e: 'One libpcap file: 1602 frames, 25 seconds, taken from a mirror port on the lab LAN. Three flag fragments: a DNS TXT record, an EXIF field in a JPEG carried over HTTP, and speech in a G.711 RTP stream set up by SIP.'
    },
    story: [
      { s: 'On 8 September at 14:07 the lab switch was told to copy everything that Lab PC 2 sent or received to the Student VM, which recorded it all into one file: <code>evidence.pcap</code>. Somebody at Lab PC 2 was sneaking a secret out of the lab. They were careful: no single packet gives the whole thing away. They split it into three pieces and hid each one in a different kind of traffic.',
        m: 'On 8 September at 14:07 a mirror (SPAN) port on the lab switch copied all traffic to and from Lab PC 2 (192.168.110.60) to the Student VM, which saved it as <code>evidence.pcap</code>. Someone at Lab PC 2 exfiltrated a secret in three pieces, each hidden in a different protocol so that no single packet, and no single filter, reveals all of it.',
        e: 'Capture point: mirror port, so both directions of everything Lab PC 2 sent or received, no traffic of the capturing host itself. 25 seconds; ARP, NTP, ICMP, five DNS transactions, two HTTP connections, one SIP dialog with two RTP streams. The flag was split into three fragments carried by DNS, HTTP and RTP respectively.' },
      'The flag has the form <code>epicCTF{...}</code>. Each exhibit below hides one piece of it. Each has an answer box, so you can confirm a piece as soon as you find it, and the last row checks the whole flag.'
    ],
    rows: [
      ['Exhibit A', 'A DNS lookup that answers too much. Ten packets, one filter, and the first piece is sitting in plain text.'],
      ['Exhibit B', 'A photo fetched over HTTP. Rebuild the file from its fourteen segments and read what is written inside it.'],
      ['Exhibit C', 'A phone call on the LAN. Turn 1542 packets of audio back into sound and listen.'],
      ['Submit the flag', 'Put the three pieces together in order.']
    ],
    levels: '<b>Hint level.</b> On this site the <b>Simple</b>, <b>Moderate</b> and <b>Engineer</b> buttons at the top right change how much help you get. Simple walks you through every click. Moderate names the filters and menus and leaves the clicking to you. Engineer gives you the protocol facts and nothing else. Your choice, and the pieces you have found, are remembered on this browser.',
    machinesNote: 'The addresses are the same lab network as the other Packet Lessons sites. Lab Server is on the far side of the gateway, so its packets carry the gateway’s MAC address on this LAN; everything else is directly on the LAN.',
    onPage: [
      { s: 'Every packet table on this site has a <b>display filter</b> box, like the green bar in Wireshark. Type <code>dns</code> and press Apply and only the DNS packets remain. Exhibit B has a tool that glues files back together from their packets. Exhibit C has a player that turns the audio packets back into sound. You can solve the whole case without installing anything.',
        m: 'Every packet table has a display filter box that understands a subset of Wireshark’s language: protocol names (<code>dns</code>, <code>http</code>, <code>sip</code>, <code>rtp</code>), fields such as <code>ip.addr == 192.168.110.72</code>, <code>udp.port == 5060</code>, <code>http.request</code>, <code>dns.txt</code>, <code>frame contains "text"</code>, and <code>and</code>, <code>or</code>, <code>not</code>. Exhibit B rebuilds the files carried over HTTP and reads their metadata. Exhibit C lists the calls and plays the audio. Click any packet to open it layer by layer.',
        e: 'Client-side libpcap parser (<code>pcap.js</code>), filter subset documented in <code>app.js</code>, TCP reassembly by sequence number, EXIF IFD0 walk, G.711 decode into an <code>AudioBuffer</code> at 8 kHz. No server side.' }
    ],
    inWireshark: [
      { s: 'Press <b>Download .pcap</b> below and open the file in Wireshark. Everything on this site can be done there too, and each exhibit tells you exactly which menu to use.',
        m: 'Download the capture and open it in Wireshark. The same filters work in the green bar. <b>File → Export Objects → HTTP</b> rebuilds files; <b>Telephony → VoIP Calls</b> plays the call; <b>Analyze → Follow → TCP Stream</b> shows a whole conversation as text. Each exhibit names the menu it needs.',
        e: 'Classic pcap, link type 1, all checksums valid. Wireshark: <code>dns.txt</code>, Export Objects → HTTP, Telephony → RTP → RTP Streams; tshark: <code>tshark -r evidence.pcap -Y dns.txt -T fields -e dns.txt</code>, <code>--export-objects http,dir</code>, <code>-z rtp,streams</code>.' }
    ],
    captureHint: {
      s: 'This is the whole recording, all 1602 packets. Most of them are the phone call. Type <code>dns</code> in the filter box and press Apply to see how much smaller the haystack gets. Press Clear to get everything back.',
      m: 'The whole capture. Try the filter box: <code>dns</code>, <code>http</code>, <code>sip</code>, <code>rtp</code>, <code>ip.addr == 192.168.110.72</code>, or <code>not rtp</code> to hide the audio and see the 60 packets that are left.',
      e: 'All 1602 frames; 1542 are RTP. <code>not rtp</code> leaves the 60 that matter.'
    }
  }
};

var FILES = {
  evidence: 'evidence.pcap'
};

var LESSONS = [
  /* ================================================================== A: DNS */
  {
    id: 'exhibit-a',
    stack: 7,
    chip: 'DNS',
    part: 0,
    title: 'Exhibit A',
    subtitle: 'A lookup that answers too much',
    oneLiner: {
      s: 'A computer asked the name server a question, and the answer was the first piece of the secret.',
      m: 'Lab PC 2 sent five DNS lookups. One asked for a TXT record, and the answer is the first part of the flag in plain text.',
      e: 'Five DNS transactions to 192.168.110.1. One query has qtype 16 (TXT); the RDATA of its response is fragment 1.'
    },
    facts: [
      ['Protocol', 'DNS over UDP port 53'],
      ['Filter', '<code>dns</code>, then <code>dns.txt</code>'],
      ['Skill', { s: 'Filtering: making 1602 packets into 10', m: 'Display filters; reading a DNS answer', e: 'dns.qry.type == 16' }]
    ],
    sections: [
      { h: 'What happened',
        p: [
          { s: 'Before a computer can talk to a name like <code>photos.lab.local</code> it has to ask the name server which address that name means. That question and its answer are DNS. Most DNS answers are addresses. But DNS can also carry a line of plain text, in a kind of record called <b>TXT</b>, and that is where somebody put the first piece.',
            m: 'DNS lookups are normally for <b>A</b> records: a name in, an IPv4 address out. A <b>TXT</b> record carries free text instead. Legitimate uses include mail policy (SPF) and proving you own a domain. Because almost nobody looks at them, TXT records are a favourite hiding place for anything small, and a classic first step in DNS-based exfiltration: the "server" that answers is under the attacker’s control, so it can say whatever it likes.',
            e: 'Five queries, all UDP/53 from Lab PC 2 to the gateway, all answered with rcode 0. Four are qtype 1 (A). One is qtype 16 (TXT) for <code>part1.evidence.lab.local</code>; its response carries a single 24-byte character-string. RFC 1035 §3.3.14: TXT RDATA is one or more length-prefixed &lt;character-string&gt;s of up to 255 bytes.' },
          { s: 'The lookup happened about three and a half seconds into the recording, just before the photo was downloaded. Everything on this row is about finding that one answer.',
            m: 'The TXT lookup is at 3.54 s, between a lookup for <code>evidence.lab.local</code> and one for the desk phone. The transaction ID (0x1a2e) ties the query to its answer.',
            e: 'Frames 22 and 23, txid 0x1a2e, sport 40114. Response flags 0x8180 (QR, RD, RA), one answer RR, TTL 300.' }
        ] },
      { h: 'Where to look',
        p: [
          { s: 'Follow these steps on this page (the packet table is at the bottom of this row) or in Wireshark; they are the same.', m: '', e: '' },
          { s: '', m: 'Start wide, then narrow. <code>dns</code> leaves ten packets: five questions and five answers. The Info column already shows the record type of each. <code>dns.txt</code> (on this page) or <code>dns.qry.type == 16</code> (Wireshark) leaves the one that matters. Open the response and read the answer section.', e: '' },
          { s: '', m: '', e: 'Filter <code>dns.txt</code> (page) or <code>dns.qry.type == 16</code> (Wireshark). The RDATA is in the answer section of the response; Wireshark shows it as <code>dns.txt</code>, tshark prints it with <code>-T fields -e dns.txt</code>.' }
        ],
        steps: [
          { s: 'Type <code>dns</code> in the display filter box and press <b>Apply</b>. In Wireshark, type it in the green bar and press Enter. Ten packets remain.', m: '', e: '' },
          { s: 'Read the <b>Info</b> column. Every query line says <code>A</code> except one, which says <code>TXT</code>. The line under it is its answer (same number after "response").', m: '', e: '' },
          { s: 'Click the answer packet. Open the <b>Domain Name System</b> section. The <b>Answer</b> row shows the text between quotes.', m: '', e: '' },
          { s: 'The piece you need starts with <code>epicCTF{</code> and runs to the end of the text. Type it into the box below to check it.', m: '', e: '' }
        ] },
      { h: 'In Wireshark and on this page',
        columns: [
          { h: 'In Wireshark', p: [
            { s: 'Open <code>evidence.pcap</code>, type <code>dns</code> in the green filter bar, press Enter. Click the TXT response; expand Domain Name System, then Answers.',
              m: 'Filter <code>dns.qry.type == 16</code>. Expand Domain Name System → Answers in the packet details. Or right-click the TXT field → Apply as Column to see it in the list.',
              e: '<code>dns.txt</code> as a column, or <code>tshark -r evidence.pcap -Y dns.txt -T fields -e dns.qry.name -e dns.txt</code>.' } ] },
          { h: 'On this page', p: [
            { s: 'The table at the bottom of this row already has <code>dns</code> in its filter box. Click the packet whose Info says <code>TXT</code> and ends with a quoted text.',
              m: 'The table below is pre-filtered on <code>dns</code>; change it to <code>dns.txt</code> to isolate the answer. Clicking a row opens the decoded record.',
              e: 'Table below, filter <code>dns.txt</code>.' } ] }
        ] },
      { h: 'Check part 1', tool: 'part', part: 0,
        p: [{ s: 'Type exactly what you found, starting with <code>epicCTF{</code>. Capital letters and spaces do not matter here.', m: 'Everything from <code>epicCTF{</code> onwards. Case does not matter.', e: 'From <code>epicCTF{</code> to the end of the string.' }] }
    ],
    actors: [{ name: 'Lab PC 2', addr: '192.168.110.60' }, { name: 'Gateway (DNS)', addr: '192.168.110.1' }],
    steps: [
      { from: 0, to: 1, label: 'A? updates.lab.local' }, { from: 1, to: 0, label: 'A 10.10.20.5', dashed: true },
      { from: 0, to: 1, label: 'A? photos.lab.local' }, { from: 1, to: 0, label: 'A 10.10.20.5', dashed: true },
      { from: 0, to: 1, label: 'A? evidence.lab.local' }, { from: 1, to: 0, label: 'A 10.10.20.5', dashed: true },
      { from: 0, to: 1, label: 'TXT? part1.evidence.lab.local' }, { from: 1, to: 0, label: 'TXT "part 1 of 3: ..."', dashed: true },
      { from: 0, to: 1, label: 'A? desk.lab.local' }, { from: 1, to: 0, label: 'A 192.168.110.72', dashed: true }
    ],
    lookFor: [
      { s: 'Each question and its answer share the same transaction number, so you can pair them up.', m: 'Query and response share a transaction ID (0x1a2b to 0x1a2f); the response has the QR flag set.', e: 'txid 0x1a2b–0x1a2f; flags 0x0100 out, 0x8180 back; source port changes per query (40111–40115).' },
      { s: 'The answer to the TXT question is the only DNS packet that contains quotation marks.', m: 'The TXT response is 121 bytes, the longest DNS packet in the file: the text is carried inside it.', e: 'Frame 23: 121 bytes on the wire, RDLENGTH 25 (one length byte plus 24 characters).' },
      { s: 'All five questions go to the gateway. It is the name server for this network.', m: 'All lookups go to 192.168.110.1, the gateway, which is also the LAN’s resolver (compare the DHCP row on the Protocols site).', e: 'Resolver 192.168.110.1; answers are authoritative-looking (AA not set, RA set) with TTL 300.' }
    ],
    captures: [{ file: 'evidence.pcap', title: 'The DNS packets', filter: 'dns',
      hint: { s: 'The filter box already says <code>dns</code>, so only the ten DNS packets are shown. Press Clear to see all 1602 again.', m: 'Pre-filtered on <code>dns</code>. Try <code>dns.txt</code>, <code>dns.qry.name contains evidence</code>, or <code>dns.flags.response == 1</code>.', e: 'Filter <code>dns</code>; 10 of 1602.' } }]
  },

  /* ================================================================== B: HTTP + JPEG */
  {
    id: 'exhibit-b',
    stack: 7,
    chip: 'HTTP',
    part: 1,
    title: 'Exhibit B',
    subtitle: 'A photo fetched over HTTP',
    oneLiner: {
      s: 'The computer downloaded a photo. The picture is innocent; the note hidden inside the file is not.',
      m: 'Lab PC 2 fetched whiteboard.jpg over HTTP. The image arrived in fourteen TCP segments. Rebuild the file and read its EXIF metadata.',
      e: 'GET /photos/whiteboard.jpg, 200 OK, 20004-byte image/jpeg body in 14 segments (13 × 1460 + 1243). Fragment 2 is EXIF IFD0 tag 0x010E, ImageDescription.'
    },
    facts: [
      ['Protocol', 'HTTP/1.1 over TCP port 80'],
      ['Filter', '<code>http</code>, then <code>tcp.port == 49211</code>'],
      ['Skill', { s: 'Gluing a file back together, and reading its hidden labels', m: 'TCP reassembly, Export Objects, EXIF metadata', e: 'Stream reassembly; JPEG APP1/TIFF IFD0 parsing' }]
    ],
    sections: [
      { h: 'What happened',
        p: [
          { s: 'A photo of 20,000 bytes does not fit in one packet, so the web server cut it into fourteen pieces and TCP numbered them. Wireshark, and this page, can glue the pieces back into the file. Photos also carry hidden labels called <b>metadata</b>: the camera, the date, and sometimes a written comment. That is where the second piece went.',
            m: 'The browser on Lab PC 2 loaded <code>photos.lab.local/index.html</code> and then the whiteboard photo it links to. HTTP sends the file as a stream of bytes inside TCP; each segment carries up to 1460 bytes, the MSS agreed in the handshake. Reassembly puts the segments back in sequence-number order and cuts the HTTP headers off the front. A JPEG can carry <b>EXIF</b> metadata in a segment near the start of the file: camera make and model, timestamps, sometimes GPS, and free-text fields such as <b>ImageDescription</b>.',
            e: 'Two TCP connections to 10.10.20.5:80 from client ports 49210 (index.html, 511-byte response) and 49211 (the JPEG). Second connection: three-way handshake with MSS 1460, GET with Referer, 200 OK with Content-Length 20004, 14 data segments (PSH on the last), delayed ACKs every second segment, client FIN 0.9 s later. File layout: SOI, APP1 "Exif\\0\\0", TIFF header (II), IFD0 with ImageDescription, Make, Model, Software, DateTime, Artist.' },
          { s: 'Look at the picture too. It is a photo of the lab whiteboard, and nothing on it is the answer. The answer is in the file, not in the picture.',
            m: 'The image content is a red herring: a whiteboard with the lab topology. The fragment is in the file’s metadata, which never appears on screen.',
            e: 'Pixels are irrelevant. ImageDescription value at file offset 116, inside the first segment; the whole EXIF block fits in the first 1460 bytes after the headers.' }
        ] },
      { h: 'Where to look',
        p: [
          { s: '', m: 'Filter <code>http</code> to see the two requests and their responses. The response to <code>GET /photos/whiteboard.jpg</code> is what you need, but it is fourteen packets long. Let Wireshark or this page reassemble it, then read the EXIF ImageDescription. Three ways in Wireshark: Export Objects, the decoded JPEG tree on the reassembled packet, or Follow TCP Stream.', e: '' },
          { s: '', m: '', e: 'Frame 30 (the 200 OK) is where Wireshark shows the reassembled body; the JFIF dissector decodes the EXIF IFD entries in place. Export Objects writes the file; <code>exiftool -ImageDescription</code> or <code>strings</code> reads it. <code>tcp.stream eq 1</code> isolates the connection.' }
        ],
        steps: [
          { s: 'On this page: scroll to <b>Files carried over HTTP</b> below. It lists every file that crossed the wire. Press <b>Show</b> next to <code>/photos/whiteboard.jpg</code>.', m: '', e: '' },
          { s: 'Under <b>Metadata inside the file</b>, read the line <b>EXIF ImageDescription</b>. The same text is also in the <b>Printable text</b> list, which is what the <code>strings</code> command would print.', m: '', e: '' },
          { s: 'In Wireshark instead: <b>File → Export Objects → HTTP</b>, click <code>whiteboard.jpg</code>, <b>Save</b>. Then run <code>exiftool whiteboard.jpg</code> or <code>strings whiteboard.jpg | head</code>, or open the file’s properties in your image viewer.', m: '', e: '' },
          { s: 'The piece is everything after "part 2 of 3:". Type it into the box below.', m: '', e: '' }
        ] },
      { h: 'In Wireshark and on this page',
        columns: [
          { h: 'In Wireshark', p: [
            { s: '<b>File → Export Objects → HTTP</b> shows a list with <code>index.html</code> and <code>whiteboard.jpg</code>. Save the photo and look at its details.',
              m: 'Export Objects → HTTP, or click frame 30 and expand <b>JPEG File Interchange Format → Exif</b>: Wireshark decodes IFD entries, including ImageDescription. Or <b>Analyze → Follow → TCP Stream</b> on any packet of the connection and read the server side as text.',
              e: '<code>tshark -r evidence.pcap --export-objects http,out</code>; <code>exiftool out/whiteboard.jpg</code>. Or Follow TCP Stream, show data as Raw, save server side, strip 236 bytes of headers.' } ],
            cmd: 'exiftool whiteboard.jpg\nstrings whiteboard.jpg | head' },
          { h: 'On this page', p: [
            { s: 'The tool below has already rebuilt both files. Press <b>Show</b> on the photo to see it, its metadata, and its text.',
              m: 'The tool below reassembles each server response by TCP sequence number, splits headers from body, and for JPEGs walks the EXIF IFD. <b>Save</b> gives you the file for exiftool.',
              e: 'Reassembly by seq, duplicates dropped; Content-Length honoured; EXIF IFD0 and Exif sub-IFD ASCII tags listed.' } ] }
        ] },
      { h: 'Files carried over HTTP', tool: 'objects',
        p: [{ s: 'Every response the web server sent, glued back together from its packets.', m: 'Every HTTP response in the capture, rebuilt from its segments. Show renders it and lists its metadata; Save downloads it.', e: 'HTTP objects, reassembled.' }] },
      { h: 'Check part 2', tool: 'part', part: 1,
        p: [{ s: 'Type the text after "part 2 of 3:". Underscores and capitals do not matter here.', m: 'The text after the label. Case and underscores are ignored by this check, but you will need the underscores for the final flag.', e: 'The ImageDescription value after the label.' }] }
    ],
    actors: [{ name: 'Lab PC 2', addr: '192.168.110.60 : 49211' }, { name: 'Lab Server', addr: '10.10.20.5 : 80' }],
    steps: [
      { from: 0, to: 1, label: 'SYN' }, { from: 1, to: 0, label: 'SYN, ACK' }, { from: 0, to: 1, label: 'ACK' },
      { from: 0, to: 1, label: 'GET /photos/whiteboard.jpg' },
      { from: 1, to: 0, label: '200 OK + first 1460 bytes of the JPEG' },
      { from: 1, to: 0, label: '13 more segments, 1460 bytes each (1243 in the last)' },
      { from: 0, to: 1, label: 'ACK every second segment', dashed: true },
      { from: 0, to: 1, label: 'FIN, ACK (0.9 s later)' }, { from: 1, to: 0, label: 'FIN, ACK' }, { from: 0, to: 1, label: 'ACK' }
    ],
    lookFor: [
      { s: 'The first packet of the answer says "200 OK" and "image/jpeg". The next thirteen just say "Continuation": more of the same file.', m: 'Frame 30 carries the status line and headers plus the first bytes of the file; frames 31 to 49 are continuation segments. Content-Length in the headers (20004) tells the client when the file is complete.', e: 'Response headers 236 bytes; body starts mid-frame 30 at seq 237; last segment ends at seq 20241 (relative). Content-Length 20004 = 20241 − 237.' },
      { s: 'The client says "got it" only every second piece. That is normal; it saves packets.', m: 'The client ACKs every second segment (delayed ACK); the ACK numbers climb by 2920 each time.', e: 'Ack 2921, 5841, 8761 ... every second segment, final ACK 20225 covers the FIN.' },
      { s: 'The web page fetched just before (index.html) lists the photo. That is how the browser found it.', m: 'The first connection (port 49210) fetched <code>/index.html</code>, whose HTML links to the photo; the second request carries a matching <code>Referer</code> header.', e: 'Stream 0: GET /index.html, 511-byte text/html. Stream 1: Referer: http://photos.lab.local/index.html. Both keep-alive, client-initiated close.' }
    ],
    captures: [{ file: 'evidence.pcap', title: 'The web traffic', filter: 'http',
      hint: { s: 'The filter box says <code>http</code>: two requests and two "200 OK" answers. Change it to <code>tcp.port == 49211</code> to see all 28 packets of the photo download, handshake and goodbye included.', m: 'Pre-filtered on <code>http</code>. Try <code>tcp.port == 49211</code> for the whole connection, <code>http.request</code> for requests only, or <code>frame contains "part 2"</code>.', e: 'Filter <code>http</code>; the connection is <code>tcp.port == 49211</code>.' } }]
  },

  /* ================================================================== C: SIP + RTP */
  {
    id: 'exhibit-c',
    stack: 7,
    chip: 'VoIP',
    part: 2,
    title: 'Exhibit C',
    subtitle: 'A phone call on the LAN',
    oneLiner: {
      s: 'Someone made a phone call over the network and said the last piece out loud. The sound is in the packets, and you can play it back.',
      m: 'Lab PC 2 called the front desk phone. SIP set the call up and RTP carried the voice, 771 packets each way. Play the caller’s stream and listen.',
      e: 'SIP dialog on UDP/5060 (INVITE, 100, 180, 200, ACK; BYE, 200). SDP offers PCMU on 192.168.110.60:16384, answer 192.168.110.72:20002. Two RTP streams, PT 0, 20 ms per packet, 15.4 s, no loss. Fragment 3 is spoken, plain words.'
    },
    facts: [
      ['Protocols', 'SIP and SDP on UDP port 5060; RTP on UDP ports 16384 and 20002'],
      ['Filter', '<code>sip</code> for the set-up, <code>rtp</code> for the audio'],
      ['Skill', { s: 'Turning packets back into sound', m: 'Reading a SIP dialog; playing RTP audio', e: 'SDP media negotiation; G.711 decode' }]
    ],
    sections: [
      { h: 'What happened',
        p: [
          { s: 'A phone call over a network is two things. First a short exchange that sets the call up: "I want to call you", "ringing", "answered", and at the end "hang up". That is <b>SIP</b>. Then a river of tiny packets carrying the sound, fifty every second in each direction. That is <b>RTP</b>. Each sound packet holds twenty thousandths of a second of voice. Put them in order and you have the recording.',
            m: '<b>SIP</b> is the signalling: an <b>INVITE</b> from the softphone on Lab PC 2 to the desk phone, <b>100 Trying</b>, <b>180 Ringing</b> while it rang, <b>200 OK</b> when the desk picked up, and an <b>ACK</b>. The <b>SDP</b> body inside the INVITE and the 200 OK tells each side where to send audio (an IP address and UDP port) and in which codec (PCMU, that is G.711 µ-law). <b>RTP</b> then carries the audio: 160 samples, 20 ms, per packet, with a sequence number to spot loss and a timestamp to keep the timing. <b>BYE</b> ends the call.',
            e: 'INVITE sip:desk@lab.local from "Lab PC 2" &lt;sip:pc2@lab.local&gt; to "Front Desk", Subject: part three, Call-ID 6b8d2f1e4a@192.168.110.60. Offer: c=IN IP4 192.168.110.60, m=audio 16384 RTP/AVP 0 101. Answer in the 200 OK: 192.168.110.72:20002. RTP v2, PT 0, SSRC 0x1e0f3c2a (caller) and 0x7a45b19c (callee), 771 packets each, seq +1 and timestamp +160 per packet, marker on the first. Caller speaks from about 0.4 s in; the callee answers near the end.' },
          { s: 'The person at Lab PC 2 read the last piece out loud to the front desk. It is two ordinary words. You will hear them twice.',
            m: 'The caller reads the fragment aloud, twice, as two plain words, and says where the closing brace goes. The Subject header of the INVITE is not subtle.',
            e: 'Fragment 3 is in the caller stream (SSRC 0x1e0f3c2a), plain English, repeated. Write the words with an underscore between them, followed by the closing brace.' }
        ] },
      { h: 'Where to look',
        p: [
          { s: '', m: 'Filter <code>sip</code> to see the seven packets of set-up and tear-down; the INVITE tells you who called whom and where the audio will go. Then play the audio: on this page, the player below; in Wireshark, <b>Telephony → VoIP Calls</b>, select the call, <b>Play Streams</b>. Wireshark decodes G.711 itself.', e: '' },
          { s: '', m: '', e: 'Telephony → RTP → RTP Streams, select the 192.168.110.60:16384 stream, Analyze, Play. Or the player below. Payload is raw G.711 µ-law, 8 kHz, 8 bits: dumping the payloads in sequence order to a file and <code>sox -t ul -r 8000 caller.ul caller.wav</code> works too.' }
        ],
        steps: [
          { s: 'Turn your sound on. Scroll down to <b>The call</b>. Under <b>Audio streams</b> press <b>Play</b> on the stream <b>from 192.168.110.60</b> (the caller), or press <b>Play the whole call</b>.', m: '', e: '' },
          { s: 'Listen for "part three of the flag is two words". Write the two words down with an underscore between them, then add the closing curly brace <code>}</code>.', m: '', e: '' },
          { s: 'In Wireshark instead: <b>Telephony → VoIP Calls</b>, tick the call, press <b>Play Streams</b>, then the play button. If the list is empty, make sure the file was opened in classic pcap format.', m: '', e: '' },
          { s: 'Type the two words (with or without the underscore) into the box below.', m: '', e: '' }
        ] },
      { h: 'In Wireshark and on this page',
        columns: [
          { h: 'In Wireshark', p: [
            { s: '<b>Telephony → VoIP Calls</b> lists the call with who called whom. <b>Play Streams</b> opens a player with both sides.',
              m: 'Telephony → VoIP Calls → Play Streams, or Telephony → RTP → RTP Streams → Analyze → Play. Flow Sequence draws the SIP ladder. Filter <code>sip</code> and open the INVITE to read the SDP.',
              e: 'VoIP Calls; RTP Streams (jitter, delta, lost); <code>tshark -q -z rtp,streams</code>; <code>-z sip,stat</code>.' } ] },
          { h: 'On this page', p: [
            { s: 'The player below found the call and its two audio streams. Press Play and listen.',
              m: 'The player lists SIP dialogs (from, to, subject, timing) and RTP streams (SSRC, codec, packets, loss). Play decodes G.711 in the browser; Save .wav gives you the audio file.',
              e: 'G.711 µ-law table decode into a mono 8 kHz AudioBuffer; streams placed by RTP timestamp, mixed by arrival time.' } ] }
        ] },
      { h: 'The call', tool: 'voip',
        p: [{ s: 'Everything the page found about the phone call.', m: 'The SIP dialog and the RTP streams, with a player.', e: 'SIP dialogs and RTP streams.' }] },
      { h: 'Check part 3', tool: 'part', part: 2,
        p: [{ s: 'Type the two words you heard. With or without the underscore, with or without the brace: this box does not mind.', m: 'The two spoken words. Case, spaces, underscores and the brace are ignored by this check.', e: 'The spoken words.' }] }
    ],
    actors: [{ name: 'Lab PC 2 (softphone)', addr: '192.168.110.60' }, { name: 'Front desk phone', addr: '192.168.110.72' }],
    steps: [
      { from: 0, to: 1, label: 'INVITE sip:desk@lab.local (SDP: audio to .60:16384)' },
      { from: 1, to: 0, label: '100 Trying', dashed: true },
      { from: 1, to: 0, label: '180 Ringing', dashed: true },
      { from: 1, to: 0, label: '200 OK (SDP: audio to .72:20002)' },
      { from: 0, to: 1, label: 'ACK' },
      { from: 0, to: 1, label: 'RTP: 771 packets of G.711, 20 ms each' },
      { from: 1, to: 0, label: 'RTP: 771 packets back' },
      { from: 0, to: 1, label: 'BYE' },
      { from: 1, to: 0, label: '200 OK', dashed: true }
    ],
    lookFor: [
      { s: 'The INVITE packet has a Subject line, like an email. Read it.', m: 'The INVITE carries <code>Subject: part three</code>, plus From, To and Call-ID headers that tie all seven SIP packets together.', e: 'Call-ID 6b8d2f1e4a@192.168.110.60 on all seven; CSeq 1 INVITE / 1 ACK / 2 BYE; To gets a tag from 180 onwards.' },
      { s: 'The desk phone rang for about two seconds (180 Ringing to 200 OK) before someone answered.', m: '180 Ringing at 7.41 s, 200 OK at 9.35 s: the desk rang for about two seconds. Audio starts 30 ms after the ACK.', e: 'INVITE 7.000 s, 180 at +0.412, 200 at +2.351, ACK +0.004, first RTP +0.035. BYE at 25.05 s.' },
      { s: 'Each audio packet is 214 bytes: 160 of them are sound, the rest is addressing.', m: 'Each RTP packet is 214 bytes on the wire: 14 Ethernet + 20 IP + 8 UDP + 12 RTP + 160 bytes of audio. 50 packets a second per direction is 85.6 kbit/s each way.', e: '160-byte payload, 20 ms ptime, 12-byte RTP header, no CSRC, no extension. 771 packets, seq 4021–4791 and 812–1582, timestamps +160 per packet: no loss, no jitter to speak of.' },
      { s: 'Sound packets have a running number. If a number were missing, part of the sound would be gone. Here none is.', m: 'Sequence numbers are contiguous and the Lost column in the player says 0, so the recording is complete.', e: 'Expected = received = 771 per SSRC.' }
    ],
    captures: [{ file: 'evidence.pcap', title: 'The signalling', filter: 'sip',
      hint: { s: 'The filter box says <code>sip</code>: the seven packets that set up and end the call. Change it to <code>rtp</code> to see the 1542 sound packets (the table folds most of them away).', m: 'Pre-filtered on <code>sip</code>. Try <code>rtp</code>, <code>rtp.marker == 1</code> for the first packet of each stream, <code>rtp.ssrc == 0x1e0f3c2a</code> for the caller only, or <code>sdp</code> for the two packets that carry media descriptions.', e: 'Filter <code>sip</code>; <code>rtp.ssrc == 0x1e0f3c2a</code> is the caller.' } }]
  },

  /* ================================================================== the verdict */
  {
    id: 'verdict',
    stack: 'flag',
    chip: 'flag',
    title: 'Submit the flag',
    subtitle: 'Put the three parts together',
    oneLiner: { s: 'Three pieces, one flag.', m: 'Join the three parts in order: DNS, then the photo, then the call.', e: 'Concatenate fragments 1, 2 and 3.' },
    facts: [
      ['Format', '<code>epicCTF{...}</code>, words joined by underscores'],
      ['Order', '{{row:exhibit-a}}, then {{row:exhibit-b}}, then {{row:exhibit-c}}']
    ],
    sections: [
      { h: 'Assemble it',
        p: [
          { s: 'Write the three pieces one after the other with nothing in between: the DNS piece (it starts with <code>epicCTF{</code>), then the piece from the photo, then the two spoken words joined by an underscore, then the closing brace <code>}</code>. Capital letters do not matter.',
            m: 'Fragment 1 begins with <code>epicCTF{</code>, fragment 2 follows immediately (it ends with an underscore), and fragment 3 is the two spoken words joined by an underscore, then <code>}</code>. The check ignores case and turns spaces into underscores.',
            e: 'flag = f1 + f2 + f3; f3 = spoken words joined by "_", then "}". Compared case-insensitively after whitespace → underscore.' }
        ], tool: 'flag' },
      { h: 'What you practised',
        p: [{ s: 'Three ways of finding something in a pile of packets, and each of them is a real forensics skill.', m: 'Three techniques that come up in every network forensics case:', e: 'Techniques exercised:' }],
        steps: [
          { s: '<b>Filtering.</b> 1602 packets became 10 with one word. Filters are how you find anything in a real capture, which can have millions.', m: '<b>Display filters</b> by protocol and field: the difference between a haystack and a needle.', e: 'Display filters; qtype-based DNS filtering.' },
          { s: '<b>Rebuilding files.</b> Big things are cut into packets. Wireshark can glue them back. Then the file has its own secrets: its metadata.', m: '<b>TCP reassembly and object export</b>, then <b>file metadata</b> (EXIF): the file is evidence, and so is what is written inside it.', e: 'TCP stream reassembly; HTTP object extraction; EXIF/TIFF IFD parsing.' },
          { s: '<b>Playing back a call.</b> Voice over the network is just packets too, and unencrypted voice can be listened to by anyone who captured it.', m: '<b>VoIP reconstruction</b>: SIP tells you who called whom, SDP tells you where the audio is, RTP is the audio. Unencrypted RTP is a recording of the call.', e: 'SIP/SDP dialog analysis; RTP stream extraction and G.711 decode.' }
        ] },
      { h: 'Go further',
        p: [{ s: 'Things to try in Wireshark on the same file, now that you know what is in it.', m: 'The same file has more to teach. In Wireshark, try:', e: 'On the same file:' }],
        steps: [
          { s: '<b>Statistics → Conversations</b>: a table of who talked to whom and how much. The phone call dominates.', m: '<b>Statistics → Conversations</b> and <b>Protocol Hierarchy</b>: the shape of the capture at a glance, before any filter.', e: 'Conversations (UDP tab: two RTP flows, 165 KB each); Protocol Hierarchy.' },
          { s: '<b>Right-click a packet → Follow → TCP Stream</b>: the whole web conversation as text, request in red, answer in blue.', m: '<b>Follow TCP Stream</b> on the photo download: headers in text, then the JPEG bytes; switch "Show data as" to Raw and save the server side.', e: 'Follow TCP Stream, stream 1, server direction, Raw.' },
          { s: '<b>Telephony → RTP → RTP Stream Analysis</b>: a graph of how evenly the sound packets arrived.', m: '<b>RTP Stream Analysis</b>: jitter, delta and loss per stream. Real calls are never this clean.', e: 'RTP Stream Analysis: delta 20.0 ms ± 0.06, jitter ≈ 0, 0 lost; compare with a real capture.' },
          { s: '<b>Edit → Find Packet</b>, choose String, type a word: search every packet’s bytes at once.', m: '<b>Edit → Find Packet</b> (String, Packet bytes) or the filter <code>frame contains "part"</code>: how many packets mention the word, and which ones?', e: '<code>frame contains "part"</code> matches the DNS answer, the first JPEG segment and the INVITE.' },
          { s: 'Change the wrong answer and try again: what would the capture look like if the call had been encrypted (SRTP), or the photo fetched over HTTPS?', m: 'Ask what would have stopped you: HTTPS hides the photo and its metadata; SRTP or a TLS-protected call hides the voice; DNS over HTTPS hides the TXT lookup from a mirror port. The Encryption and Protocols site shows the first of these.', e: 'Mitigations: TLS for HTTP, SRTP/ZRTP or SIP over TLS with SRTP, DoH/DoT. Each removes one exhibit.' }
        ] }
    ]
  }
];
