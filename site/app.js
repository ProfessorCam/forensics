/* app.js - wires the left column to the right column. No frameworks.
 * Beyond the usual lesson rendering this site has four investigation tools:
 *   a display filter on every packet table (a small subset of Wireshark's language),
 *   "export objects" (rebuilds files carried over HTTP and reads their metadata),
 *   a call player (decodes G.711 audio out of RTP packets and plays it), and
 *   answer boxes that check a part of the flag, or the whole flag, against a SHA-256 hash. */
(function () {
  'use strict';

  var nav = document.getElementById('nav');
  var main = document.getElementById('main');
  var content = document.getElementById('content');
  var pcapCache = {};
  var PROGRESS_KEY = 'forensics-progress';

  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  /* ---------- expanding site menu (the whole left rail is the button) ---------- */

  function buildMenu() {
    var panel = document.getElementById('sitemenu'), btn = document.getElementById('menu-btn');
    if (!panel || !btn || !SITE.menu) return;
    panel.innerHTML = '<div class="sitemenu-title">Sites</div>' + SITE.menu.map(function (m) {
      if (!m.href) return '<span class="menu-item soon"><span>' + esc(m.label) + '</span><small>coming soon</small></span>';
      return '<a class="menu-item' + (m.current ? ' current' : '') + '" href="' + esc(m.href) + '"' + (m.current ? ' aria-current="page"' : '') + '>' + esc(m.label) + (m.current ? '<small>you are here</small>' : '') + '</a>';
    }).join('') + '<div class="sitemenu-foot">Click anywhere else, or press Escape, to close.</div>';

    var leaveTimer = null;
    function setOpen(open) {
      panel.classList.toggle('open', open);
      btn.classList.toggle('open', open);
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      btn.setAttribute('aria-label', open ? 'Close site menu' : 'Open site menu');
      if (leaveTimer) { clearTimeout(leaveTimer); leaveTimer = null; }
    }
    function isOpen() { return panel.classList.contains('open'); }

    btn.addEventListener('click', function (e) { e.stopPropagation(); setOpen(!isOpen()); });
    panel.addEventListener('click', function (e) {
      e.stopPropagation();
      if (e.target.closest('a.menu-item')) setOpen(false);
    });
    document.addEventListener('click', function () { if (isOpen()) setOpen(false); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && isOpen()) { setOpen(false); btn.focus(); } });
    panel.addEventListener('mouseleave', function () { if (isOpen()) leaveTimer = setTimeout(function () { setOpen(false); }, 1200); });
    panel.addEventListener('mouseenter', function () { if (leaveTimer) { clearTimeout(leaveTimer); leaveTimer = null; } });
    panel.addEventListener('focusout', function (e) { if (!panel.contains(e.relatedTarget) && e.relatedTarget !== btn) setOpen(false); });
  }

  /* ---------- progress: which parts have been found, remembered on this browser ---------- */

  function getProgress() {
    try { var p = JSON.parse(localStorage.getItem(PROGRESS_KEY) || '{}'); return { parts: p.parts || [], flag: !!p.flag }; }
    catch (e) { return { parts: [], flag: false }; }
  }
  function saveProgress(pr) { try { localStorage.setItem(PROGRESS_KEY, JSON.stringify(pr)); } catch (e) { /* private mode: fine */ } }
  function markSolved(part) {
    var pr = getProgress();
    if (part === 'flag') pr.flag = true; else pr.parts[part] = true;
    saveProgress(pr);
    updateNavMarks();
  }
  function updateNavMarks() {
    var pr = getProgress();
    Array.prototype.forEach.call(nav.querySelectorAll('.row'), function (b) {
      var l = LESSONS.filter(function (x) { return x.id === b.dataset.id; })[0];
      var solved = l && (l.part !== undefined ? !!pr.parts[l.part] : l.id === 'verdict' ? pr.flag : false);
      b.classList.toggle('solved', solved);
      var mark = b.querySelector('.done');
      if (mark) mark.hidden = !solved;
    });
  }

  /* ---------- left column ---------- */

  var STACK_GROUPS = { 7: 'Layer 7 · Application', flag: 'The verdict' };
  var STACK_CHIPS = { 7: 'L7', flag: 'flag' };

  function buildNav() {
    var last = null;
    LESSONS.forEach(function (l) {
      if (l.stack !== undefined && l.stack !== last) {
        var g = document.createElement('div');
        g.className = 'nav-group';
        g.textContent = STACK_GROUPS[l.stack] || String(l.stack);
        nav.appendChild(g);
        last = l.stack;
      }
      var b = document.createElement('button');
      b.className = 'row';
      b.type = 'button';
      b.dataset.id = l.id;
      b.innerHTML =
        '<span class="text"><span class="title">' + esc(l.title) + '</span>' +
        '<span class="sub">' + esc(l.subtitle) + '</span></span>' +
        '<span class="done" title="Found" hidden>&#10003;</span>' +
        (l.stack !== undefined ? '<span class="lay">' + esc(l.chip || STACK_CHIPS[l.stack] || l.stack) + '</span>' : '');
      b.addEventListener('click', function () { location.hash = l.id; });
      nav.appendChild(b);
    });
    updateNavMarks();
  }

  function setActive(id) {
    Array.prototype.forEach.call(nav.querySelectorAll('.row'), function (b) {
      b.classList.toggle('active', b.dataset.id === id);
    });
  }

  /* ---------- sequence diagram ---------- */

  function diagram(lesson) {
    var actors = lesson.actors, steps = lesson.steps;
    var colW = actors.length > 2 ? 330 : 460, left = 200, top = 70, rowH = 34;
    var width = left * 2 + colW * (actors.length - 1);
    var height = top + rowH * steps.length + 30;
    var xs = actors.map(function (a, i) { return left + colW * i; });
    var out = [];
    out.push('<svg class="seq" viewBox="0 0 ' + width + ' ' + height + '" style="max-width:' + width + 'px" role="img" aria-label="Sequence diagram">');
    var head = '<path d="M0 0 L10 5 L0 10 z"/>';
    function marker(id) { return '<marker id="' + id + '" class="' + id + '" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">' + head + '</marker>'; }
    out.push('<defs>' + marker('arrow') + marker('arrow-bcast') + marker('arrow-dashed') + '</defs>');
    actors.forEach(function (a, i) {
      out.push('<line class="life" x1="' + xs[i] + '" y1="' + (top - 10) + '" x2="' + xs[i] + '" y2="' + (height - 10) + '"/>');
      out.push('<text class="actor" x="' + xs[i] + '" y="24" text-anchor="middle">' + esc(a.name) + '</text>');
      out.push('<text class="addr" x="' + xs[i] + '" y="42" text-anchor="middle">' + esc(a.addr) + '</text>');
    });
    steps.forEach(function (s, i) {
      var y = top + rowH * i + 12;
      var x1 = xs[s.from], x2, cls = 'msg' + (s.dashed ? ' dashed' : '');
      if (s.to === 'all') {
        cls += ' bcast';
        out.push('<line class="' + cls + '" x1="40" y1="' + y + '" x2="' + (width - 20) + '" y2="' + y + '" marker-start="url(#arrow-bcast)" marker-end="url(#arrow-bcast)"/>');
        out.push('<circle class="origin" cx="' + x1 + '" cy="' + y + '" r="4"/>');
        out.push('<text class="label" x="' + (width / 2) + '" y="' + (y - 6) + '" text-anchor="middle">' + esc(s.label) + '</text>');
      } else {
        x2 = xs[s.to];
        out.push('<line class="' + cls + '" x1="' + x1 + '" y1="' + y + '" x2="' + x2 + '" y2="' + y + '" marker-end="url(#' + (s.dashed ? 'arrow-dashed' : 'arrow') + ')"/>');
        out.push('<text class="label" x="' + ((x1 + x2) / 2) + '" y="' + (y - 6) + '" text-anchor="middle">' + esc(s.label) + '</text>');
      }
      out.push('<text class="stepno" x="18" y="' + (y + 4) + '" text-anchor="middle">' + (i + 1) + '</text>');
    });
    out.push('</svg>');
    return out.join('');
  }

  /* ---------- welcome page ---------- */

  function renderWelcome() {
    var hosts = (SITE.hosts || []).map(function (x) {
      return '<tr><td>' + esc(x.name) + '</td><td>' + esc(x.mac) + '</td><td>' + esc(x.ip) + '</td><td>' + esc(x.role) + '</td></tr>';
    }).join('');
    var w = SITE.welcome;
    var h = ['<article class="welcome">'];
    h.push('<h1>' + esc(SITE.title) + '</h1>');
    h.push('<p class="lead">' + esc(lv(w.lead)) + '</p>');
    h.push('<h2>The case</h2>');
    lv(w.story).forEach(function (p) { h.push('<p>' + p + '</p>'); });
    h.push('<h2>What to do</h2><ol>');
    w.rows.forEach(function (r) { h.push('<li><b>' + esc(r[0]) + '.</b> ' + r[1] + '</li>'); });
    h.push('</ol>');
    h.push('<p class="hint">' + w.levels + '</p>');
    h.push('<h2>The machines in the capture</h2>');
    h.push('<div class="table-wrap"><table class="lab hosts"><tr><th>Machine</th><th>MAC address</th><th>IPv4</th><th>Role</th></tr>' + hosts + '</table></div>');
    h.push('<p class="hint">' + w.machinesNote + '</p>');
    h.push('<h2>Two ways to work</h2>');
    h.push('<div class="cols"><div class="col"><h3>On this page</h3>' + lv(w.onPage).map(function (p) { return '<p>' + p + '</p>'; }).join('') + '</div>' +
      '<div class="col"><h3>In Wireshark</h3>' + lv(w.inWireshark).map(function (p) { return '<p>' + p + '</p>'; }).join('') + '</div></div>');
    h.push('<h2>Run it on your own LAN</h2>');
    h.push('<p class="hint">The site is also published as a Docker image, so a class can use it without internet access:</p>');
    h.push('<pre class="cmd">docker run --rm -it --name forensics --network host ' + esc(SITE.image) + '</pre>');
    h.push('<p class="hint">Then open <a href="http://127.0.0.1:' + SITE.port + '/">http://127.0.0.1:' + SITE.port + '/</a> on that machine, or its LAN address followed by <code>:' + SITE.port + '</code> from another computer on the LAN. The container runs in the foreground; press Ctrl+C to stop it, and it removes itself.</p>');
    h.push(captureSectionHtml({ file: FILES.evidence, title: 'The evidence file', filter: '', hint: w.captureHint }));
    h.push('</article>');
    content.innerHTML = h.join('');
    main.scrollTop = 0;
    loadPackets();
  }

  /* ---------- lesson sections ---------- */

  function columnsHtml(cols) {
    return '<div class="cols">' + cols.map(function (c) {
      var after = lv(c.after);
      return '<div class="col"><h3>' + esc(c.h) + '</h3>' + lv(c.p || []).map(function (p) { return '<p>' + p + '</p>'; }).join('') +
        (c.cmd ? '<pre class="cmd">' + esc(c.cmd) + '</pre>' : '') + (after ? '<p>' + after + '</p>' : '') + '</div>';
    }).join('') + '</div>';
  }

  function tableHtml(rows, cls) {
    var h = ['<div class="table-wrap"><table class="lab ' + (cls || 'compare') + '">'];
    rows.map(lv).forEach(function (row, i) { h.push('<tr>' + row.map(function (c, j) { return (i === 0 || j === 0 ? '<th>' : '<td>') + c + (i === 0 || j === 0 ? '</th>' : '</td>'); }).join('') + '</tr>'); });
    h.push('</table></div>');
    return h.join('');
  }

  function captureSectionHtml(c) {
    return '<section class="packets"><div class="packets-head"><h2>' + esc(c.title || 'The packets') + '</h2><div class="dl-group">' +
      '<a class="dl" href="pcaps/' + encodeURIComponent(c.file) + '" download>Download .pcap</a></div></div>' +
      '<p class="hint">' + (c.hint ? lv(c.hint) + ' ' : 'Click a packet to expand its details. ') + 'File: <code>' + esc(c.file) + '</code></p>' +
      '<div class="pktbox" data-file="' + esc(c.file) + '" data-filter="' + esc(c.filter || '') + '"><p class="loading">Loading capture...</p></div></section>';
  }

  function toolHtml(s) {
    if (s.tool === 'objects') return '<div class="tool objects" data-file="' + esc(s.file || FILES.evidence) + '"><p class="loading">Rebuilding the files carried over HTTP...</p></div>';
    if (s.tool === 'voip') return '<div class="tool voip" data-file="' + esc(s.file || FILES.evidence) + '"><p class="loading">Looking for phone calls...</p></div>';
    if (s.tool === 'part') return answerBoxHtml('part', s.part);
    if (s.tool === 'flag') return answerBoxHtml('flag');
    return '';
  }

  function sectionHtml(s) {
    var h = ['<section' + (s.cls ? ' class="' + esc(s.cls) + '"' : '') + '><h2>' + esc(s.h) + '</h2>'];
    lv(s.p || []).forEach(function (p) { h.push('<p>' + p + '</p>'); });
    var steps = lv(s.steps || []);
    if (steps.length) { h.push('<ol class="steps">'); steps.forEach(function (t) { h.push('<li>' + t + '</li>'); }); h.push('</ol>'); }
    if (s.packet) h.push('<div class="peek" data-file="' + esc(s.packet.file) + '" data-no="' + s.packet.no + '" data-note="' + esc(s.packet.note || '') + '"><p class="loading">Loading frame ' + s.packet.no + ' of ' + esc(s.packet.file) + ' ...</p></div>');
    if (s.columns) h.push(columnsHtml(s.columns));
    if (s.table) h.push(tableHtml(s.table));
    if (s.tool) h.push(toolHtml(s));
    lv(s.after || []).forEach(function (p) { h.push('<p>' + p + '</p>'); });
    h.push('</section>');
    return h.join('');
  }

  function renderLesson(lesson) {
    var h = [];
    h.push('<article class="lesson" id="lesson-' + lesson.id + '">');
    h.push('<p class="crumb">' + esc(STACK_GROUPS[lesson.stack] || 'Lesson') + '</p>');
    h.push('<h1>' + esc(lesson.title) + ' <small>' + esc(lesson.subtitle) + '</small></h1>');
    h.push('<p class="lead">' + esc(lv(lesson.oneLiner)) + '</p>');
    if (lesson.facts) h.push('<div class="facts">' + lesson.facts.map(function (f) { return '<div><span class="k">' + esc(f[0]) + '</span><span class="v">' + lv(f[1]) + '</span></div>'; }).join('') + '</div>');
    lesson.sections.forEach(function (s) { h.push(sectionHtml(s)); });
    if (lesson.steps) h.push('<section><h2>The conversation, step by step</h2><div class="diagram">' + diagram(lesson) + '</div></section>');
    if (lesson.lookFor) {
      h.push('<section><h2>' + esc(lv(lesson.lookForTitle) || 'What to look for') + '</h2><ul class="lookfor">');
      lv(lesson.lookFor).forEach(function (t) { h.push('<li>' + t + '</li>'); });
      h.push('</ul></section>');
    }
    (lesson.captures || []).forEach(function (c) { h.push(captureSectionHtml(c)); });
    h.push('</article>');
    content.innerHTML = h.join('');
    main.scrollTop = 0;
    loadPeeks();
    loadPackets();
    loadObjects();
    loadVoip();
    wireAnswerBoxes();
  }

  /* ---------- one frame from a capture, shown inline in a lesson ---------- */

  function loadPeeks() {
    Array.prototype.forEach.call(main.querySelectorAll('.peek'), function (box) {
      var file = box.dataset.file, no = +box.dataset.no, note = box.dataset.note;
      fetchPcap(file).then(function (packets) {
        var p = packets[no - 1];
        if (!p || p.no !== no) throw new Error('there is no frame ' + no);
        box.innerHTML = '<div class="peek-head">Frame ' + p.no + ' of <code>' + esc(file) + '</code>' + (note ? ', ' + esc(note) : '') + '. Click the row to fold the details away.</div>' +
          '<div class="table-wrap peek-table">' + packetTable([p], packets.length).replace('class="pkt ', 'class="pkt open ').replace('<tr class="det" hidden>', '<tr class="det">') + '</div>';
        wireDetails(box);
      }).catch(function (e) {
        box.innerHTML = '<p class="error">Could not load frame ' + no + ' of ' + esc(file) + ': ' + esc(e.message) + '</p>';
      });
    });
  }

  /* ---------- packets ---------- */

  function fetchPcap(file) {
    if (pcapCache[file]) return Promise.resolve(pcapCache[file]);
    return fetch('pcaps/' + encodeURIComponent(file))
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.arrayBuffer(); })
      .then(function (buf) { var p = parsePcap(buf); pcapCache[file] = p; return p; });
  }

  function loadPackets() {
    Array.prototype.forEach.call(main.querySelectorAll('.pktbox'), function (box) {
      fetchPcap(box.dataset.file).then(function (packets) {
        box.innerHTML = '<form class="filter-bar" autocomplete="off"><label>Display filter <input type="text" class="filter-input" spellcheck="false" placeholder="e.g. dns, http.request, sip, rtp, ip.addr == 192.168.110.72, frame contains &quot;part&quot;"></label>' +
          '<button type="submit" class="asm-btn filter-apply">Apply</button><button type="button" class="asm-btn filter-clear">Clear</button><span class="filter-count"></span></form>' +
          '<p class="filter-error" hidden></p><div class="table-wrap pkt-table"></div>';
        var input = box.querySelector('.filter-input');
        input.value = box.dataset.filter || '';
        function apply() {
          var expr = input.value.trim(), err = box.querySelector('.filter-error'), shown = packets;
          err.hidden = true;
          if (expr) {
            try { var fn = compileFilter(expr); shown = packets.filter(fn); }
            catch (e) { err.textContent = 'Filter not understood: ' + e.message; err.hidden = false; shown = []; }
          }
          box.querySelector('.filter-count').textContent = 'Displayed: ' + shown.length + ' of ' + packets.length;
          var tbl = box.querySelector('.pkt-table');
          tbl.innerHTML = shown.length ? packetTable(shown, packets.length) : '<p class="hint">No packets match.</p>';
          wireDetails(tbl);
          wireCollapse(tbl);
        }
        box.querySelector('.filter-bar').addEventListener('submit', function (e) { e.preventDefault(); apply(); });
        box.querySelector('.filter-clear').addEventListener('click', function () { input.value = ''; apply(); });
        apply();
      }).catch(function (e) {
        box.innerHTML = '<p class="error">Could not load the capture: ' + esc(e.message) + '. This page must be served over HTTP, not opened as a file.</p>';
      });
    });
  }

  var FOLD_ABOVE = 120, FOLD_HEAD = 60, FOLD_TAIL = 10;

  function packetTable(packets) {
    var h = ['<table class="pk"><thead><tr><th>No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr></thead><tbody>'];
    var fold = packets.length > FOLD_ABOVE;
    packets.forEach(function (p, i) {
      var cls = 'proto-' + p.proto.toLowerCase().replace(/[^a-z0-9]/g, '');
      var folded = fold && i >= FOLD_HEAD && i < packets.length - FOLD_TAIL;
      if (fold && i === FOLD_HEAD) {
        h.push('<tr class="fold"><td colspan="7"><button type="button" class="fold-btn">Show the other ' + (packets.length - FOLD_HEAD - FOLD_TAIL) + ' packets</button></td></tr>');
      }
      h.push('<tr class="pkt ' + cls + (folded ? ' folded' : '') + '" data-i="' + i + '" tabindex="0"' + (folded ? ' hidden' : '') + '>' +
        '<td class="n">' + p.no + '</td><td class="t">' + p.time.toFixed(6) + '</td>' +
        '<td>' + esc(p.src) + '</td><td>' + esc(p.dst) + '</td>' +
        '<td class="p">' + esc(p.proto) + '</td><td class="n">' + p.len + '</td>' +
        '<td class="info">' + esc(p.info) + '</td></tr>');
      h.push('<tr class="det" hidden><td colspan="7"><div class="det-inner">' + details(p) + '</div></td></tr>');
    });
    h.push('</tbody></table>');
    return h.join('');
  }

  function details(p) {
    var h = ['<div class="frame-line">Frame ' + p.no + ': ' + p.len + ' bytes on the wire, captured ' + p.time.toFixed(6) + ' s after the first packet</div>'];
    p.details.forEach(function (sec) {
      h.push('<div class="sec"><div class="sec-title">' + esc(sec.title) + '</div><table class="kv">');
      sec.rows.forEach(function (r) { h.push('<tr><th>' + esc(r[0]) + '</th><td>' + esc(r[1]).replace(/\n/g, '<br>') + '</td></tr>'); });
      h.push('</table></div>');
    });
    if (p.rawData && p.rawData.length) h.push('<div class="sec"><div class="sec-title">The bytes after the Ethernet header</div><pre class="hex">' + hexDump(p.rawData, 96) + '</pre></div>');
    return h.join('');
  }

  function hexDump(bytes, max) {
    var out = [], n = Math.min(bytes.length, max);
    for (var i = 0; i < n; i += 16) {
      var hexs = [], chars = '';
      for (var j = i; j < i + 16 && j < n; j++) { hexs.push(bytes[j].toString(16).padStart(2, '0')); chars += bytes[j] >= 32 && bytes[j] < 127 ? String.fromCharCode(bytes[j]) : '.'; }
      out.push(String(i).padStart(4, '0') + '  ' + hexs.join(' ').padEnd(47) + '  ' + esc(chars));
    }
    if (bytes.length > max) out.push('... ' + (bytes.length - max) + ' more bytes');
    return out.join('\n');
  }

  function wireCollapse(box) {
    var btn = box.querySelector('.fold-btn');
    if (!btn) return;
    btn.addEventListener('click', function () {
      Array.prototype.forEach.call(box.querySelectorAll('tr.pkt.folded'), function (tr) { tr.hidden = false; });
      btn.parentNode.parentNode.remove();
    });
  }

  function wireDetails(box) {
    Array.prototype.forEach.call(box.querySelectorAll('tr.pkt'), function (tr) {
      function toggle() {
        var det = tr.nextElementSibling;
        det.hidden = !det.hidden;
        tr.classList.toggle('open', !det.hidden);
      }
      tr.addEventListener('click', toggle);
      tr.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
    });
  }

  /* ---------- display filter: a small subset of Wireshark's language ----------
   * Protocols: eth arp ip icmp udp tcp dns http sip sdp rtp ntp.  Fields: ip.addr ip.src ip.dst
   * eth.addr eth.src eth.dst udp.port udp.srcport udp.dstport tcp.port tcp.srcport tcp.dstport tcp.len
   * tcp.flags.syn tcp.flags.fin frame.number frame.len dns.qry.name dns.txt http.request http.response
   * http.request.uri http.host http.content_type http.response.code sip.method sip.status_code sip.call_id
   * sip.from sip.to sip.subject rtp.ssrc rtp.p_type rtp.seq rtp.marker icmp.type arp.opcode.
   * Operators: == != > < >= <= contains, and/&&, or/||, not/!, parentheses, "frame contains "text"". */

  var PROTOS = ['eth', 'arp', 'ip', 'icmp', 'udp', 'tcp', 'dns', 'http', 'sip', 'sdp', 'rtp', 'ntp', 'dhcp', 'tftp'];

  var FIELDS = {
    'ip.addr': function (p) { return p.layers.indexOf('ip') >= 0 ? [p.src, p.dst] : []; },
    'ip.src': function (p) { return p.layers.indexOf('ip') >= 0 ? [p.src] : []; },
    'ip.dst': function (p) { return p.layers.indexOf('ip') >= 0 ? [p.dst] : []; },
    'ip.ttl': function (p) { return p.ttl !== undefined ? [p.ttl] : []; },
    'eth.addr': function (p) { return [p.srcMac, p.dstMac]; },
    'eth.src': function (p) { return [p.srcMac]; },
    'eth.dst': function (p) { return [p.dstMac]; },
    'udp.port': function (p) { return p.layers.indexOf('udp') >= 0 ? [p.sport, p.dport] : []; },
    'udp.srcport': function (p) { return p.layers.indexOf('udp') >= 0 ? [p.sport] : []; },
    'udp.dstport': function (p) { return p.layers.indexOf('udp') >= 0 ? [p.dport] : []; },
    'tcp.port': function (p) { return p.tcp ? [p.sport, p.dport] : []; },
    'tcp.srcport': function (p) { return p.tcp ? [p.sport] : []; },
    'tcp.dstport': function (p) { return p.tcp ? [p.dport] : []; },
    'tcp.len': function (p) { return p.tcp ? [p.tcp.len] : []; },
    'tcp.flags.syn': function (p) { return p.tcp ? [p.tcp.syn ? 1 : 0] : []; },
    'tcp.flags.fin': function (p) { return p.tcp ? [p.tcp.fin ? 1 : 0] : []; },
    'frame.number': function (p) { return [p.no]; },
    'frame.len': function (p) { return [p.len]; },
    'frame.time_relative': function (p) { return [p.time]; },
    'dns.qry.name': function (p) { return p.dns ? p.dns.questions.map(function (q) { return q.name; }) : []; },
    'dns.qry.type': function (p) { return p.dns ? p.dns.questions.map(function (q) { return q.type; }) : []; },
    'dns.txt': function (p) { return p.dns ? p.dns.answers.filter(function (a) { return a.type === 'TXT'; }).map(function (a) { return a.data; }) : []; },
    'dns.flags.response': function (p) { return p.dns ? [p.dns.response ? 1 : 0] : []; },
    'http.request': function (p) { return p.http && p.http.request ? [1] : []; },
    'http.response': function (p) { return p.http && p.http.response ? [1] : []; },
    'http.request.uri': function (p) { return p.http && p.http.request ? [p.http.uri] : []; },
    'http.request.method': function (p) { return p.http && p.http.request ? [p.http.method] : []; },
    'http.host': function (p) { return p.http && p.http.host ? [p.http.host] : []; },
    'http.content_type': function (p) { return p.http && p.http.ctype ? [p.http.ctype] : []; },
    'http.response.code': function (p) { return p.http && p.http.response ? [p.http.status] : []; },
    'sip.method': function (p) { return p.sip && p.sip.method ? [p.sip.method] : []; },
    'sip.status_code': function (p) { return p.sip && p.sip.status ? [p.sip.status] : []; },
    'sip.call_id': function (p) { return p.sip ? [p.sip.callId] : []; },
    'sip.from': function (p) { return p.sip ? [p.sip.from] : []; },
    'sip.to': function (p) { return p.sip ? [p.sip.to] : []; },
    'sip.subject': function (p) { return p.sip && p.sip.subject ? [p.sip.subject] : []; },
    'rtp.ssrc': function (p) { return p.rtp ? [p.rtp.ssrc] : []; },
    'rtp.p_type': function (p) { return p.rtp ? [p.rtp.pt] : []; },
    'rtp.seq': function (p) { return p.rtp ? [p.rtp.seq] : []; },
    'rtp.marker': function (p) { return p.rtp ? [p.rtp.marker ? 1 : 0] : []; },
    'icmp.type': function (p) { return p.layers.indexOf('icmp') >= 0 ? [p.rawData[20] !== undefined ? p.rawData[(p.rawData[0] & 15) * 4] : 0] : []; },
    'arp.opcode': function (p) { return p.arp ? [p.arp.op] : []; }
  };

  function frameText(p) {
    if (p._text === undefined) {
      var s = '';
      for (var i = 0; i < p.rawData.length; i++) s += String.fromCharCode(p.rawData[i]);
      p._text = s;
    }
    return p._text;
  }

  function tokenize(src) {
    var re = /\s*(\(|\)|&&|\|\||==|!=|>=|<=|>|<|!|"(?:[^"\\]|\\.)*"|[A-Za-z_][A-Za-z0-9_.\-]*|[0-9][0-9A-Za-z.:\-]*)/g;
    var out = [], m, pos = 0;
    while (pos < src.length) {
      re.lastIndex = pos;
      m = re.exec(src);
      if (!m || m.index !== pos) throw new Error('unexpected character at "' + src.slice(pos, pos + 8) + '"');
      out.push(m[1]);
      pos = re.lastIndex;
      if (/^\s*$/.test(src.slice(pos))) break;
    }
    return out;
  }

  function compileFilter(src) {
    var toks = tokenize(src), i = 0;
    function peek() { return toks[i]; }
    function take() { return toks[i++]; }
    function isKw(t, k) { return t !== undefined && t.toLowerCase() === k; }
    function parseOr() {
      var left = parseAnd();
      while (peek() === '||' || isKw(peek(), 'or')) { take(); var r = parseAnd(); left = (function (a, b) { return function (p) { return a(p) || b(p); }; })(left, r); }
      return left;
    }
    function parseAnd() {
      var left = parseNot();
      while (peek() === '&&' || isKw(peek(), 'and')) { take(); var r = parseNot(); left = (function (a, b) { return function (p) { return a(p) && b(p); }; })(left, r); }
      return left;
    }
    function parseNot() {
      if (peek() === '!' || isKw(peek(), 'not')) { take(); var inner = parseNot(); return function (p) { return !inner(p); }; }
      return parseAtom();
    }
    function literal(t) {
      if (t === undefined) throw new Error('a value is missing');
      if (t[0] === '"') return { str: t.slice(1, -1).replace(/\\(.)/g, '$1') };
      if (/^0x[0-9a-f]+$/i.test(t)) return { num: parseInt(t, 16), str: t };
      if (/^\d+(\.\d+)?$/.test(t)) return { num: parseFloat(t), str: t };
      return { str: t };
    }
    function compare(vals, op, lit) {
      return vals.some(function (v) {
        var vn = typeof v === 'number' ? v : (typeof v === 'string' && /^\d+(\.\d+)?$/.test(v) ? parseFloat(v) : NaN);
        var both = lit.num !== undefined && !isNaN(vn);
        var vs = String(v).toLowerCase(), ls = lit.str.toLowerCase();
        switch (op) {
          case '==': return both ? vn === lit.num : vs === ls;
          case '!=': return both ? vn !== lit.num : vs !== ls;
          case '>': return both && vn > lit.num;
          case '<': return both && vn < lit.num;
          case '>=': return both && vn >= lit.num;
          case '<=': return both && vn <= lit.num;
          case 'contains': return vs.indexOf(ls) >= 0;
        }
        return false;
      });
    }
    function parseAtom() {
      var t = take();
      if (t === undefined) throw new Error('the filter ends too early');
      if (t === '(') { var e = parseOr(); if (take() !== ')') throw new Error('missing )'); return e; }
      var name = t.toLowerCase();
      if (name === 'frame' && isKw(peek(), 'contains')) {
        take(); var lit = literal(take()).str.toLowerCase();
        return function (p) { return frameText(p).toLowerCase().indexOf(lit) >= 0; };
      }
      var op = peek();
      if (op === '==' || op === '!=' || op === '>' || op === '<' || op === '>=' || op === '<=' || isKw(op, 'contains') || isKw(op, 'eq') || isKw(op, 'ne')) {
        take();
        op = op.toLowerCase(); if (op === 'eq') op = '=='; if (op === 'ne') op = '!=';
        var getter = FIELDS[name];
        if (!getter) throw new Error('unknown field "' + t + '"');
        var l = literal(take());
        if (op === '!=') return function (p) { var v = getter(p); return v.length > 0 && !compare(v, '==', l); };
        return function (p) { return compare(getter(p), op, l); };
      }
      if (PROTOS.indexOf(name) >= 0) return function (p) { return p.layers.indexOf(name) >= 0; };
      if (FIELDS[name]) return function (p) { var v = FIELDS[name](p); return v.length > 0 && v.some(function (x) { return x !== 0 && x !== ''; }); };
      throw new Error('unknown protocol or field "' + t + '"');
    }
    var fn = parseOr();
    if (i < toks.length) throw new Error('unexpected "' + toks[i] + '"');
    return fn;
  }

  /* ---------- export objects: rebuild the files carried over HTTP ---------- */

  function tcpStreams(packets) {
    /* key = client:port>server:port, decided by who sent the SYN (or, failing that, the lower port is the server) */
    var streams = {};
    packets.forEach(function (p) {
      if (!p.tcp) return;
      var a = p.src + ':' + p.sport, b = p.dst + ':' + p.dport;
      var key = streams[a + '>' + b] ? a + '>' + b : streams[b + '>' + a] ? b + '>' + a : null;
      if (!key) {
        var clientFirst = p.tcp.syn && !p.tcp.hasAck ? true : p.sport > p.dport;
        key = clientFirst ? a + '>' + b : b + '>' + a;
        streams[key] = { key: key, client: clientFirst ? a : b, server: clientFirst ? b : a, packets: [] };
      }
      streams[key].packets.push(p);
    });
    return Object.keys(streams).map(function (k) { return streams[k]; });
  }

  function reassemble(packets, from) {
    /* bytes sent by `from` (ip:port), in sequence order, duplicates dropped */
    var segs = packets.filter(function (p) { return p.src + ':' + p.sport === from && p.tcp.len > 0; })
      .sort(function (a, b) { return (a.tcp.seq >>> 0) - (b.tcp.seq >>> 0); });
    var out = [], expect = null, total = 0;
    segs.forEach(function (p) {
      if (expect !== null && p.tcp.seq < expect) return;      /* retransmission */
      out.push(p.tcp.payload); total += p.tcp.payload.length; expect = p.tcp.seq + p.tcp.len;
    });
    var buf = new Uint8Array(total), o = 0;
    out.forEach(function (s) { buf.set(s, o); o += s.length; });
    return buf;
  }

  function latin1(bytes, start, end) {
    var s = '';
    for (var i = start; i < end; i++) s += String.fromCharCode(bytes[i]);
    return s;
  }

  function httpObjects(packets) {
    var objs = [];
    tcpStreams(packets).forEach(function (st) {
      var req = st.packets.filter(function (p) { return p.http && p.http.request; })[0];
      if (!req) return;
      var bytes = reassemble(st.packets, st.server);
      var head = latin1(bytes, 0, Math.min(bytes.length, 4096));
      var split = head.indexOf('\r\n\r\n');
      if (split < 0) return;
      var headers = {}, lines = head.slice(0, split).split('\r\n');
      lines.slice(1).forEach(function (l) { var i = l.indexOf(':'); if (i > 0) headers[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim(); });
      var clen = parseInt(headers['content-length'] || '0', 10);
      var body = bytes.subarray(split + 4, split + 4 + (clen || bytes.length));
      objs.push({ frame: req.no, host: req.http.host, uri: req.http.uri, status: lines[0], ctype: (headers['content-type'] || 'unknown').split(';')[0], declared: clen, body: body,
        complete: !clen || body.length === clen, stream: st, name: (req.http.uri.split('/').pop() || 'index') });
    });
    return objs.sort(function (a, b) { return a.frame - b.frame; });
  }

  /* JPEG metadata: the EXIF ImageDescription and friends, and any COM (comment) segments. */
  function jpegMetadata(b) {
    var rows = [];
    if (b.length < 4 || b[0] !== 0xff || b[1] !== 0xd8) return rows;
    var pos = 2;
    while (pos + 4 <= b.length && b[pos] === 0xff) {
      var marker = b[pos + 1], len = (b[pos + 2] << 8) | b[pos + 3];
      if (marker === 0xda || marker === 0xd9) break;
      if (marker === 0xfe) rows.push(['JPEG comment (COM)', latin1(b, pos + 4, pos + 2 + len)]);
      if (marker === 0xe1 && latin1(b, pos + 4, pos + 10) === 'Exif\0\0') rows = rows.concat(exifRows(b.subarray(pos + 10, pos + 2 + len)));
      if (marker === 0xe0 && latin1(b, pos + 4, pos + 8) === 'JFIF') rows.push(['JFIF version', b[pos + 9] + '.' + b[pos + 10]]);
      pos += 2 + len;
    }
    return rows;
  }

  function exifRows(t) {
    var le = latin1(t, 0, 2) === 'II';
    function u16(o) { return le ? t[o] | (t[o + 1] << 8) : (t[o] << 8) | t[o + 1]; }
    function u32(o) { return le ? (t[o] | (t[o + 1] << 8) | (t[o + 2] << 16) | (t[o + 3] << 24)) >>> 0 : ((t[o] << 24) | (t[o + 1] << 16) | (t[o + 2] << 8) | t[o + 3]) >>> 0; }
    var names = { 0x010e: 'ImageDescription', 0x010f: 'Make', 0x0110: 'Model', 0x0112: 'Orientation', 0x0131: 'Software', 0x0132: 'DateTime', 0x013b: 'Artist', 0x8298: 'Copyright', 0x9003: 'DateTimeOriginal', 0x9286: 'UserComment', 0x8825: 'GPS IFD' };
    var rows = [], seen = {};
    function ifd(off, depth) {
      if (depth > 3 || off + 2 > t.length || seen[off]) return; seen[off] = true;
      var n = u16(off);
      for (var i = 0; i < n; i++) {
        var e = off + 2 + i * 12, tag = u16(e), type = u16(e + 2), count = u32(e + 4), size = ({ 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1 }[type] || 1) * count;
        var vo = size <= 4 ? e + 8 : u32(e + 8);
        var name = names[tag] || ('tag 0x' + tag.toString(16));
        if (tag === 0x8769) { ifd(u32(e + 8), depth + 1); continue; }
        if (type === 2) rows.push(['EXIF ' + name, latin1(t, vo, vo + count).replace(/\0+$/, '')]);
        else if (type === 7 && tag === 0x9286) rows.push(['EXIF ' + name, latin1(t, vo + 8, vo + count).replace(/\0+$/, '')]);
        else if (type === 3 && count === 1) rows.push(['EXIF ' + name, String(u16(vo))]);
      }
      var next = u32(off + 2 + n * 12);
      if (next) ifd(next, depth + 1);
    }
    try { ifd(u32(4), 0); } catch (e) { /* truncated: show what we have */ }
    return rows;
  }

  function stringsIn(b, min) {
    var out = [], cur = '';
    for (var i = 0; i <= b.length; i++) {
      var c = b[i];
      if (i < b.length && c >= 32 && c < 127) cur += String.fromCharCode(c);
      else { if (cur.length >= min) out.push(cur); cur = ''; }
    }
    return out;
  }

  function loadObjects() {
    Array.prototype.forEach.call(main.querySelectorAll('.tool.objects'), function (box) {
      fetchPcap(box.dataset.file).then(function (packets) {
        var objs = httpObjects(packets);
        if (!objs.length) { box.innerHTML = '<p class="hint">No complete HTTP responses in this capture.</p>'; return; }
        var h = ['<div class="table-wrap"><table class="lab objects-table"><tr><th>Request in frame</th><th>Host</th><th>Path</th><th>Type</th><th>Size</th><th></th></tr>'];
        objs.forEach(function (o, i) {
          h.push('<tr><td>' + o.frame + '</td><td>' + esc(o.host) + '</td><td><code>' + esc(o.uri) + '</code></td><td>' + esc(o.ctype) + '</td><td>' + o.body.length + ' bytes' + (o.complete ? '' : ' (incomplete)') + '</td>' +
            '<td class="obj-actions"><button type="button" class="asm-btn obj-show" data-i="' + i + '">Show</button> <button type="button" class="asm-btn obj-save" data-i="' + i + '">Save</button></td></tr>');
        });
        h.push('</table></div><div class="obj-view" hidden></div>');
        box.innerHTML = h.join('');
        var view = box.querySelector('.obj-view');
        box.addEventListener('click', function (e) {
          var b = e.target.closest('button'); if (!b) return;
          var o = objs[+b.dataset.i];
          var blob = new Blob([o.body], { type: o.ctype });
          if (b.classList.contains('obj-save')) {
            var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = o.name; document.body.appendChild(a); a.click(); a.remove();
            setTimeout(function () { URL.revokeObjectURL(a.href); }, 5000);
            return;
          }
          var v = ['<div class="obj-head"><b>' + esc(o.name) + '</b> from <code>' + esc(o.status) + '</code>, ' + o.body.length + ' bytes rebuilt from ' + o.stream.packets.filter(function (p) { return p.src + ':' + p.sport === o.stream.server && p.tcp.len > 0; }).length + ' segments sent by ' + esc(o.stream.server) + '.</div>'];
          if (o.ctype.indexOf('image/') === 0) v.push('<div class="obj-img"><img alt="' + esc(o.name) + '" src="' + URL.createObjectURL(blob) + '"></div>');
          else if (o.ctype.indexOf('text/') === 0) v.push('<pre class="plain">' + esc(latin1(o.body, 0, Math.min(o.body.length, 3000))) + '</pre>');
          var meta = o.ctype === 'image/jpeg' ? jpegMetadata(o.body) : [];
          if (meta.length) {
            v.push('<div class="sec"><div class="sec-title">Metadata inside the file</div><table class="kv">' + meta.map(function (r) { return '<tr><th>' + esc(r[0]) + '</th><td>' + esc(r[1]) + '</td></tr>'; }).join('') + '</table></div>');
          }
          var strs = stringsIn(o.body, 8);
          v.push('<div class="sec"><div class="sec-title">Printable text inside the file (8 characters or longer, like the <code>strings</code> command)</div><pre class="plain strings">' +
            (strs.length ? strs.slice(0, 60).map(esc).join('\n') + (strs.length > 60 ? '\n... ' + (strs.length - 60) + ' more' : '') : '(none)') + '</pre></div>');
          view.innerHTML = v.join('');
          view.hidden = false;
        });
      }).catch(function (e) { box.innerHTML = '<p class="error">Could not rebuild the files: ' + esc(e.message) + '</p>'; });
    });
  }

  /* ---------- the call player: SIP dialogs and RTP streams, G.711 decoded in the browser ---------- */

  var MULAW = (function () {
    var t = new Float32Array(256);
    for (var i = 0; i < 256; i++) {
      var u = ~i & 0xff, sign = u & 0x80, exp = (u >> 4) & 7, mant = u & 0x0f;
      var mag = ((mant << 3) + 0x84) << exp; mag -= 0x84;
      t[i] = (sign ? -mag : mag) / 32768;
    }
    return t;
  })();

  function alawDecode(i) {
    var a = i ^ 0x55, sign = a & 0x80, exp = (a >> 4) & 7, mant = a & 0x0f, mag;
    if (exp === 0) mag = (mant << 4) + 8; else mag = ((mant << 4) + 0x108) << (exp - 1);
    return (sign ? mag : -mag) / 32768;
  }

  function rtpStreams(packets) {
    var by = {};
    packets.forEach(function (p) {
      if (!p.rtp) return;
      var k = p.rtp.ssrc + '|' + p.src + ':' + p.sport;
      if (!by[k]) by[k] = { ssrc: p.rtp.ssrc, src: p.src + ':' + p.sport, dst: p.dst + ':' + p.dport, pt: p.rtp.pt, ptName: p.rtp.ptName, packets: [] };
      by[k].packets.push(p);
    });
    return Object.keys(by).map(function (k) {
      var s = by[k], ps = s.packets;
      s.first = ps[0].time; s.last = ps[ps.length - 1].time;
      s.expected = ((ps[ps.length - 1].rtp.seq - ps[0].rtp.seq) & 0xffff) + 1;
      s.lost = Math.max(0, s.expected - ps.length);
      s.seconds = (ps.length * (ps[0].rtp.payload.length || 160)) / 8000;
      return s;
    }).sort(function (a, b) { return a.first - b.first; });
  }

  function streamSamples(s) {
    /* place each packet at its RTP timestamp, so gaps stay gaps */
    var ts0 = s.packets[0].rtp.ts, n = 0;
    s.packets.forEach(function (p) { n = Math.max(n, ((p.rtp.ts - ts0) >>> 0) + p.rtp.payload.length); });
    var out = new Float32Array(n);
    s.packets.forEach(function (p) {
      var o = (p.rtp.ts - ts0) >>> 0, pl = p.rtp.payload;
      for (var i = 0; i < pl.length && o + i < n; i++) out[o + i] = s.pt === 8 ? alawDecode(pl[i]) : MULAW[pl[i]];
    });
    return out;
  }

  function mixStreams(streams) {
    var t0 = Math.min.apply(null, streams.map(function (s) { return s.first; }));
    var parts = streams.map(function (s) { return { off: Math.round((s.first - t0) * 8000), pcm: streamSamples(s) }; });
    var n = Math.max.apply(null, parts.map(function (x) { return x.off + x.pcm.length; }));
    var out = new Float32Array(n);
    parts.forEach(function (x) { for (var i = 0; i < x.pcm.length; i++) out[x.off + i] += x.pcm[i]; });
    for (var j = 0; j < n; j++) out[j] = Math.max(-1, Math.min(1, out[j]));
    return out;
  }

  function wavBlob(pcm) {
    var n = pcm.length, buf = new ArrayBuffer(44 + n * 2), dv = new DataView(buf);
    function str(o, s) { for (var i = 0; i < s.length; i++) dv.setUint8(o + i, s.charCodeAt(i)); }
    str(0, 'RIFF'); dv.setUint32(4, 36 + n * 2, true); str(8, 'WAVE'); str(12, 'fmt '); dv.setUint32(16, 16, true);
    dv.setUint16(20, 1, true); dv.setUint16(22, 1, true); dv.setUint32(24, 8000, true); dv.setUint32(28, 16000, true); dv.setUint16(32, 2, true); dv.setUint16(34, 16, true);
    str(36, 'data'); dv.setUint32(40, n * 2, true);
    for (var i = 0; i < n; i++) dv.setInt16(44 + i * 2, Math.round(pcm[i] * 32767), true);
    return new Blob([buf], { type: 'audio/wav' });
  }

  var audioCtx = null, playing = null;
  function playPcm(pcm, onEnd) {
    stopAudio();
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === 'suspended') audioCtx.resume();
    var buf = audioCtx.createBuffer(1, pcm.length, 8000);
    buf.getChannelData(0).set(pcm);
    var src = audioCtx.createBufferSource();
    src.buffer = buf; src.connect(audioCtx.destination);
    src.onended = function () { if (playing === src) { playing = null; onEnd(); } };
    src.start();
    playing = src;
  }
  function stopAudio() { if (playing) { try { playing.stop(); } catch (e) { /* already done */ } playing = null; } }

  function sipCalls(packets) {
    var calls = {};
    packets.forEach(function (p) {
      if (!p.sip) return;
      var c = calls[p.sip.callId] || (calls[p.sip.callId] = { id: p.sip.callId, from: '', to: '', subject: '', invite: null, answered: null, bye: null, status: 'unanswered', packets: [] });
      c.packets.push(p);
      if (p.sip.method === 'INVITE' && !c.invite) { c.invite = p; c.from = p.sip.from; c.to = p.sip.to; c.subject = p.sip.subject; c.caller = p.src; c.callee = p.dst; }
      if (p.sip.status === 200 && /INVITE/.test(p.sip.cseq)) { c.answered = p; c.status = 'answered'; }
      if (p.sip.status >= 400) c.status = 'rejected (' + p.sip.status + ' ' + p.sip.reason + ')';
      if (p.sip.method === 'BYE') { c.bye = p; c.status = 'completed'; }
      if (p.sip.method === 'CANCEL') c.status = 'cancelled';
    });
    return Object.keys(calls).map(function (k) { return calls[k]; });
  }

  function fmtT(t) { return t.toFixed(3) + ' s'; }

  function loadVoip() {
    Array.prototype.forEach.call(main.querySelectorAll('.tool.voip'), function (box) {
      fetchPcap(box.dataset.file).then(function (packets) {
        var calls = sipCalls(packets), streams = rtpStreams(packets);
        var h = [];
        h.push('<div class="sec-title">Calls found in the signalling (SIP)</div>');
        if (!calls.length) h.push('<p class="hint">No SIP calls in this capture.</p>');
        else {
          h.push('<div class="table-wrap"><table class="lab calls"><tr><th>From</th><th>To</th><th>Subject</th><th>Started</th><th>Talking</th><th>Ended</th><th>Outcome</th></tr>');
          calls.forEach(function (c) {
            h.push('<tr><td>' + esc(c.from.replace(/;tag=.*$/, '')) + '</td><td>' + esc(c.to.replace(/;tag=.*$/, '')) + '</td><td>' + esc(c.subject || '(none)') + '</td><td>' + (c.invite ? 'frame ' + c.invite.no + ', ' + fmtT(c.invite.time) : '?') + '</td>' +
              '<td>' + (c.answered ? 'from ' + fmtT(c.answered.time) : 'never') + '</td><td>' + (c.bye ? 'frame ' + c.bye.no + ', ' + fmtT(c.bye.time) : '?') + '</td><td>' + esc(c.status) + '</td></tr>');
          });
          h.push('</table></div>');
        }
        h.push('<div class="sec-title">Audio streams (RTP)</div>');
        if (!streams.length) h.push('<p class="hint">No RTP audio in this capture.</p>');
        else {
          h.push('<div class="table-wrap"><table class="lab streams"><tr><th>From</th><th>To</th><th>SSRC</th><th>Codec</th><th>Packets</th><th>Lost</th><th>Length</th><th></th></tr>');
          streams.forEach(function (s, i) {
            h.push('<tr><td>' + esc(s.src) + '</td><td>' + esc(s.dst) + '</td><td><code>0x' + s.ssrc.toString(16).padStart(8, '0') + '</code></td><td>' + esc(s.ptName) + '</td><td>' + s.packets.length + '</td><td>' + s.lost + '</td><td>' + s.seconds.toFixed(1) + ' s</td>' +
              '<td class="obj-actions"><button type="button" class="asm-btn play" data-i="' + i + '">Play</button> <button type="button" class="asm-btn save-wav" data-i="' + i + '">Save .wav</button></td></tr>');
          });
          h.push('</table></div>');
          h.push('<div class="call-ctl"><button type="button" class="asm-btn play-all">&#9654; Play the whole call (both sides mixed)</button> <button type="button" class="asm-btn stop-audio">&#9632; Stop</button> <span class="play-state" aria-live="polite"></span></div>');
          h.push('<p class="hint">Playback rebuilds 8000 samples a second from the packets, one byte of G.711 per sample, in this browser. Nothing is downloaded from anywhere else.</p>');
        }
        box.innerHTML = h.join('');
        var state = box.querySelector('.play-state');
        function setState(t) { if (state) state.textContent = t; }
        box.addEventListener('click', function (e) {
          var b = e.target.closest('button'); if (!b) return;
          if (b.classList.contains('stop-audio')) { stopAudio(); setState('Stopped.'); return; }
          if (b.classList.contains('save-wav')) {
            var s = streams[+b.dataset.i], a = document.createElement('a');
            a.href = URL.createObjectURL(wavBlob(streamSamples(s))); a.download = 'stream-' + s.ssrc.toString(16) + '.wav';
            document.body.appendChild(a); a.click(); a.remove(); setTimeout(function () { URL.revokeObjectURL(a.href); }, 5000);
            return;
          }
          var pcm, label;
          if (b.classList.contains('play-all')) { pcm = mixStreams(streams); label = 'the whole call'; }
          else { var st = streams[+b.dataset.i]; pcm = streamSamples(st); label = 'the stream from ' + st.src; }
          setState('Playing ' + label + ', ' + (pcm.length / 8000).toFixed(1) + ' seconds...');
          playPcm(pcm, function () { setState('Finished playing ' + label + '.'); });
        });
      }).catch(function (e) { box.innerHTML = '<p class="error">Could not read the call: ' + esc(e.message) + '</p>'; });
    });
  }

  /* ---------- answer boxes ---------- */

  function answerBoxHtml(kind, part) {
    var pr = getProgress();
    var solved = kind === 'flag' ? pr.flag : !!pr.parts[part];
    var label = kind === 'flag' ? 'The whole flag' : 'Part ' + (part + 1) + ' of the flag';
    return '<form class="answer' + (solved ? ' ok' : '') + '" data-kind="' + kind + '" data-part="' + (part === undefined ? '' : part) + '" autocomplete="off">' +
      '<label><span class="answer-label">' + label + '</span><input type="text" class="answer-input" spellcheck="false" placeholder="' + (kind === 'flag' ? 'epicCTF{...}' : 'type what you found') + '"></label>' +
      '<button type="submit" class="asm-btn answer-check">Check</button>' +
      '<span class="answer-msg" aria-live="polite">' + (solved ? '&#10003; Already found on this browser.' : '') + '</span></form>';
  }

  function normPart(s) { return s.toLowerCase().replace(/[^a-z0-9]/g, ''); }
  function normFlag(s) { return s.trim().toLowerCase().replace(/\s+/g, '_'); }

  function wireAnswerBoxes() {
    Array.prototype.forEach.call(main.querySelectorAll('form.answer'), function (f) {
      f.addEventListener('submit', function (e) {
        e.preventDefault();
        var kind = f.dataset.kind, part = f.dataset.part === '' ? null : +f.dataset.part;
        var raw = f.querySelector('.answer-input').value, msg = f.querySelector('.answer-msg');
        var norm = kind === 'flag' ? normFlag(raw) : normPart(raw);
        if (!norm) { msg.textContent = 'Type something first.'; return; }
        var want = kind === 'flag' ? ANSWERS.flag : ANSWERS.parts[part];
        var ok = sha256(norm) === want;
        f.classList.toggle('ok', ok); f.classList.toggle('bad', !ok);
        if (ok) {
          markSolved(kind === 'flag' ? 'flag' : part);
          msg.innerHTML = kind === 'flag' ? '&#10003; Correct. Case closed.' : '&#10003; Correct. That is part ' + (part + 1) + '.';
        } else {
          msg.textContent = kind === 'flag' ? 'Not the flag. Check the three parts and the underscores between words.' : 'Not this part. Look again at the evidence.';
        }
      });
    });
  }

  /* SHA-256 in plain JavaScript, so the check also works on http://<lan address> where crypto.subtle is unavailable. */
  function sha256(str) {
    var K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var bytes = [], i;
    for (i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c < 128) bytes.push(c);
      else if (c < 2048) bytes.push(192 | (c >> 6), 128 | (c & 63));
      else bytes.push(224 | (c >> 12), 128 | ((c >> 6) & 63), 128 | (c & 63));
    }
    var bitLen = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    for (i = 7; i >= 0; i--) bytes.push(i >= 4 ? 0 : (bitLen >>> (i * 8)) & 0xff);
    var w = new Array(64);
    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
    for (var off = 0; off < bytes.length; off += 64) {
      for (i = 0; i < 16; i++) w[i] = (bytes[off + i * 4] << 24) | (bytes[off + i * 4 + 1] << 16) | (bytes[off + i * 4 + 2] << 8) | bytes[off + i * 4 + 3];
      for (i = 16; i < 64; i++) {
        var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      var a = H[0], b = H[1], c2 = H[2], d = H[3], e = H[4], f = H[5], g = H[6], hh = H[7];
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K[i] + w[i]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22), maj = (a & b) ^ (a & c2) ^ (b & c2);
        var t2 = (S0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c2; c2 = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c2) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + hh) | 0;
    }
    return H.map(function (x) { return (x >>> 0).toString(16).padStart(8, '0'); }).join('');
  }

  /* ---------- routing ---------- */

  function route() {
    stopAudio();
    var id = location.hash.replace('#', '');
    var idx = -1;
    LESSONS.forEach(function (l, i) { if (l.id === id) idx = i; });
    setActive(idx >= 0 ? id : null);
    if (idx >= 0) renderLesson(LESSONS[idx]);
    else renderWelcome();
    document.title = (idx >= 0 ? LESSONS[idx].title + ' - ' : '') + SITE.title;
  }

  buildMenu();
  buildNav();
  window.rerender = function () { var y = main.scrollTop; route(); main.scrollTop = y; };
  wireLevelBar(document.getElementById('level-bar'));
  window.addEventListener('hashchange', route);
  route();
  if (typeof module !== 'undefined' && module.exports) module.exports = { sha256: sha256, compileFilter: compileFilter };
})();
