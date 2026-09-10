/* level.js - the Simple | Moderate | Engineer reading level.
   Shared by every Packet Lessons site; keep the copies identical.

   Any piece of prose in lessons.js may be written three ways:
     'one string'                          -> the same at every level
     { s: '...', m: '...', e: '...' }      -> one version per level (s = Simple, m = Moderate, e = Engineer)
     [ 'string', { s: '...', m: '...' } ]  -> an array where each entry may be either
   A missing key falls back to Moderate, then to whatever exists. An explicit '' means
   "leave this paragraph out at this level". lv() resolves all of that, and also turns
   {{row:id}} / {{Row:id}} into 'the "Title" row' / 'The "Title" row' from the lesson's title. */

var LEVELS = [
  { id: 's', label: 'Simple',   hint: 'Plain words and the big idea' },
  { id: 'm', label: 'Moderate', hint: 'CCNA-student depth' },
  { id: 'e', label: 'Engineer', hint: 'Full technical detail, kept short' }
];

var LEVEL_KEY = 'packet-lessons-level';
var LEVEL_NAMES = { simple: 's', moderate: 'm', engineer: 'e', s: 's', m: 'm', e: 'e' };

function getLevel() {
  var v = null;
  try { v = localStorage.getItem(LEVEL_KEY); } catch (e) { v = null; }
  if (!v) {
    var q = /[?&]level=([a-z]+)/i.exec(location.search);
    if (q) v = LEVEL_NAMES[q[1].toLowerCase()] || null;
  }
  return LEVEL_NAMES[v] || 'm';
}

var LEVEL = getLevel();
document.documentElement.dataset.level = LEVEL;

function setLevel(id) {
  if (!LEVEL_NAMES[id] || LEVEL_NAMES[id] === LEVEL) return;
  LEVEL = LEVEL_NAMES[id];
  try { localStorage.setItem(LEVEL_KEY, LEVEL); } catch (e) { /* private mode: level lasts for this page only */ }
  document.documentElement.dataset.level = LEVEL;
  var bar = document.querySelector('.level-bar');
  if (bar) markLevelBar(bar);
  if (typeof window !== 'undefined' && typeof window.rerender === 'function') window.rerender();
}

function isLevelObject(x) {
  return x !== null && typeof x === 'object' && !Array.isArray(x) && ('s' in x || 'm' in x || 'e' in x);
}

function rowRefs(str) {
  if (typeof str !== 'string' || str.indexOf('{{') < 0) return str;
  return str.replace(/\{\{(row|Row):([a-z0-9-]+)\}\}/g, function (all, word, id) {
    var title = null;
    if (typeof LESSONS !== 'undefined') LESSONS.forEach(function (l) { if (l.id === id) title = l.title; });
    if (!title) return all;
    return (word === 'Row' ? 'The' : 'the') + ' \u201c' + title.replace(/^The /, '') + '\u201d row';
  });
}

function lv(x) {
  if (x === null || x === undefined) return x;
  if (typeof x === 'string') return rowRefs(x);
  if (Array.isArray(x)) {
    var out = [];
    x.forEach(function (item) {
      var r = lv(item);
      if (r === null || r === undefined || r === '') return;
      if (Array.isArray(r)) out = out.concat(r); else out.push(r);
    });
    return out;
  }
  if (isLevelObject(x)) {
    var v;
    if (LEVEL in x) v = x[LEVEL];
    else if ('m' in x) v = x.m;
    else v = ('e' in x) ? x.e : x.s;
    return lv(v);
  }
  return x;
}

function levelBarHtml() {
  return '<div class="level-bar" role="group" aria-label="Reading level">' + LEVELS.map(function (l) {
    return '<button type="button" class="level-btn" data-level="' + l.id + '" title="' + l.hint + '" aria-pressed="' + (l.id === LEVEL ? 'true' : 'false') + '">' + l.label + '</button>';
  }).join('') + '</div>';
}

function markLevelBar(bar) {
  Array.prototype.forEach.call(bar.querySelectorAll('.level-btn'), function (b) {
    b.setAttribute('aria-pressed', b.dataset.level === LEVEL ? 'true' : 'false');
  });
}

function wireLevelBar(wrap) {
  if (!wrap) return;
  wrap.innerHTML = levelBarHtml();
  wrap.addEventListener('click', function (e) {
    var b = e.target.closest('.level-btn');
    if (b) setLevel(b.dataset.level);
  });
}

if (typeof module !== 'undefined') module.exports = { lv: lv, setLevel: setLevel, getLevel: getLevel, LEVELS: LEVELS };
