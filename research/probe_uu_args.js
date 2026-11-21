// Probe uu() with the real argument order from bW: uu(V,x,this,E,J,f,M,v,Y,T)
// Each parameter gets a distinct tagged object so we can see which one receives
// the Y/Pf tables and the J self-reference.
const fs = require('fs');
const src = fs.readFileSync(process.argv[2] || 'frame_src.js', 'utf8');
const start = src.indexOf('uu=function');
if (start < 0) { console.log('uu=function not found'); process.exit(1); }
// find the matching close of the function expression
let i = src.indexOf('{', start), depth = 0, end = -1;
for (let j = i; j < src.length; j++) {
  if (src[j] === '{') depth++;
  else if (src[j] === '}') { depth--; if (depth === 0) { end = j + 1; break; } }
}
const fn = src.slice(start, end);
console.log('uu fn len', fn.length);

function tag(name) {
  const o = {};
  o.__tag = name;
  return o;
}
const V = tag('bW.V'), x = tag('bW.x'), inst = tag('instance');
const E = tag('bW.E'), J = tag('bW.J'), f = tag('bW.f'), M = tag('bW.M');
const v = tag('bW.v'), Y = tag('bW.Y'), T = tag('bW.T');

const uu = eval('(' + fn.replace(/^uu=/, '') + ')');
const out = uu(V, x, inst, E, J, f, M, v, Y, T);
console.log('uu returned', out === undefined ? 'undefined' : typeof out);

function desc(o) {
  const r = { tag: o && o.__tag };
  r.Y = Array.isArray(o.Y) ? 'arr' + o.Y.length : typeof o.Y;
  r.Pf = Array.isArray(o.Pf) ? 'arr' + o.Pf.length : typeof o.Pf;
  r.J = o.J === o ? 'SELF' : (typeof o.J === 'object' && o.J ? (o.J.__tag || 'obj') : o.J);
  r.keys = Object.keys(o).filter(k => k !== '__tag').slice(0, 20);
  return r;
}
for (const [n, o] of [['bW.V', V], ['bW.x', x], ['instance', inst], ['bW.E', E],
                      ['bW.J', J], ['bW.f', f], ['bW.M', M], ['bW.v', v],
                      ['bW.Y', Y], ['bW.T', T]]) {
  console.log(n, JSON.stringify(desc(o)));
}
