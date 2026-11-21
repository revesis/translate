// Evaluate uu's second statement (the `if` whose condition contains x.J=x)
// with stubs, to see whether x.J ends up as the self-reference.
const fs = require('fs');
const src = fs.readFileSync(process.argv[2] || 'frame_src.js', 'utf8');
const marker = 'if(((x.Mw=[],E).length<';
const start = src.indexOf(marker);
const tail = src.indexOf('try{x.lU=JSON.parse(T)}', start);
if (start < 0 || tail < 0) { console.log('markers not found', start, tail); process.exit(1); }
// condition text is between the leading 'if(' and the ')try{'
const cond = src.slice(start + 3, tail).slice(0, -1);
console.log('cond len', cond.length);
console.log('cond head', cond.slice(0, 60));
console.log('cond tail', cond.slice(-60));

const vT = function () { throw new Error('vT should not be called'); };
const x = { W: 'create' };
const E = 'ab';            // uu's E = bW.f
const T = '{"a":1}';       // uu's T = bW.E (JSON text)
const f = undefined;        // uu's f
const Jv = 30008;          // scratch number used by the condition
const YM = 0;
const V = { __tag: 'uu.V' };
const K = { __tag: 'uu.K' };
const Y = { __tag: 'uu.Y' };
const H = { __tag: 'uu.H' };
const W = { __tag: 'uu.W' };
const X = { __tag: 'uu.X' };
const A = { __tag: 'uu.A' };
const b = { __tag: 'uu.b' };
const r = 'slice', l = 'length', d = String, U = 'toString', oz = 'pop';
const z1 = 0, eL = 0, f$ = 0, EQ = 'push', K$ = 0, Jv2 = Jv;

const fn = new Function('x', 'E', 'T', 'f', 'vT', 'Jv', 'YM', 'V', 'K', 'Y',
  'H', 'W', 'X', 'A', 'b', 'r', 'l', 'd', 'U', 'oz', 'z1', 'eL', 'f$',
  'EQ', 'K$', 'window', 'JSON',
  'return (' + cond + ')');
const out = fn(x, E, T, f, vT, Jv, YM, V, K, Y, H, W, X, A, b, r, l, d, U, oz,
               z1, eL, f$, EQ, K$, { performance: {} }, JSON);
console.log('condition value:', out);
console.log('x.J === x :', x.J === x);
console.log('x.J :', x.J);
console.log('x.A1:', x.A1, 'x.b2===V:', x.b2 === V);
console.log('x.qw is function:', typeof x.qw);
console.log('x.Mw:', JSON.stringify(x.Mw), 'x.RF:', JSON.stringify(x.RF),
            'x.IR:', JSON.stringify(x.IR));
console.log('E after:', JSON.stringify(E), 'l:', l, 'd===String:', d === String,
            'U:', U, 'oz:', oz, 'r:', r, 'z:', z);
