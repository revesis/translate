const fs = require('fs');
const src = fs.readFileSync(process.argv[2] || 'frame_src.js', 'utf8');
const i = src.indexOf('T.J=', src.indexOf('ZK=function'));
let j = i + 4; while (src[j] !== '(') j++;
let depth = 0, k = j;
for (; k < src.length; k++) { if (src[k] === '(') depth++; else if (src[k] === ')') { depth--; if (depth === 0) break; } }
const rhs = src.slice(j, k + 1);
const T = { A: 1, tE: 16, j8: 0, X: true, Bx: true, MF: 1, v: undefined,
            l: undefined, bS: 30008, u: undefined, TY: 0, po: 0, Lo: 0,
            T() { return 100; } };
globalThis.document = { hidden: 0 };
const fn = new Function('T', 'f', 'v', 'Y', 'J', 'E', 'M', 'X', 'r', 'd', 'K', 'W',
  'document', 'return ' + rhs);
for (const [f, v, Y, J] of [[false, undefined, 1, 6], [false, undefined, 5, 6],
                            [undefined, undefined, 1, 6], [false, true, 1, 6]]) {
  const T2 = Object.assign({}, T);
  const val = fn(T2, f, v, Y, J, undefined, undefined, undefined, undefined,
                 undefined, undefined, undefined, { hidden: 0 });
  console.log(`f=${f} v=${v} Y=${Y} J=${J} -> RHS=${val} (${typeof val})  T.A=${T2.A} T.u=${T2.u} T.j8=${T2.j8}`);
}
