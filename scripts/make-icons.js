// Generates public/icon-192.png and public/icon-512.png with pure JS (zlib only).
// Design: teal→blue gradient rounded square, white chat bubble, 3 teal dots.
const fs = require('fs');
const zlib = require('zlib');
const path = require('path');

function crcTable() {
  if (crcTable.t) return crcTable.t;
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c;
  }
  crcTable.t = t;
  return t;
}
function crc32(buf) {
  const t = crcTable();
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = t[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const td = Buffer.from(type, 'ascii');
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([td, data])), 0);
  return Buffer.concat([len, td, data, crc]);
}
// rounded-rect hit test (Minkowski: inner rect + disk)
function inRR(x, y, x0, y0, x1, y1, r) {
  const nx = Math.max(x0 + r, Math.min(x, x1 - r));
  const ny = Math.max(y0 + r, Math.min(y, y1 - r));
  const dx = x - nx, dy = y - ny;
  return dx * dx + dy * dy <= r * r;
}
function inCircle(x, y, cx, cy, r) {
  const dx = x - cx, dy = y - cy;
  return dx * dx + dy * dy <= r * r;
}
function inTri(x, y, ax, ay, bx, by, cx, cy) {
  const d1 = (x - bx) * (ay - by) - (ax - bx) * (y - by);
  const d2 = (x - cx) * (by - cy) - (bx - cx) * (y - cy);
  const d3 = (x - ax) * (cy - ay) - (cx - ax) * (y - ay);
  const neg = d1 < 0 || d2 < 0 || d3 < 0;
  const pos = d1 > 0 || d2 > 0 || d3 > 0;
  return !(neg && pos);
}

function makeIcon(size) {
  const w = size, h = size;
  const px = Buffer.alloc(w * h * 4);
  const set = (x, y, r, g, b) => {
    if (x < 0 || y < 0 || x >= w || y >= h) return;
    const i = (y * w + x) * 4;
    px[i] = r; px[i + 1] = g; px[i + 2] = b; px[i + 3] = 255;
  };
  const TEAL = [20, 184, 166], BLUE = [79, 124, 255];
  const bgR = Math.round(w * 0.06);
  for (let y = 0; y < h; y++) {
    const t = y / (h - 1);
    const r = Math.round(TEAL[0] + (BLUE[0] - TEAL[0]) * t);
    const g = Math.round(TEAL[1] + (BLUE[1] - TEAL[1]) * t);
    const b = Math.round(TEAL[2] + (BLUE[2] - TEAL[2]) * t);
    for (let x = 0; x < w; x++) {
      if (inRR(x + 0.5, y + 0.5, 0, 0, w, h, bgR)) set(x, y, r, g, b);
    }
  }
  // white bubble
  const bx0 = w * 0.20, bx1 = w * 0.80, by0 = h * 0.28, by1 = h * 0.60, br = w * 0.09;
  for (let y = Math.floor(by0); y < Math.ceil(by1); y++) {
    for (let x = Math.floor(bx0); x < Math.ceil(bx1); x++) {
      if (inRR(x + 0.5, y + 0.5, bx0, by0, bx1, by1, br)) set(x, y, 255, 255, 255);
    }
  }
  // tail (triangle under bubble, left side)
  for (let y = Math.floor(h * 0.58); y < Math.ceil(h * 0.76); y++) {
    for (let x = Math.floor(w * 0.24); x < Math.ceil(w * 0.46); x++) {
      if (inTri(x + 0.5, y + 0.5, w * 0.34, h * 0.58, w * 0.26, h * 0.75, w * 0.46, h * 0.58)) set(x, y, 255, 255, 255);
    }
  }
  // 3 teal dots
  const dy = h * 0.44, dr = w * 0.038;
  for (const fx of [0.36, 0.50, 0.64]) {
    const cx = w * fx;
    for (let y = Math.floor(dy - dr - 1); y < Math.ceil(dy + dr + 1); y++) {
      for (let x = Math.floor(cx - dr - 1); x < Math.ceil(cx + dr + 1); x++) {
        if (inCircle(x + 0.5, y + 0.5, cx, dy, dr)) set(x, y, 13, 148, 136);
      }
    }
  }
  const raw = Buffer.alloc(h * (1 + w * 4));
  for (let y = 0; y < h; y++) {
    raw[y * (1 + w * 4)] = 0; // filter: none
    px.copy(raw, y * (1 + w * 4) + 1, y * w * 4, (y + 1) * w * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = 6; // 8-bit RGBA
  const png = Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
  const out = path.join(__dirname, '..', 'public', `icon-${size}.png`);
  fs.writeFileSync(out, png);
  console.log('icon written:', out, png.length, 'bytes');
}

makeIcon(192);
makeIcon(512);
