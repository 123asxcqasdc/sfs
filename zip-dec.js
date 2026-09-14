/* ZIP-распаковка методов 0/8/12/14/95.
 * Для сжатых методов используются готовые веб-декомпрессоры (MIT/BSD):
 *   - bzip2 (12) -> vendor/bzip2.js  (seek-bzip)  -> window.Bunzip
 *   - lzma  (14) -> vendor/lzma.js   (js-lzma)     -> window.LZMA
 *   - zstd  (95) -> vendor/fzstd.js  (fzstd)       -> window.fzstd
 *   - deflate (8) -> нативный DecompressionStream
 * Пишет в window.ZipDec (браузер); в Node — module.exports = { ZipDec }.
 */
(function(global){
'use strict';

const Bunzip = global.Bunzip;
const LZMA = global.LZMA;
const fzstd = global.fzstd;

function decodeStore(bytes){
  return bytes.slice();
}

async function decodeDeflate(bytes){
  if(bytes.length === 0) return new Uint8Array(0);
  if(typeof DecompressionStream === 'undefined'){
    throw new Error('deflate: требуется DecompressionStream (поддерживается современными браузерами)');
  }
  const ds = new DecompressionStream('deflate-raw');
  const stream = new Blob([bytes]).stream().pipeThrough(ds);
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

function decodeBzip2(bytes){
  if(!Bunzip){ throw new Error('bzip2: не загружен vendor/bzip2.js'); }
  const out = Bunzip.decode(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
  return out instanceof Uint8Array ? out : new Uint8Array(out);
}

function decodeLzma(payload, size){
  if(!LZMA){ throw new Error('lzma: не загружен vendor/lzma.js'); }
  if(size === undefined || size === null){ throw new Error('lzma: неизвестен ожидаемый размер (нет uncompressedSize)'); }
  if(payload.length < 4 || payload[0] !== 0x09 || payload[1] !== 0x04){
    throw new Error('lzma: битая сигнатура блока');
  }
  const u8 = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
  const psize = u8[2] | (u8[3] << 8);
  if(4 + psize > u8.length){ throw new Error('lzma: короткий payload'); }
  const props = u8.subarray(4, 4 + psize);
  const data = u8.subarray(4 + psize);
  const propsAB = new ArrayBuffer(psize); new Uint8Array(propsAB).set(props);
  const dataAB = new ArrayBuffer(data.length); new Uint8Array(dataAB).set(data);
  const outStream = new LZMA.oStream();
  LZMA.decompress(new LZMA.iStream(propsAB), new LZMA.iStream(dataAB), outStream, size);
  return outStream.toUint8Array();
}

function decodeZstd(bytes){
  if(!fzstd){ throw new Error('zstd: не загружен vendor/fzstd.js'); }
  return fzstd.decompress(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength));
}

const METHODS = {
  0:  { name: 'stored',    decode: decodeStore },
  8:  { name: 'deflate',   decode: decodeDeflate },
  9:  { name: 'deflate64', decode: null },
  12: { name: 'bzip2',     decode: decodeBzip2 },
  14: { name: 'LZMA',      decode: decodeLzma },
  95: { name: 'zstd',      decode: decodeZstd },
  98: { name: 'PPMd',      decode: null },
  99: { name: 'AES',       decode: null }
};

const ZipDec = {
  METHODS,

  /* async ZipDec.decode(метод, payload, opts) -> Uint8Array
   * opts.size — ожидаемый размер данных (обязателен для lzma). */
  decode(method, bytes, opts){
    opts = opts || {};
    const info = METHODS[method];
    if(!info || !info.decode){
      const name = info ? info.name : 'unknown';
      return Promise.reject(new Error('ZIP-метод ' + method + ' (' + name +
        ') не поддерживается: поддерживаются stored, deflate, bzip2, LZMA, zstd'));
    }
    try {
      return Promise.resolve(info.decode(bytes, opts.size));
    } catch(e) {
      return Promise.reject(e);
    }
  }
};

global.ZipDec = ZipDec;
if(typeof module !== 'undefined' && module.exports){ module.exports = { ZipDec }; }
})(typeof window !== 'undefined' ? window : globalThis);