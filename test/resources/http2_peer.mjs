// Independent peer: Node's built-in HTTP/2 implementation, no npm dependencies.
import http2 from 'node:http2';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));
const tls = { key: fs.readFileSync(path.join(here, 'key.pem')), cert: fs.readFileSync(path.join(here, 'cert.pem')) };
const sessions = new Set();
function install(server) {
  server.on('session', s => { sessions.add(s); s.on('error', () => {}); s.on('close', () => sessions.delete(s)); });
  server.on('stream', (s, headers) => {
    s.on('error', () => {});
    const url = headers[':path'];
    const chunks = [];
    s.on('data', chunk => chunks.push(chunk));
    s.on('end', () => {
      if (s.destroyed) return;
      if (url === '/stall') return;
      if (url === '/reset') { s.respond({ ':status': 200 }); s.write('partial'); setTimeout(() => s.destroy(new Error('forced reset')), 20); return; }
      if (url === '/goaway') { s.session.goaway(http2.constants.NGHTTP2_PROTOCOL_ERROR); return; }
      if (url === '/info') s.additionalHeaders({ ':status': 103, link: '</example>' });
      if (url === '/error') { s.respond({ ':status': 429 }); s.end('rate limited'); return; }
      if (url === '/headers') { s.respond({ ':status': 200, 'content-type': 'application/json' }); s.end(JSON.stringify(headers)); return; }
      if (url === '/largeheaders') { s.respond({ ':status': 200, 'x-large': 'abcdef'.repeat(4000) }); s.end('ok'); return; }
      if (url === '/hugeheaders') { s.respond({ ':status': 200, 'x-huge': 'a'.repeat(70000) }); s.end('ok'); return; }
      if (url === '/gzip') { s.respond({ ':status': 200, 'content-encoding': 'gzip' }); s.end(zlib.gzipSync('compressed response')); return; }
      if (url === '/badlength') { s.respond({ ':status': 200, 'content-length': '100' }); s.end('short'); return; }
      if (url === '/sse' || url === '/sse-gzip' || url === '/sse-untyped') {
        s.respond({ ':status': 200, ...(url.endsWith('untyped') ? {} : { 'content-type': 'text/event-stream' }), ...(url.endsWith('gzip') ? { 'content-encoding': 'gzip' } : {}) });
        if (url.endsWith('gzip')) { s.end(zlib.gzipSync('data: one\n\ndata: two\n\n')); return; }
        s.write('data: one\n\n');
        setTimeout(() => { if (!s.destroyed) s.write('data: two\n\n'); }, 30);
        setTimeout(() => { if (!s.destroyed) s.end('data: three\n\n'); }, 60);
        return;
      }
      if (url === '/trailers') {
        s.respond({ ':status': 200 }, { waitForTrailers: true });
        s.on('wantTrailers', () => s.sendTrailers({ 'x-check': 'complete' }));
        s.end('body'); return;
      }
      s.respond({ ':status': 200 });
      s.end(url === '/echo' ? Buffer.concat(chunks) : 'ok');
    });
  });
  return server;
}
const plain = install(http2.createServer({ settings: { initialWindowSize: 32768 } }));
const secure = install(http2.createSecureServer(tls));
const h1 = https.createServer({ ...tls, ALPNProtocols: ['http/1.1'] }, (_, res) => res.end('h1'));
await Promise.all([plain, secure, h1].map(s => new Promise(resolve => s.listen(0, '127.0.0.1', resolve))));
console.log([plain.address().port, secure.address().port, h1.address().port].join(' '));
process.on('SIGTERM', () => { for (const s of sessions) s.destroy(); for (const server of [plain, secure, h1]) server.close(); process.exit(0); });
