import https from 'node:https';
import { createHash, createPublicKey, verify } from 'node:crypto';
import * as fs from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HOME = dirname(fileURLToPath(import.meta.url));
export const BASE = 'https://raw.githubusercontent.com/ithing-goon/receive-only-updater-demo/main/distribution/';
const MAX = 16 * 1024 * 1024;
export const hash = b => createHash('sha256').update(b).digest('hex');

export function getFile(name, limit, requestFn = https.request) {
  if (!(name === 'release.json' || /^[a-f0-9]{64}\.bin$/.test(name))) {
    return Promise.reject(new Error('Unapproved download path'));
  }
  return new Promise((resolve, reject) => {
    let timer;
    const req = requestFn(BASE + name, {
      method: 'GET', rejectUnauthorized: true, agent: false,
      headers: { Accept: 'application/octet-stream', 'Accept-Encoding': 'identity' },
    }, res => {
      if (res.statusCode !== 200) {
        res.destroy();
        req.destroy(new Error(`HTTP ${res.statusCode}; no redirect or alternative route attempted`));
        return;
      }
      let length = 0;
      const chunks = [];
      res.on('data', b => {
        length += b.length;
        if (length > limit) req.destroy(new Error('Download too large'));
        else chunks.push(b);
      });
      res.on('error', reject);
      res.on('aborted', () => reject(new Error('Incomplete response')));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });
    timer = setTimeout(() => req.destroy(new Error('15 second deadline exceeded')), 15000);
    req.on('close', () => clearTimeout(timer));
    req.on('error', reject);
    req.end(); // No request body. No credentials, cookies, local data or telemetry.
  });
}

export function checkRelease(envelope, key, now = Date.now()) {
  if (envelope.length > 16384) throw new Error('Envelope too large');
  const e = JSON.parse(envelope.toString('utf8'));
  if (typeof e.payload !== 'string' || typeof e.signature !== 'string') throw new Error('Bad envelope');
  const bytes = Buffer.from(e.payload, 'base64');
  const sig = Buffer.from(e.signature, 'base64');
  const pub = createPublicKey(key);
  if (pub.asymmetricKeyType !== 'ed25519' || sig.length !== 64 || !verify(null, bytes, pub, sig)) throw new Error('Invalid signature');
  const m = JSON.parse(bytes.toString('utf8'));
  const start = Date.parse(m.created), end = Date.parse(m.expires);
  if (m.schema !== 1 || m.source !== BASE || !Number.isSafeInteger(m.version) || m.version < 1 ||
      !Number.isSafeInteger(m.size) || m.size < 1 || m.size > MAX ||
      typeof m.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(m.sha256) ||
      m.file !== `${m.sha256}.bin` || !Number.isFinite(start) || !Number.isFinite(end) ||
      start > now + 300000 || end <= now || end <= start || end - start > 7 * 86400000) throw new Error('Release policy or expiry invalid');
  return m;
}

export function checkData(data, m) {
  if (data.length !== m.size || hash(data) !== m.sha256) throw new Error('File integrity failed');
}

export function checkVersion(state, m) {
  if (!state) return;
  if (!Number.isSafeInteger(state.version) || state.version < 1 || !/^[a-f0-9]{64}$/.test(state.sha256)) throw new Error('Invalid local state');
  if (m.version < state.version || (m.version === state.version && m.sha256 !== state.sha256)) throw new Error('Rollback or conflicting version refused');
}

export async function receive({ root = HOME, get = getFile } = {}) {
  const key = await fs.readFile(join(root, 'trusted-key.pem'));
  const inbox = join(root, 'inbox');
  await fs.mkdir(inbox, { recursive: true });
  const lock = await fs.open(join(inbox, '.lock'), 'wx');
  try {
    let state = null;
    try { state = JSON.parse(await fs.readFile(join(inbox, 'state.json'), 'utf8')); }
    catch (e) { if (e.code !== 'ENOENT') throw e; }
    const m = checkRelease(await get('release.json', 16384), key);
    checkVersion(state, m);
    const output = join(inbox, `${m.version}-${m.sha256}.bin`);
    if (state?.version === m.version) {
      checkData(await fs.readFile(output), m);
      return { status: 'already-current', version: m.version, output };
    }
    const bytes = await get(m.file, m.size);
    checkData(bytes, m);
    // Stage only; never execute, unpack, or touch a development checkout.
    try { await fs.writeFile(output, bytes, { flag: 'wx' }); }
    catch (e) {
      if (e.code !== 'EEXIST') throw e;
      checkData(await fs.readFile(output), m);
    }
    await fs.writeFile(join(inbox, 'state.next'), JSON.stringify({ version: m.version, sha256: m.sha256 }));
    await fs.rename(join(inbox, 'state.next'), join(inbox, 'state.json'));
    return { status: 'verified', version: m.version, bytes: bytes.length, sha256: m.sha256, output };
  } finally {
    await lock.close();
    await fs.unlink(join(inbox, '.lock'));
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) { console.error('Arguments are not accepted'); process.exitCode = 1; }
  else receive().then(r => console.log(JSON.stringify(r, null, 2))).catch(e => { console.error(e.message); process.exitCode = 1; });
}
