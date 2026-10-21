// External publisher only. No network and no Git invocation.
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createHash, sign } from 'node:crypto';
import { join, resolve } from 'node:path';
import { BASE } from './updater.mjs';

const [input, keyPath, versionText, output] = process.argv.slice(2);
if (!input || !keyPath || !output || process.argv.length !== 6) throw new Error('Usage: node prepare-release.mjs INPUT EXTERNAL_PRIVATE_KEY VERSION OUTPUT_DIR');
const version = Number(versionText);
if (!Number.isSafeInteger(version) || version < 1) throw new Error('Version must be a positive integer');
const bytes = await readFile(resolve(input));
if (!bytes.length || bytes.length > 16 * 1024 * 1024) throw new Error('Payload must be 1 byte to 16 MiB');
const sha256 = createHash('sha256').update(bytes).digest('hex');
const now = Date.now();
const manifest = Buffer.from(JSON.stringify({ schema: 1, source: BASE, version, file: `${sha256}.bin`, size: bytes.length, sha256,
  created: new Date(now).toISOString(), expires: new Date(now + 7 * 86400000).toISOString() }));
const signature = sign(null, manifest, await readFile(resolve(keyPath)));
await mkdir(resolve(output), { recursive: true });
await writeFile(join(resolve(output), `${sha256}.bin`), bytes, { flag: 'wx' });
await writeFile(join(resolve(output), 'release.json'), JSON.stringify({ payload: manifest.toString('base64'), signature: signature.toString('base64') }), { flag: 'wx' });
console.log('Signed distribution files prepared. Publish only these files from the external environment.');
