/**
 * Reset a portal account's password from the command line.
 *
 *     npx tsx scripts/onboard/reset-password.ts <email> <new-password>
 *     PORTAL_DATA_DIR=/data npx tsx scripts/onboard/reset-password.ts <email> <new-password>
 *
 * WHY THIS IS A SCRIPT AND NOT A ROUTE. The portal has no email delivery, so a "forgot password"
 * link would have nowhere to send a token, and a reset endpoint without one would let anyone
 * take over any account. The operator resets a hash on the box instead — the same file the
 * server reads, the same hashing function (`hashPassword`), written atomically — and drops the
 * account's live sessions so a stolen cookie does not outlive the old password.
 *
 * THE SERVER MUST BE RESTARTED AFTERWARDS. The account store is load-once, write-on-change: a
 * running server keeps serving the OLD hash from memory and overwrites this edit on its next
 * mutation. Locally: stop it, run this, start it. On Railway: `railway ssh` into the service,
 * command line (shell history, `ps`): prefix the command with a space or clear history after.
 */

import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { assertPassword, hashPassword, normalizeEmail } from './accounts.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const DATA_DIR = resolve(process.env['PORTAL_DATA_DIR'] ?? join(ROOT, 'scripts', '.demo-data'));
const ACCOUNTS_FILE = join(DATA_DIR, 'accounts.json');

const [, , rawEmail, newPassword] = process.argv;
if (rawEmail === undefined || newPassword === undefined) {
  console.error('usage: npx tsx scripts/onboard/reset-password.ts <email> <new-password>');
  process.exit(2);
}
if (!existsSync(ACCOUNTS_FILE)) {
  console.error(`no accounts file at ${ACCOUNTS_FILE} (set PORTAL_DATA_DIR if the data lives elsewhere)`);
  process.exit(1);
}

assertPassword(newPassword);
const email = normalizeEmail(rawEmail);

interface AccountRow {
  id: string;
  email: string;
  passwordHash: string;
  [key: string]: unknown;
}
interface AccountsFile {
  version: 1;
  accounts: AccountRow[];
}

const file = JSON.parse(readFileSync(ACCOUNTS_FILE, 'utf8')) as AccountsFile;
const row = file.accounts.find((a) => a.email === email);
if (row === undefined) {
  console.error(`no account for ${email}`);
  process.exit(1);
}
row.passwordHash = hashPassword(newPassword);

const tmp = `${ACCOUNTS_FILE}.${process.pid}.tmp`;
writeFileSync(tmp, JSON.stringify(file, null, 2), { mode: 0o600 });
renameSync(tmp, ACCOUNTS_FILE);

// Sign the account out everywhere: sessions are keyed by token hash but carry the account id.
const SESSIONS_FILE = join(DATA_DIR, 'sessions.json');
let dropped = 0;
if (existsSync(SESSIONS_FILE)) {
  const sessions = JSON.parse(readFileSync(SESSIONS_FILE, 'utf8')) as {
    version: 1;
    sessions: Array<{ accountId: string }>;
  };
  const before = sessions.sessions.length;
  sessions.sessions = sessions.sessions.filter((x) => x.accountId !== row.id);
  dropped = before - sessions.sessions.length;
  const stmp = `${SESSIONS_FILE}.${process.pid}.tmp`;
  writeFileSync(stmp, JSON.stringify(sessions), { mode: 0o600 });
  renameSync(stmp, SESSIONS_FILE);
}
console.log(`password reset for account ${row.id}; ${dropped} session(s) dropped. Restart the server now.`);
