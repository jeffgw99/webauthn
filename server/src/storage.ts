import { promises as fs } from 'fs';
import path from 'path';
import type { AuthenticatorTransportFuture } from '@simplewebauthn/types';

export interface UserRecord {
  id: string;
  username: string;
  createdAt: string;
}

export interface ChallengeRecord {
  challenge: string;
  createdAt: string;
}

export interface UsersFile {
  users: Record<string, UserRecord>;
}

export interface ChallengesFile {
  challenges: Record<
    string,
    {
      registration?: ChallengeRecord;
      authentication?: ChallengeRecord;
    }
  >;
}

export interface StoredCredential {
  credentialID_b64url: string;
  publicKey_b64url: string;
  counter: number;
  transports?: AuthenticatorTransportFuture[];
  aaguid?: string;
  createdAt: string;
  lastUsedAt: string;
}

export interface CredentialsFile {
  credentials: Record<string, StoredCredential[]>;
}

const dataDir = path.resolve(__dirname, '../data');
const usersPath = path.join(dataDir, 'users.json');
const challengesPath = path.join(dataDir, 'challenges.json');
const credentialsPath = path.join(dataDir, 'credentials.json');

const defaultUsers: UsersFile = { users: {} };
const defaultChallenges: ChallengesFile = { challenges: {} };
const defaultCredentials: CredentialsFile = { credentials: {} };

let lock: Promise<unknown> = Promise.resolve();

function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const run = lock.then(fn, fn);
  lock = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

async function readJson<T>(filePath: string, defaultValue: T): Promise<T> {
  try {
    const raw = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(raw) as T;
  } catch (err: any) {
    if (err && err.code === 'ENOENT') {
      await writeJsonAtomic(filePath, defaultValue);
      return defaultValue;
    }
    throw err;
  }
}

export async function writeJsonAtomic<T>(filePath: string, data: T): Promise<void> {
  const tmpPath = `${filePath}.tmp`;
  const json = JSON.stringify(data, null, 2);
  await fs.writeFile(tmpPath, json, 'utf-8');
  await fs.rename(tmpPath, filePath);
}

function createStore<T>(filePath: string, defaultValue: T) {
  return {
    read: () =>
      withLock(async () => {
        return readJson(filePath, defaultValue);
      }),
    write: (data: T) =>
      withLock(async () => {
        await writeJsonAtomic(filePath, data);
        return data;
      }),
    update: (updater: (current: T) => T | Promise<T>) =>
      withLock(async () => {
        const current = await readJson(filePath, defaultValue);
        const clone =
          typeof structuredClone === 'function'
            ? structuredClone(current)
            : (JSON.parse(JSON.stringify(current)) as T);
        const updated = await updater(clone);
        await writeJsonAtomic(filePath, updated);
        return updated;
      }),
  };
}

export const usersStore = createStore(usersPath, defaultUsers);
export const challengesStore = createStore(challengesPath, defaultChallenges);
export const credentialsStore = createStore(credentialsPath, defaultCredentials);

export async function ensureDataFiles(): Promise<void> {
  await fs.mkdir(dataDir, { recursive: true });
  await withLock(async () => {
    await Promise.all([
      fs.access(usersPath).catch(() => writeJsonAtomic(usersPath, defaultUsers)),
      fs.access(challengesPath).catch(() => writeJsonAtomic(challengesPath, defaultChallenges)),
      fs.access(credentialsPath).catch(() => writeJsonAtomic(credentialsPath, defaultCredentials)),
    ]);
  });
}

export async function resetDataFiles(): Promise<void> {
  await withLock(async () => {
    await writeJsonAtomic(usersPath, defaultUsers);
    await writeJsonAtomic(challengesPath, defaultChallenges);
    await writeJsonAtomic(credentialsPath, defaultCredentials);
  });
}
