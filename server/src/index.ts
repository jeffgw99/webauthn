import Fastify from 'fastify';
import cors from '@fastify/cors';
import { v4 as uuidv4 } from 'uuid';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/types';
import {
  ensureDataFiles,
  usersStore,
  challengesStore,
  credentialsStore,
  resetDataFiles,
  StoredCredential,
  UserRecord,
} from './storage';

const rpName = 'WebAuthn Demo';
const rpID = 'localhost';
const expectedOrigin = 'http://localhost:5173';
const port = 3000;

const app = Fastify({ logger: true });

app.register(cors, {
  origin: expectedOrigin,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
});

function parseUsername(raw: unknown): { ok: true; value: string } | { ok: false; message: string } {
  if (typeof raw !== 'string') return { ok: false, message: 'Username is required' };
  const value = raw.trim();
  if (!value) return { ok: false, message: 'Username is required' };
  if (value.length > 32) return { ok: false, message: 'Username too long (max 32 chars)' };
  if (!/^[a-zA-Z0-9._-]+$/.test(value)) {
    return { ok: false, message: 'Use only letters, numbers, dots, dashes, and underscores' };
  }
  return { ok: true, value };
}

async function getOrCreateUser(username: string): Promise<UserRecord> {
  let user: UserRecord | undefined;
  await usersStore.update((data) => {
    const existing = data.users[username];
    if (existing) {
      user = existing;
      return data;
    }
    const now = new Date().toISOString();
    const created: UserRecord = { id: uuidv4(), username, createdAt: now };
    data.users[username] = created;
    user = created;
    return data;
  });
  return user!;
}

async function storeChallenge(username: string, type: 'registration' | 'authentication', challenge: string) {
  const now = new Date().toISOString();
  await challengesStore.update((data) => {
    const current = data.challenges[username] ?? {};
    current[type] = { challenge, createdAt: now };
    data.challenges[username] = current;
    return data;
  });
}

async function consumeChallenge(
  username: string,
  type: 'registration' | 'authentication',
): Promise<string | null> {
  let value: string | null = null;
  await challengesStore.update((data) => {
    const record = data.challenges[username]?.[type];
    if (record) {
      value = record.challenge;
      delete data.challenges[username][type];
      if (
        !data.challenges[username].registration &&
        !data.challenges[username].authentication
      ) {
        delete data.challenges[username];
      }
    }
    return data;
  });
  return value;
}

async function getCredentials(username: string): Promise<StoredCredential[]> {
  const data = await credentialsStore.read();
  return data.credentials[username] ?? [];
}

async function upsertCredential(username: string, credential: StoredCredential): Promise<void> {
  await credentialsStore.update((data) => {
    const list = data.credentials[username] ?? [];
    const existingIndex = list.findIndex(
      (c) => c.credentialID_b64url === credential.credentialID_b64url,
    );
    if (existingIndex >= 0) {
      const existing = list[existingIndex];
      list[existingIndex] = {
        ...existing,
        ...credential,
        createdAt: existing.createdAt,
      };
    } else {
      list.push(credential);
    }
    data.credentials[username] = list;
    return data;
  });
}

app.post('/webauthn/register/options', async (request, reply) => {
  const body = request.body as { username?: string };
  const parsed = parseUsername(body?.username);
  if (!parsed.ok) {
    return reply.code(400).send({ error: parsed.message });
  }

  const username = parsed.value;
  const user = await getOrCreateUser(username);
  const existingCredentials = await getCredentials(username);

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: Buffer.from(user.id, 'utf8'),
    userName: user.username,
    userDisplayName: user.username,
    attestationType: 'none',
    excludeCredentials: existingCredentials.map((cred) => ({
      id: cred.credentialID_b64url,
      transports: cred.transports,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  await storeChallenge(username, 'registration', options.challenge);

  return reply.send(options);
});

app.post('/webauthn/register/verify', async (request, reply) => {
  const body = request.body as { username?: string; response?: RegistrationResponseJSON };
  const parsed = parseUsername(body?.username);
  if (!parsed.ok) {
    return reply.code(400).send({ verified: false, message: parsed.message });
  }
  const username = parsed.value;
  const expectedChallenge = await consumeChallenge(username, 'registration');
  if (!expectedChallenge) {
    return reply
      .code(400)
      .send({ verified: false, message: 'No registration challenge found. Start over.' });
  }

  const response = body.response;
  if (!response) {
    return reply.code(400).send({ verified: false, message: 'Missing registration response' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return reply.code(400).send({ verified: false, message: 'Registration verification failed' });
    }

    const { credential, aaguid } = verification.registrationInfo;

    const transports = response.response?.transports;
    const now = new Date().toISOString();
    const storedCredential: StoredCredential = {
      credentialID_b64url: credential.id,
      publicKey_b64url: isoBase64URL.fromBuffer(Buffer.from(credential.publicKey)),
      counter: credential.counter,
      transports,
      aaguid,
      createdAt: now,
      lastUsedAt: now,
    };

    await upsertCredential(username, storedCredential);

    return reply.send({ verified: true, message: 'Passkey registered' });
  } catch (err: any) {
    request.log.error({ err }, 'Registration verification error');
    return reply.code(400).send({ verified: false, message: err?.message || 'Verification failed' });
  }
});

app.post('/webauthn/login/options', async (request, reply) => {
  const body = request.body as { username?: string };
  const parsed = parseUsername(body?.username);
  if (!parsed.ok) {
    return reply.code(400).send({ error: parsed.message });
  }
  const username = parsed.value;
  const user = await getOrCreateUser(username);
  const credentials = await getCredentials(username);
  if (!credentials.length) {
    return reply.code(400).send({ error: 'No credentials found for this user. Register first.' });
  }

  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: 'preferred',
    allowCredentials: credentials.map((cred) => ({
      id: cred.credentialID_b64url,
      transports: cred.transports,
    })),
  });

  await storeChallenge(user.username, 'authentication', options.challenge);

  return reply.send(options);
});

app.post('/webauthn/login/verify', async (request, reply) => {
  const body = request.body as { username?: string; response?: AuthenticationResponseJSON };
  const parsed = parseUsername(body?.username);
  if (!parsed.ok) {
    return reply.code(400).send({ verified: false, message: parsed.message });
  }
  const username = parsed.value;
  const expectedChallenge = await consumeChallenge(username, 'authentication');
  if (!expectedChallenge) {
    return reply
      .code(400)
      .send({ verified: false, message: 'No authentication challenge found. Start over.' });
  }

  const response = body.response;
  if (!response) {
    return reply.code(400).send({ verified: false, message: 'Missing authentication response' });
  }

  const credentials = await getCredentials(username);
  const credential = credentials.find((cred) => cred.credentialID_b64url === response.id);
  if (!credential) {
    return reply
      .code(400)
      .send({ verified: false, message: 'Credential not recognized for this user' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      credential: {
        id: credential.credentialID_b64url,
        publicKey: isoBase64URL.toBuffer(credential.publicKey_b64url),
        counter: credential.counter,
        transports: credential.transports,
      },
      requireUserVerification: true,
    });

    if (!verification.verified || !verification.authenticationInfo) {
      return reply
        .code(400)
        .send({ verified: false, message: 'Authentication verification failed' });
    }

    const { newCounter } = verification.authenticationInfo;
    await credentialsStore.update((data) => {
      const list = data.credentials[username] ?? [];
      const idx = list.findIndex((c) => c.credentialID_b64url === credential.credentialID_b64url);
      if (idx >= 0) {
        list[idx] = {
          ...list[idx],
          counter: newCounter,
          lastUsedAt: new Date().toISOString(),
        };
      }
      data.credentials[username] = list;
      return data;
    });

    return reply.send({ verified: true, message: 'Authenticated' });
  } catch (err: any) {
    request.log.error({ err }, 'Authentication verification error');
    return reply.code(400).send({ verified: false, message: err?.message || 'Verification failed' });
  }
});

app.post('/debug/reset', async (_request, reply) => {
  await resetDataFiles();
  return reply.send({ ok: true });
});

app.get('/debug/state', async (_request, reply) => {
  const [users, credentials, challenges] = await Promise.all([
    usersStore.read(),
    credentialsStore.read(),
    challengesStore.read(),
  ]);
  return reply.send({
    users: users.users,
    credentials: credentials.credentials,
    challenges: challenges.challenges,
  });
});

app.post('/debug/remove-user', async (request, reply) => {
  const body = request.body as { username?: string };
  const parsed = parseUsername(body?.username);
  if (!parsed.ok) {
    return reply.code(400).send({ ok: false, message: parsed.message });
  }
  const username = parsed.value;

  await Promise.all([
    usersStore.update((data) => {
      delete data.users[username];
      return data;
    }),
    credentialsStore.update((data) => {
      delete data.credentials[username];
      return data;
    }),
    challengesStore.update((data) => {
      delete data.challenges[username];
      return data;
    }),
  ]);

  return reply.send({ ok: true });
});

app.post('/debug/remove-credential', async (request, reply) => {
  const body = request.body as { username?: string; credentialID?: string };
  const parsed = parseUsername(body?.username);
  if (!parsed.ok) {
    return reply.code(400).send({ ok: false, message: parsed.message });
  }
  const username = parsed.value;
  const credentialID = body.credentialID;
  if (!credentialID) {
    return reply.code(400).send({ ok: false, message: 'credentialID required' });
  }

  await credentialsStore.update((data) => {
    const list = data.credentials[username] ?? [];
    data.credentials[username] = list.filter((c) => c.credentialID_b64url !== credentialID);
    return data;
  });

  return reply.send({ ok: true });
});

const start = async () => {
  await ensureDataFiles();
  try {
    await app.listen({ port, host: '0.0.0.0' });
    app.log.info(`Server running on http://localhost:${port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};

start();
