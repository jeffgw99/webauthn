import { useEffect, useMemo, useState } from 'react';
import { QRCodeCanvas } from 'qrcode.react';
import { startAuthentication, startRegistration } from '@simplewebauthn/browser';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/types';
import './index.css';

type StepKey =
  | 'fetchRegOptions'
  | 'createCredential'
  | 'verifyAttestation'
  | 'fetchAuthOptions'
  | 'getAssertion'
  | 'verifyAssertion'
  | 'authenticated';

type StepStatus = 'idle' | 'active' | 'done' | 'error';

// Default to same-origin for prod; override with VITE_API_BASE when needed locally.
const API_BASE = import.meta.env.VITE_API_BASE ?? '';

const stepsConfig: Record<
  StepKey,
  { label: string; hint: string; phase: 'registration' | 'authentication' }
> = {
  fetchRegOptions: {
    label: 'Fetch registration options',
    hint: 'Server prepares challenge',
    phase: 'registration',
  },
  createCredential: {
    label: 'Create credential',
    hint: 'navigator.credentials.create',
    phase: 'registration',
  },
  verifyAttestation: {
    label: 'Verify attestation',
    hint: 'Server validates response',
    phase: 'registration',
  },
  fetchAuthOptions: {
    label: 'Fetch authentication options',
    hint: 'Server prepares assertion challenge',
    phase: 'authentication',
  },
  getAssertion: { label: 'Get assertion', hint: 'navigator.credentials.get', phase: 'authentication' },
  verifyAssertion: {
    label: 'Verify assertion',
    hint: 'Server checks signature + counter',
    phase: 'authentication',
  },
  authenticated: { label: 'Authenticated', hint: 'Finished', phase: 'authentication' },
};

const stepOrder: StepKey[] = [
  'fetchRegOptions',
  'createCredential',
  'verifyAttestation',
  'fetchAuthOptions',
  'getAssertion',
  'verifyAssertion',
  'authenticated',
];

const stepGroups: { title: string; subtitle: string; keys: StepKey[] }[] = [
  {
    title: 'Registration',
    subtitle: 'Create a passkey tied to this RP ID',
    keys: ['fetchRegOptions', 'createCredential', 'verifyAttestation'],
  },
  {
    title: 'Authentication',
    subtitle: 'Prove you own the stored credential',
    keys: ['fetchAuthOptions', 'getAssertion', 'verifyAssertion', 'authenticated'],
  },
];

const initialSteps: Record<StepKey, StepStatus> = {
  fetchRegOptions: 'idle',
  createCredential: 'idle',
  verifyAttestation: 'idle',
  fetchAuthOptions: 'idle',
  getAssertion: 'idle',
  verifyAssertion: 'idle',
  authenticated: 'idle',
};

function StepPill({ status }: { status: StepStatus }) {
  const map: Record<StepStatus, { text: string; bg: string; dot: string }> = {
    idle: { text: 'text-gray-400', bg: 'bg-gray-800/60 border border-gray-800', dot: 'bg-gray-600' },
    active: {
      text: 'text-black',
      bg: 'bg-yellow-400 border border-yellow-500 shadow-[0_0_0_2px_rgba(250,204,21,0.4)]',
      dot: 'bg-black',
    },
    done: { text: 'text-black', bg: 'bg-yellow-500 border border-yellow-600', dot: 'bg-black' },
    error: { text: 'text-white', bg: 'bg-red-600 border border-red-700', dot: 'bg-white' },
  };

  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold ${map[status].bg} ${map[status].text}`}
    >
      <span className={`h-2 w-2 rounded-full ${map[status].dot}`} />
      {status === 'done' ? 'done' : status}
    </span>
  );
}

function DebugBlock({ title, data }: { title: string; data: unknown }) {
  const text = useMemo(() => {
    if (!data) return '—';
    try {
      return JSON.stringify(data, null, 2);
    } catch (err) {
      return 'Could not render';
    }
  }, [data]);

  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/70 p-3">
      <div className="mb-2 text-sm font-semibold text-gray-200">{title}</div>
      <pre className="max-h-48 overflow-auto break-words whitespace-pre-wrap text-xs leading-relaxed text-gray-300">
        {text}
      </pre>
    </div>
  );
}

function DataTile({ label, value, helper }: { label: string; value: string; helper?: string }) {
  return (
    <div className="flex min-w-0 flex-col gap-1 rounded-xl border border-gray-800 bg-gray-900/70 px-3 py-3">
      <span className="text-[11px] uppercase tracking-[0.12em] text-gray-400">{label}</span>
      <span className="break-words text-sm font-semibold text-yellow-200">{value || '—'}</span>
      {helper && <span className="break-words text-[11px] text-gray-500">{helper}</span>}
    </div>
  );
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = (data as any).error || (data as any).message || `Request failed (${res.status})`;
    throw new Error(message);
  }
  return data as T;
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = (data as any).error || (data as any).message || `Request failed (${res.status})`;
    throw new Error(message);
  }
  return data as T;
}

function truncate(val: string | undefined | null, length = 18) {
  if (!val) return '';
  return val.length <= length ? val : `${val.slice(0, length)}…`;
}

function base64UrlByteLength(value: string | undefined): number | null {
  if (!value) return null;
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
    const bin = atob(normalized + pad);
    return bin.length;
  } catch {
    return null;
  }
}

const algDetails: Record<number, { name: string; detail: string }> = {
  '-7': { name: 'ES256', detail: 'P-256 (SHA-256)' },
  '-8': { name: 'EdDSA', detail: 'Ed25519/Ed448' },
  '-257': { name: 'RS256', detail: 'RSA (SHA-256)' },
  '-258': { name: 'RS384', detail: 'RSA (SHA-384)' },
  '-259': { name: 'RS512', detail: 'RSA (SHA-512)' },
};

function formatAlgorithms(
  params: PublicKeyCredentialCreationOptionsJSON['pubKeyCredParams'] | undefined,
): string {
  if (!params || !params.length) return '—';
  return params
    .map((p) => {
      const info = algDetails[p.alg];
      return info ? `${info.name} · ${info.detail}` : `alg ${p.alg}`;
    })
    .join(', ');
}

function randomToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = '';
  bytes.forEach((b) => {
    bin += String.fromCharCode(b);
  });
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

type ServerState = {
  users: Record<string, { id: string; username: string; createdAt: string }>;
  credentials: Record<
    string,
    Array<{
      credentialID_b64url: string;
      counter: number;
      createdAt: string;
      lastUsedAt: string;
      transports?: string[];
      aaguid?: string;
    }>
  >;
  challenges: Record<
    string,
    {
      registration?: { challenge: string; createdAt: string };
      authentication?: { challenge: string; createdAt: string };
    }
  >;
};

function App() {
  const [username, setUsername] = useState('username');
  const [steps, setSteps] = useState<Record<StepKey, StepStatus>>(initialSteps);
  const [status, setStatus] = useState<'Ready' | 'Registered' | 'Logged in'>('Ready');
  const [lastError, setLastError] = useState<string | null>(null);
  const [debugOpen, setDebugOpen] = useState<boolean>(false);
  const [loading, setLoading] = useState(false);
  const [view, setView] = useState<'demo' | 'server'>('demo');
  const [qrOpen, setQrOpen] = useState(false);
  const [qrToken, setQrToken] = useState<string>('');
  const [aboutOpen, setAboutOpen] = useState(false);

  const [registrationOptions, setRegistrationOptions] =
    useState<PublicKeyCredentialCreationOptionsJSON | null>(null);
  const [registrationResponse, setRegistrationResponse] = useState<RegistrationResponseJSON | null>(
    null,
  );
  const [registrationResult, setRegistrationResult] = useState<any>(null);
  const [authOptions, setAuthOptions] = useState<PublicKeyCredentialRequestOptionsJSON | null>(null);
  const [authResponse, setAuthResponse] = useState<AuthenticationResponseJSON | null>(null);
  const [authResult, setAuthResult] = useState<any>(null);
  const [serverState, setServerState] = useState<ServerState | null>(null);
  const [loadingServer, setLoadingServer] = useState(false);

  const resetUI = () => {
    setSteps(initialSteps);
    setStatus('Ready');
    setLastError(null);
    setRegistrationOptions(null);
    setRegistrationResponse(null);
    setRegistrationResult(null);
    setAuthOptions(null);
    setAuthResponse(null);
    setAuthResult(null);
  };

  const markSteps = (updates: Partial<Record<StepKey, StepStatus>>) => {
    setSteps((prev) => ({ ...prev, ...updates }));
  };

  const loadServerState = async () => {
    setLoadingServer(true);
    setLastError(null);
    try {
      const data = await getJson<ServerState>('/debug/state');
      setServerState(data);
    } catch (err: any) {
      setLastError(err?.message || 'Failed to load server JSON');
    } finally {
      setLoadingServer(false);
    }
  };

  useEffect(() => {
    if (view === 'server' && !serverState && !loadingServer) {
      void loadServerState();
    }
  }, [view, serverState, loadingServer]);

  const handleRemoveUser = async (targetUsername: string) => {
    setLoadingServer(true);
    setLastError(null);
    try {
      await postJson('/debug/remove-user', { username: targetUsername });
      const data = await getJson<ServerState>('/debug/state');
      setServerState(data);
    } catch (err: any) {
      setLastError(err?.message || 'Failed to remove user');
    } finally {
      setLoadingServer(false);
    }
  };

  const handleRemoveCredential = async (targetUsername: string, credentialID: string) => {
    setLoadingServer(true);
    setLastError(null);
    try {
      await postJson('/debug/remove-credential', { username: targetUsername, credentialID });
      const data = await getJson<ServerState>('/debug/state');
      setServerState(data);
    } catch (err: any) {
      setLastError(err?.message || 'Failed to remove credential');
    } finally {
      setLoadingServer(false);
    }
  };

  const handleRegister = async () => {
    setLoading(true);
    setLastError(null);
    markSteps({
      fetchRegOptions: 'active',
      createCredential: 'idle',
      verifyAttestation: 'idle',
      fetchAuthOptions: 'idle',
      getAssertion: 'idle',
      verifyAssertion: 'idle',
      authenticated: 'idle',
    });
    try {
      const options = await postJson<PublicKeyCredentialCreationOptionsJSON>(
        '/webauthn/register/options',
        { username },
      );
      setRegistrationOptions(options);
      markSteps({ fetchRegOptions: 'done', createCredential: 'active' });

      const regResponse = await startRegistration({ optionsJSON: options });
      setRegistrationResponse(regResponse);
      markSteps({ createCredential: 'done', verifyAttestation: 'active' });

      const verification = await postJson('/webauthn/register/verify', {
        username,
        response: regResponse,
      });
      setRegistrationResult(verification);

      if (!(verification as any).verified) {
        throw new Error((verification as any).message || 'Verification failed');
      }

      markSteps({ verifyAttestation: 'done' });
      setStatus('Registered');
      void loadServerState();
    } catch (err: any) {
      setLastError(err?.message || 'Registration failed');
      setSteps((prev) => ({
        ...prev,
        fetchRegOptions: prev.fetchRegOptions === 'active' ? 'error' : prev.fetchRegOptions,
        createCredential: prev.createCredential === 'active' ? 'error' : prev.createCredential,
        verifyAttestation: 'error',
      }));
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async () => {
    setLoading(true);
    setLastError(null);
    markSteps({
      fetchAuthOptions: 'active',
      getAssertion: 'idle',
      verifyAssertion: 'idle',
      authenticated: 'idle',
    });

    try {
      const options = await postJson<PublicKeyCredentialRequestOptionsJSON>('/webauthn/login/options', {
        username,
      });
      setAuthOptions(options);
      markSteps({ fetchAuthOptions: 'done', getAssertion: 'active' });

      const assertion = await startAuthentication({ optionsJSON: options });
      setAuthResponse(assertion);
      markSteps({ getAssertion: 'done', verifyAssertion: 'active' });

      const verification = await postJson('/webauthn/login/verify', {
        username,
        response: assertion,
      });
      setAuthResult(verification);

      if (!(verification as any).verified) {
        throw new Error((verification as any).message || 'Authentication failed');
      }

      markSteps({ verifyAssertion: 'done', authenticated: 'done' });
      setStatus('Logged in');
      void loadServerState();
    } catch (err: any) {
      setLastError(err?.message || 'Authentication failed');
      setSteps((prev) => ({
        ...prev,
        fetchAuthOptions: prev.fetchAuthOptions === 'active' ? 'error' : prev.fetchAuthOptions,
        getAssertion: prev.getAssertion === 'active' ? 'error' : prev.getAssertion,
        verifyAssertion: 'error',
        authenticated: 'idle',
      }));
    } finally {
      setLoading(false);
    }
  };

  const handleServerReset = async () => {
    setLoading(true);
    try {
      await postJson('/debug/reset', {});
      resetUI();
    } catch (err: any) {
      setLastError(err?.message || 'Failed to clear server state');
    } finally {
      setLoading(false);
    }
  };

  const statusColor = {
    Ready: 'bg-gray-900 text-gray-200 border border-gray-800',
    Registered: 'bg-yellow-500 text-black',
    'Logged in': 'bg-emerald-500 text-black',
  }[status];

  const activeStepKey = stepOrder.find((key) => steps[key] === 'active');
  const activeStepLabel = activeStepKey ? stepsConfig[activeStepKey].label : 'Waiting…';
  const completedCount = stepOrder.filter((key) => steps[key] === 'done').length;

  const latestCredentialId = truncate(registrationResponse?.id || authResponse?.id || '', 22);
  const latestRegChallenge = truncate(registrationOptions?.challenge || '', 22);
  const latestAuthChallenge = truncate(authOptions?.challenge || '', 22);
  const regChallengeBytes = base64UrlByteLength(registrationOptions?.challenge);
  const authChallengeBytes = base64UrlByteLength(authOptions?.challenge);
  const regAlgs = formatAlgorithms(registrationOptions?.pubKeyCredParams);

  return (
    <div className="min-h-screen bg-[#050505] text-gray-100">
      <div className="mx-auto flex max-w-screen-2xl flex-col gap-6 px-4 py-8 sm:gap-8 sm:px-6 sm:py-10">
        <header className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-sm uppercase tracking-[0.2em] text-yellow-400">WebAuthn Demo</p>
            <h1 className="text-3xl font-semibold text-white md:text-4xl">Passkey playground</h1>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <span className={`rounded-full px-4 py-2 text-sm font-semibold ${statusColor}`}>
              {status}
            </span>
            {lastError && (
              <span className="rounded-full bg-red-700/70 px-4 py-2 text-sm text-red-100">
                {lastError}
              </span>
            )}
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => {
                  setQrToken(randomToken());
                  setQrOpen(true);
                }}
                className="rounded-lg border border-yellow-700 bg-gray-900 px-3 py-2 text-xs text-yellow-200 transition hover:border-yellow-500"
              >
                Show QR to webauthn.jeffgw.com
              </button>
              <button
                onClick={() => setAboutOpen(true)}
                className="rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-xs text-gray-200 transition hover:border-yellow-500"
              >
                About this demo
              </button>
            </div>
          </div>
        </header>

        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => setView('demo')}
            className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
              view === 'demo'
                ? 'bg-yellow-500 text-black shadow-lg shadow-yellow-500/30'
                : 'border border-gray-800 bg-gray-900 text-gray-200 hover:border-yellow-500'
            }`}
          >
            Demo flow
          </button>
          <button
            onClick={() => setView('server')}
            className={`rounded-lg px-4 py-2 text-sm font-semibold transition ${
              view === 'server'
                ? 'bg-yellow-500 text-black shadow-lg shadow-yellow-500/30'
                : 'border border-gray-800 bg-gray-900 text-gray-200 hover:border-yellow-500'
            }`}
          >
            Server JSON
          </button>
        </div>

        {view === 'demo' && (
          <div className="grid gap-5 xl:grid-cols-[1.6fr,1fr]">
          <div className="flex flex-col gap-5">
            <section className="rounded-2xl border border-gray-900 bg-gray-950/80 p-4 sm:p-5 shadow-xl shadow-yellow-500/5">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                <div className="flex-1 space-y-2">
                  <label className="text-sm text-gray-300">Username</label>
                  <input
                    className="w-full rounded-lg border border-gray-800 bg-gray-900 px-3 py-3 text-lg text-white outline-none ring-1 ring-transparent transition focus:ring-yellow-400/60"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    maxLength={32}
                  />
                  <p className="text-xs text-gray-500">
                    Default: username • Allowed: letters, numbers, dot, dash, underscore. Data lives in
                    <span className="text-yellow-300"> /server/data/*.json</span>.
                  </p>
                </div>
                <div className="flex flex-col gap-3 md:w-64">
                  <button
                    onClick={handleRegister}
                    disabled={loading}
                    className="w-full rounded-lg bg-yellow-500 px-4 py-3 text-center text-black shadow-lg shadow-yellow-500/30 transition hover:bg-yellow-400 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    Register passkey
                  </button>
                  <button
                    onClick={handleLogin}
                    disabled={loading}
                    className="w-full rounded-lg border border-yellow-700 bg-gray-900 px-4 py-3 text-center text-yellow-300 transition hover:border-yellow-500 hover:text-yellow-200 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    Login with passkey
                  </button>
                  <div className="flex flex-col gap-2 sm:flex-row">
                    <button
                      onClick={resetUI}
                      className="flex-1 rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-sm text-gray-200 transition hover:border-gray-700"
                    >
                      Reset UI
                    </button>
                    <button
                      onClick={handleServerReset}
                      disabled={loading}
                      className="flex-1 rounded-lg border border-red-800 bg-red-900/60 px-3 py-2 text-sm text-red-100 transition hover:border-red-600 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      Clear server JSON
                    </button>
                  </div>
                </div>
              </div>
              <ul className="mt-4 grid gap-2 text-sm text-gray-300 md:grid-cols-2">
                <li className="flex items-start gap-2">
                  <span className="mt-[6px] h-2 w-2 rounded-full bg-yellow-400" />
                  1) Register to mint a credential; 2) Login reuses the saved credential.
                </li>
                <li className="flex items-start gap-2">
                  <span className="mt-[6px] h-2 w-2 rounded-full bg-yellow-400" />
                  Challenges are server-issued; nothing sensitive is kept in the browser.
                </li>
              </ul>
            </section>

            <section className="rounded-2xl border border-gray-900 bg-gray-950/80 p-4 sm:p-5">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="text-sm uppercase tracking-[0.2em] text-yellow-400">Ceremony steps</p>
                  <h2 className="text-xl font-semibold text-white">Registration + Authentication timeline</h2>
                  <p className="text-xs text-gray-500">Active step: {activeStepLabel}</p>
                </div>
                <div className="rounded-full border border-gray-800 bg-gray-900 px-3 py-2 text-xs text-gray-300">
                  {completedCount}/7 complete
                </div>
              </div>

              <div className="space-y-4">
                {stepGroups.map((group) => (
                  <div key={group.title} className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <div className="text-gray-200">
                        <span className="font-semibold text-white">{group.title}</span>
                        <span className="text-gray-500"> · {group.subtitle}</span>
                      </div>
                    </div>
                    <div className="space-y-3">
                      {group.keys.map((key) => {
                        const step = stepsConfig[key];
                        return (
                          <div
                            key={key}
                            className="flex items-start justify-between rounded-xl border border-gray-900 bg-gray-900/60 px-4 py-3"
                          >
                            <div>
                              <div className="text-sm font-semibold text-white">{step.label}</div>
                              <div className="text-xs text-gray-400">{step.hint}</div>
                            </div>
                            <StepPill status={steps[key]} />
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          </div>

          <aside className="flex flex-col gap-4 rounded-2xl border border-yellow-900/40 bg-gray-950/90 p-5">
            <div className="rounded-xl border border-gray-900 bg-gray-900/60 p-4">
              <div className="flex items-center justify-between gap-2">
                <div>
                  <p className="text-[11px] uppercase tracking-[0.2em] text-yellow-400">Status</p>
                  <h3 className="text-lg font-semibold text-white">Where you are</h3>
                </div>
                <span className={`rounded-full px-3 py-1 text-xs font-semibold ${statusColor}`}>
                  {status}
                </span>
              </div>
              <div className="mt-3 space-y-1 text-sm text-gray-300">
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-yellow-400" /> {activeStepLabel}
                </div>
                {lastError ? (
                  <div className="flex items-start gap-2 text-red-200">
                    <span className="mt-1 h-2 w-2 rounded-full bg-red-500" />
                    {lastError}
                  </div>
                ) : (
                  <div className="flex items-center gap-2 text-gray-400">
                    <span className="h-2 w-2 rounded-full bg-emerald-500" />
                    No errors reported
                  </div>
                )}
              </div>
            </div>

            <div className="grid gap-2 rounded-xl border border-gray-900 bg-gray-900/60 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[11px] uppercase tracking-[0.2em] text-yellow-400">Snapshots</p>
                  <h3 className="text-base font-semibold text-white">Recent payloads</h3>
                </div>
                <span className="text-[11px] text-gray-400">Sanitized previews</span>
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                <DataTile
                  label="Reg challenge"
                  value={latestRegChallenge || '—'}
                  helper="From /webauthn/register/options"
                />
                <DataTile
                  label="Reg challenge size"
                  value={regChallengeBytes ? `${regChallengeBytes} bytes` : '—'}
                  helper="Binary challenge length (before base64url)"
                />
                <DataTile
                  label="Auth challenge"
                  value={latestAuthChallenge || '—'}
                  helper="From /webauthn/login/options"
                />
                <DataTile
                  label="Auth challenge size"
                  value={authChallengeBytes ? `${authChallengeBytes} bytes` : '—'}
                  helper="Binary challenge length (before base64url)"
                />
                <DataTile
                  label="Credential ID"
                  value={latestCredentialId || '—'}
                  helper="Public identifier (base64url)"
                />
                <DataTile
                  label="Last API call"
                  value={authResult?.verified ? 'Authenticated' : registrationResult?.verified ? 'Registered' : '—'}
                  helper="Verification result from server"
                />
                <DataTile
                  label="Crypto algs"
                  value={regAlgs}
                  helper="pubKeyCredParams (server preference order)"
                />
              </div>
            </div>

            <div className="rounded-xl border border-gray-900 bg-gray-900/60 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[11px] uppercase tracking-[0.2em] text-yellow-400">Debug</p>
                  <h3 className="text-lg font-semibold text-white">Data exchange</h3>
                </div>
                <button
                  onClick={() => setDebugOpen((prev) => !prev)}
                  className="rounded-full border border-gray-800 bg-gray-900 px-3 py-1 text-xs text-gray-200 transition hover:border-yellow-500"
                >
                  {debugOpen ? 'Hide' : 'Show'} details
                </button>
              </div>
              {debugOpen ? (
                <div className="mt-3 flex flex-col gap-3">
                  <DebugBlock title="Registration options" data={registrationOptions} />
                  <DebugBlock title="Registration response (client)" data={registrationResponse} />
                  <DebugBlock title="Verification result (register)" data={registrationResult} />
                  <DebugBlock title="Auth options" data={authOptions} />
                  <DebugBlock title="Auth response (client)" data={authResponse} />
                  <DebugBlock title="Verification result (auth)" data={authResult} />
                </div>
              ) : (
                <p className="mt-3 text-sm text-gray-400">
                  Toggle to inspect sanitized JSON payloads passed between client and server.
                </p>
              )}
            </div>
          </aside>
        </div>
        )}

        {view === 'server' && (
          <div className="rounded-2xl border border-yellow-900/40 bg-gray-950/90 p-5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <p className="text-sm uppercase tracking-[0.2em] text-yellow-400">Server JSON</p>
                <h2 className="text-xl font-semibold text-white">View & prune saved data</h2>
                <p className="text-xs text-gray-400">
                  Reads /server/data/*.json. Removing items is demo-only; it clears disk state.
                </p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={loadServerState}
                  disabled={loadingServer}
                  className="rounded-lg border border-yellow-700 bg-gray-900 px-3 py-2 text-xs text-yellow-200 transition hover:border-yellow-500 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {loadingServer ? 'Loading…' : 'Refresh'}
                </button>
                <button
                  onClick={handleServerReset}
                  disabled={loadingServer}
                  className="rounded-lg border border-red-800 bg-red-900/60 px-3 py-2 text-xs text-red-100 transition hover:border-red-600 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  Reset JSON
                </button>
              </div>
            </div>
            {serverState ? (
              <div className="mt-4 space-y-3">
                {Object.keys(serverState.users).length === 0 && (
                  <p className="text-sm text-gray-400">No users saved yet.</p>
                )}
                <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-3">
                  <DebugBlock title="Raw server JSON" data={serverState} />
                </div>
                {Object.entries(serverState.users).map(([userKey, user]) => {
                  const creds = serverState.credentials[userKey] ?? [];
                  const challenges = serverState.challenges[userKey];
                  return (
                    <div
                      key={userKey}
                      className="rounded-lg border border-gray-800 bg-gray-900/70 p-4"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="space-y-1">
                          <div className="text-sm font-semibold text-white">{user.username}</div>
                          <div className="text-[11px] text-gray-400 break-words">
                            ID: <span className="text-yellow-200">{user.id}</span>
                          </div>
                          <div className="text-[11px] text-gray-500">Created: {new Date(user.createdAt).toLocaleString()}</div>
                        </div>
                        <button
                          onClick={() => handleRemoveUser(user.username)}
                          disabled={loadingServer}
                          className="rounded border border-red-700 bg-red-900/50 px-3 py-2 text-xs text-red-100 transition hover:border-red-500 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          Remove user
                        </button>
                      </div>
                      <div className="mt-2 grid gap-2 md:grid-cols-2">
                        <div className="rounded border border-gray-800 bg-gray-900/60 p-2 text-[11px] text-gray-400">
                          Challenges: reg {challenges?.registration ? '✅' : '—'} · auth {challenges?.authentication ? '✅' : '—'}
                        </div>
                        <div className="rounded border border-gray-800 bg-gray-900/60 p-2 text-[11px] text-gray-400">
                          Credentials stored: {creds.length}
                        </div>
                      </div>
                      <div className="mt-3 space-y-2">
                        {creds.length === 0 && (
                          <p className="text-sm text-gray-500">No credentials for this user.</p>
                        )}
                        {creds.map((cred) => (
                          <div
                            key={cred.credentialID_b64url}
                            className="flex flex-col gap-1 rounded border border-gray-800 bg-gray-900/60 p-3 sm:flex-row sm:items-start sm:justify-between"
                          >
                            <div className="min-w-0 space-y-1">
                                <div className="text-xs font-semibold text-yellow-200 break-words">
                                  ID: {cred.credentialID_b64url}
                                </div>
                              <div className="text-[11px] text-gray-400">
                                Counter: {cred.counter} · Created: {new Date(cred.createdAt).toLocaleString()}
                              </div>
                              <div className="text-[11px] text-gray-400">
                                Last used: {new Date(cred.lastUsedAt).toLocaleString()}
                              </div>
                              <div className="text-[11px] text-gray-500">
                                  Transports: {cred.transports?.join(', ') || '—'} {cred.aaguid ? `· aaguid ${cred.aaguid}` : ''}
                              </div>
                            </div>
                            <button
                              onClick={() => handleRemoveCredential(user.username, cred.credentialID_b64url)}
                              disabled={loadingServer}
                              className="mt-2 w-full rounded border border-red-700 bg-red-900/50 px-3 py-2 text-xs text-red-100 transition hover:border-red-500 disabled:cursor-not-allowed disabled:opacity-60 sm:mt-0 sm:w-auto"
                            >
                              Remove credential
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="mt-3 text-sm text-gray-400">Click refresh to read current server JSON from disk.</p>
            )}
          </div>
        )}
      </div>
      {qrOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4">
          <div className="relative max-w-3xl rounded-2xl border border-yellow-700 bg-gray-950 p-6 shadow-2xl shadow-yellow-500/20">
            <button
              onClick={() => setQrOpen(false)}
              className="absolute right-3 top-3 rounded-full border border-gray-700 bg-gray-900 px-3 py-1 text-xs text-gray-200 transition hover:border-yellow-500"
            >
              Close
            </button>
            <div className="flex flex-col items-center gap-4">
              <p className="text-sm uppercase tracking-[0.2em] text-yellow-400">Demo QR</p>
              <h3 className="text-xl font-semibold text-white">webauthn.jeffgw.com</h3>
              <p className="text-sm text-gray-400">One-time token appended as query param.</p>
              <div className="text-center text-xs text-gray-500 break-words">
                https://webauthn.jeffgw.com/register?token={qrToken || '...'}
              </div>
              <div className="rounded-2xl bg-white p-6 shadow-lg">
                <QRCodeCanvas
                  value={`https://webauthn.jeffgw.com/register?token=${qrToken || 'pending'}`}
                  size={320}
                  includeMargin
                />
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setQrToken(randomToken())}
                  className="rounded border border-yellow-700 bg-gray-900 px-3 py-2 text-xs text-yellow-200 transition hover:border-yellow-500"
                >
                  Generate new token
                </button>
                <span className="text-xs text-gray-400">Token: {qrToken || '…'}</span>
              </div>
            </div>
          </div>
        </div>
      )}
      {aboutOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4">
          <div className="relative max-w-2xl rounded-2xl border border-yellow-700 bg-gray-950 p-6 shadow-2xl shadow-yellow-500/20">
            <button
              onClick={() => setAboutOpen(false)}
              className="absolute right-3 top-3 rounded-full border border-gray-700 bg-gray-900 px-3 py-1 text-xs text-gray-200 transition hover:border-yellow-500"
            >
              Close
            </button>
            <div className="space-y-4">
              <div>
                <p className="text-sm uppercase tracking-[0.2em] text-yellow-400">About</p>
                <h3 className="text-xl font-semibold text-white">Stack used in this demo</h3>
              </div>
              <div className="grid gap-3 text-sm text-gray-200 md:grid-cols-2">
                <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-3">
                  <div className="text-yellow-300">Frontend</div>
                  <ul className="mt-2 space-y-1 text-gray-300">
                    <li>React 19 (Vite)</li>
                    <li>Tailwind CSS</li>
                    <li>@simplewebauthn/browser</li>
                    <li>QR: qrcode.react + base64url token (crypto.getRandomValues) → https://webauthn.jeffgw.com/register?token=…</li>
                  </ul>
                </div>
                <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-3">
                  <div className="text-yellow-300">Backend</div>
                  <ul className="mt-2 space-y-1 text-gray-300">
                    <li>Node.js 20+</li>
                    <li>Fastify 5</li>
                    <li>@simplewebauthn/server</li>
                    <li>TypeScript</li>
                  </ul>
                </div>
                <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-3 md:col-span-2">
                  <div className="text-yellow-300">Data & tooling</div>
                  <ul className="mt-2 space-y-1 text-gray-300">
                    <li>JSON on disk: users, credentials, challenges</li>
                    <li>Atomic writes + simple locking</li>
                    <li>Vite dev server @5173, Fastify API @3000</li>
                    <li>Concurrently for dual dev servers</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
