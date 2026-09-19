/**
 * The onboarding pipeline the partner portal runs for one wallet:
 *
 *   session -> provider verdict -> claim set -> BBS+ credential -> holder custody
 *     -> selective-disclosure proof -> PII scan -> issuer preflight -> attest_bbs -> read back
 *
 * The provider is the in-process mock (`mock-kyc.ts`); its verdict is recorded against the
 * session it belongs to. Everything after that verdict is the real gateway route, the real
 * credential library, and a real transaction on Stellar testnet.
 *
 * No personal data ever appears in a `DemoStep`: every `data` field is a boolean, an id, a hash,
 * a count or a length. The PII scan step is the proof of that for the presentation itself.
 */

import { rpc } from '@stellar/stellar-sdk';

import {
  CLAIM_SPECS,
  deserializeCredential,
  gateOnrampPredicate,
  issuerIdFromPublicKey,
  prove,
  randomNonce,
  serializeProof,
} from '@stellaronramp/identity';
import type { SerializedCredential } from '@stellaronramp/identity';
import type { CredentialStore } from '@stellaronramp/sdk';
import {
  CLAIM_OVER_18,
  CLAIM_OVER_21,
  ClaimDerivationError,
  SorobanGateSimulator,
  findEncodings,
  readSubjectChainState,
} from '@stellaronramp/gateway';
import {
  AttestSubmitter,
  addrScVal,
  assertIssuerActive,
  attestBbsArgs,
  contractCall,
  deriveGrantedClaims,
  ledgerExpiryFor,
  recordExpiresAtFor,
  u32,
} from '@stellaronramp/sdk';

import { DEFAULT_APPLICANT } from './mock-kyc.js';
import type { Applicant, MockKyc } from './mock-kyc.js';

/* -------------------------------------------------------------------------- */
/* Public shapes                                                               */
/* -------------------------------------------------------------------------- */

export interface DemoStep {
  id: string;
  title: string;
  detail: string;
  status: 'ok' | 'fail' | 'pending';
  txHash?: string;
  explorerUrl?: string;
  data?: Record<string, unknown>;
}

export interface DemoDeps {
  /** The loopback gateway (`apps/gateway-http`) the portal drives. */
  gatewayBaseUrl: string;
  explorerBase: string;
  networkPassphrase: string;
  gateContractId: string;
  registryContractId: string;
  rpcUrl: string;
  /** The funded account that pays for the attestation. The wallet never signs or funds it. */
  submitter: import('@stellar/stellar-sdk').Keypair;
  /** 96-byte compressed G2 from `generateIssuerKeyPair`: the key `kyc-registry` holds. */
  issuerPublicKey: Uint8Array;
  issuerSecretKey: Uint8Array;
  /** The mock provider, shared with the gateway's applicant-creator seam. */
  kyc: MockKyc;
  /** Mark a gateway session approved: the provider's verdict reaching the issuer. */
  approveSession: (sessionId: string) => void;
  /** Holder-side custody for the credential and its subject-binding salt. */
  credentialStore?: CredentialStore;
  now: () => number;
}

export interface OnboardingResult {
  ok: boolean;
  subject: string;
  txHash?: string;
  claimBitmap?: number;
  revocationIndex?: number;
}

export type EmitStep = (step: DemoStep) => void | Promise<void>;

/** ~6 days of ledgers: inside the gate's expiry horizon, longer than a demo session. */
const RECORD_LIFETIME_LEDGERS = 100_000;

/* -------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* -------------------------------------------------------------------------- */

function asObject(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function requireString(value: unknown, what: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${what} was absent or not a non-empty string in the gateway response`);
  }
  return value;
}

function requireInteger(value: unknown, what: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new Error(`${what} was absent or not an integer in the gateway response`);
  }
  return value;
}

async function postJson(
  url: string,
  body: Record<string, unknown>,
  bearer?: string,
): Promise<{ status: number; json: unknown }> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (bearer !== undefined) headers['authorization'] = `Bearer ${bearer}`;
  const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
  const json: unknown = await res.json().catch(() => null);
  return { status: res.status, json };
}

/** Every string value anywhere inside a JSON-serialisable value, depth first. */
function stringLeaves(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const v of value) stringLeaves(v, out);
  else if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) stringLeaves(v, out);
  }
  return out;
}

function jsonSafe(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) return Buffer.from(value).toString('hex');
  if (Array.isArray(value)) return value.map(jsonSafe);
  if (value instanceof Map) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of value) out[String(k)] = jsonSafe(v);
    return out;
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = jsonSafe(v);
    return out;
  }
  return value;
}

/* -------------------------------------------------------------------------- */
/* The pipeline                                                                */
/* -------------------------------------------------------------------------- */

interface RunContext {
  cAddr: string;
  sessionId: string;
  sessionToken: string;
  applicantId: string;
  applicant: Applicant;
  emit: EmitStep;
}

/** Steps 1–2: open the gateway session and record the provider's verdict against it. */
async function openSessionAndDecide(
  deps: DemoDeps,
  args: { cAddr: string; answer: 'GREEN' | 'RED'; applicant: Applicant; emit: EmitStep },
): Promise<{ sessionId: string; sessionToken: string; applicantId: string }> {
  const base = deps.gatewayBaseUrl.replace(/\/+$/, '');
  const approved = args.answer === 'GREEN';

  const sessionRes = await postJson(`${base}/v1/session`, {
    wallet_c_addr: args.cAddr,
    chain_id: 'testnet',
  });
  if (sessionRes.status !== 201) {
    throw new Error(
      `POST /v1/session returned ${sessionRes.status}, expected 201: ${JSON.stringify(sessionRes.json)}`,
    );
  }
  const sessionJson = asObject(sessionRes.json);
  const sessionId = requireString(sessionJson['session_id'], 'session_id');
  const sessionToken = requireString(sessionJson['session_token'], 'session_token');

  await args.emit({
    id: 'session',
    title: 'Open onboarding session',
    detail:
      'POST /v1/session opened a session for the wallet contract address and created the ' +
      "provider-side applicant through the gateway's applicant seam.",
    status: 'ok',
    data: { sessionId, subject: args.cAddr },
  });

  const applicantId = deps.kyc.applicantForSession(sessionId);
  if (applicantId === undefined) {
    throw new Error(`no applicant was registered for session ${sessionId}`);
  }
  deps.kyc.decide(applicantId, args.answer, args.applicant);
  if (approved) deps.approveSession(sessionId);

  await args.emit({
    id: 'verdict',
    title: approved ? 'KYC provider approves' : 'KYC provider refuses',
    detail: approved
      ? 'The provider (mocked in this demo) verified the applicant and reported an approval; ' +
        'the gateway marked the session approved.'
      : 'The provider (mocked in this demo) refused the applicant. The session stays pending, ' +
        'so nothing can be issued for it.',
    status: 'ok',
    data: { answer: approved ? 'approved' : 'rejected' },
  });

  return { sessionId, sessionToken, applicantId };
}

async function runRejectedPath(deps: DemoDeps, args: RunContext): Promise<OnboardingResult> {
  const base = deps.gatewayBaseUrl.replace(/\/+$/, '');
  const { emit } = args;

  let refusalMessage: string;
  try {
    const rejectedStatus = await deps.kyc.fetchStatus(args.applicantId);
    deps.kyc.deriveClaims(rejectedStatus, new Date());
    throw new Error('expected deriveClaims to refuse a rejected applicant, but it returned a claim set');
  } catch (err) {
    if (!(err instanceof ClaimDerivationError)) throw err;
    refusalMessage = err.message;
  }

  await emit({
    id: 'claims',
    title: 'Derive claim set',
    detail: refusalMessage,
    status: 'fail',
    data: { refused: 'ClaimDerivationError' },
  });

  const refused = await postJson(
    `${base}/v1/credentials/issue`,
    {
      sessionId: args.sessionId,
      over18: false,
      over21: false,
      notSanctioned: false,
      notPep: false,
      jurisdictionOk: false,
      livenessOk: false,
    },
    args.sessionToken,
  );
  const refusedJson = asObject(refused.json);
  const refusedCode = asObject(refusedJson['error'])['code'];
  if (refused.status !== 409 || refusedCode !== 'session_not_approved') {
    throw new Error(
      `POST /v1/credentials/issue returned ${refused.status} ` +
        `${JSON.stringify(refusedCode)}, expected 409 session_not_approved`,
    );
  }

  await emit({
    id: 'issue',
    title: 'Attempt credential issuance',
    detail:
      'POST /v1/credentials/issue answered 409 session_not_approved: the session gate refuses ' +
      'before any credential is minted, so there is nothing to prove.',
    status: 'fail',
    data: { httpStatus: refused.status, code: refusedCode },
  });

  await emit({
    id: 'noWrite',
    title: 'No chain write',
    detail: 'No transaction was submitted and the subject holds no claim record.',
    status: 'ok',
    data: { transactions: 0 },
  });

  return { ok: true, subject: args.cAddr };
}

async function runApprovedPath(deps: DemoDeps, args: RunContext): Promise<OnboardingResult> {
  const { cAddr, emit } = args;
  const base = deps.gatewayBaseUrl.replace(/\/+$/, '');

  const server = new rpc.Server(deps.rpcUrl);
  const submitter = new AttestSubmitter({
    server,
    networkPassphrase: deps.networkPassphrase,
    submitter: deps.submitter,
  });

  /* --- 3. claim derivation ---------------------------------------------- */

  const status = await deps.kyc.fetchStatus(args.applicantId);
  const claims = deps.kyc.deriveClaims(status, new Date());

  await emit({
    id: 'claims',
    title: 'Derive claim set (personal data discarded)',
    detail:
      "The provider's status was turned into six booleans in memory; the source attributes are " +
      'discarded here. Only the booleans travel any further.',
    status: 'ok',
    data: { claims },
  });

  /* --- 4. credential issue ---------------------------------------------- */

  const issueRes = await postJson(
    `${base}/v1/credentials/issue`,
    { sessionId: args.sessionId, ...claims },
    args.sessionToken,
  );
  if (issueRes.status !== 201) {
    throw new Error(
      `POST /v1/credentials/issue returned ${issueRes.status}, expected 201: ${JSON.stringify(issueRes.json)}`,
    );
  }
  const issueJson = asObject(issueRes.json);
  const credentialField = issueJson['credential'];
  if (credentialField === null || typeof credentialField !== 'object') {
    throw new Error('POST /v1/credentials/issue returned no credential object');
  }
  const serialized = credentialField as SerializedCredential;
  const claimBitmap = requireInteger(issueJson['claim_bitmap'], 'claim_bitmap');
  const revocationIndex = requireInteger(issueJson['revocation_index'], 'revocation_index');
  const saltHex = issueJson['subject_binding_salt'];
  if (typeof saltHex !== 'string' || !/^[0-9a-f]{64}$/.test(saltHex)) {
    throw new Error('POST /v1/credentials/issue returned no 32-byte subject_binding_salt');
  }

  await emit({
    id: 'credential',
    title: 'Issue BBS+ credential',
    detail:
      'POST /v1/credentials/issue (Bearer session JWT) returned a BBS+ credential signing all ' +
      'twelve schema attributes for this wallet. The gateway keeps no copy.',
    status: 'ok',
    data: { claimBitmap, revocationIndex, attributes: CLAIM_SPECS.length },
  });

  /* --- 5. holder custody ------------------------------------------------ */

  const credential = deserializeCredential(serialized);
  if (deps.credentialStore !== undefined) {
    await deps.credentialStore.put({
      credential,
      subjectBindingSalt: Uint8Array.from(Buffer.from(saltHex, 'hex')),
      walletAddress: cAddr,
      storedAt: deps.now(),
    });
    await emit({
      id: 'custody',
      title: 'Store the credential holder-side',
      detail:
        'The credential and its 32-byte subject-binding salt went into the holder store keyed by ' +
        'the wallet address. With them the holder can derive a fresh proof later without being ' +
        're-verified.',
      status: 'ok',
      data: { wallet: cAddr, saltBytes: 32 },
    });
  }

  /* --- 6. selective-disclosure proof ------------------------------------ */

  const binding = {
    nonce: randomNonce(),
    walletAddress: cAddr,
    contractId: deps.gateContractId,
    networkPassphrase: deps.networkPassphrase,
    ledgerExpiry: await ledgerExpiryFor(server),
  };
  const proof = await prove(credential, gateOnrampPredicate(), binding);

  const withheld = CLAIM_SPECS.filter((spec) => !proof.disclosedIndexes.includes(spec.index)).map(
    (spec) => spec.name,
  );

  await emit({
    id: 'proof',
    title: 'Derive selective-disclosure proof',
    detail:
      'prove(credential, gateOnrampPredicate(), binding) revealed only the metadata block plus the ' +
      'two gate booleans; every other attribute stays hidden under the same signature.',
    status: 'ok',
    data: {
      disclosed: [...proof.disclosedMessages],
      withheld,
      nonce: binding.nonce,
      ledgerExpiry: binding.ledgerExpiry,
    },
  });

  /* --- 7. PII scan ------------------------------------------------------ */

  const serializedProof = serializeProof(proof);
  const wire = Buffer.from(JSON.stringify(serializedProof), 'utf8');
  // Search the string leaves: a leak lands in a disclosed message or a field, never inside a
  // u32, and a short document number would otherwise collide with random hex by chance.
  const textLeaves = Buffer.from(stringLeaves(serializedProof).join('\n'), 'utf8');
  const dobHits = findEncodings(textLeaves, args.applicant.dateOfBirth);
  const documentHits = findEncodings(textLeaves, args.applicant.documentNumber);
  if (dobHits.length !== 0 || documentHits.length !== 0) {
    throw new Error(
      `PII leaked into the presentation: date of birth as ${dobHits.join(', ') || 'none'}, ` +
        `document number as ${documentHits.join(', ') || 'none'}`,
    );
  }
  const control = `over18=${String(claims.over18)}`;
  if (findEncodings(textLeaves, control).length === 0) {
    throw new Error(`the PII detector cannot find "${control}", which the proof discloses`);
  }

  await emit({
    id: 'piiScan',
    title: 'Scan the proof for personal data',
    detail:
      "Hunted the applicant's date of birth and document number across every string in the " +
      'serialised presentation, in four encodings (utf-8, hex, base64, sha256). Both came back ' +
      'empty, while a value the proof DOES disclose was found, so a clean scan is not vacuous.',
    status: 'ok',
    data: {
      bytesSearched: textLeaves.length,
      bytesInPresentation: wire.length,
      dateOfBirth: '0 hits',
      documentNumber: '0 hits',
      control: 'found',
    },
  });

  /* --- 8. issuer preflight ---------------------------------------------- */

  const issuerIdHex = issuerIdFromPublicKey(deps.issuerPublicKey);
  await assertIssuerActive(submitter, deps.registryContractId, issuerIdHex, deps.issuerPublicKey);

  await emit({
    id: 'preflight',
    title: 'Issuer preflight against kyc-registry',
    detail:
      'kyc-registry.active_key(issuerId) returned this issuer key, so attest_bbs will verify the ' +
      'proof against a key the chain already trusts.',
    status: 'ok',
    data: { issuerId: issuerIdHex, registry: deps.registryContractId },
  });

  /* --- 9. submit attest_bbs --------------------------------------------- */

  const sim = new SorobanGateSimulator({
    rpcUrl: deps.rpcUrl,
    networkPassphrase: deps.networkPassphrase,
    gateContractId: deps.gateContractId,
  });
  const { revocationEpoch } = await readSubjectChainState(sim, cAddr);
  const expiresAt = await recordExpiresAtFor(server, RECORD_LIFETIME_LEDGERS);

  const bbsArgs = attestBbsArgs({
    subject: cAddr,
    issuerId: issuerIdHex,
    claimsBitmap: deriveGrantedClaims(proof),
    expiresAt,
    revocationEpoch,
    revocationIndex,
    proof,
    nonceHex: binding.nonce,
    ledgerExpiry: binding.ledgerExpiry,
  });
  const landed = await submitter.submit(
    contractCall(deps.gateContractId, 'attest_bbs', ...bbsArgs),
    'attest_bbs',
  );
  const txHash = landed.hash;
  const explorerUrl = `${deps.explorerBase}/tx/${txHash}`;

  await emit({
    id: 'submit',
    title: 'Submit attest_bbs to testnet',
    detail:
      'kyc-gate.attest_bbs ran the BLS12-381 pairing itself and wrote the claim record. No ' +
      "operator's signature is in the trust path.",
    status: 'ok',
    txHash,
    explorerUrl,
    data: {
      instructions: landed.instructions,
      feeChargedStroops: landed.feeChargedStroops,
      writeBytes: landed.writeBytes,
    },
  });

  /* --- 10. verify on chain ---------------------------------------------- */

  const checkOver18 = await submitter.simulateRead(
    contractCall(deps.gateContractId, 'check', addrScVal(cAddr), u32(CLAIM_OVER_18)),
    'check(subject, OVER_18)',
  );
  const checkOver21 = await submitter.simulateRead(
    contractCall(deps.gateContractId, 'check', addrScVal(cAddr), u32(CLAIM_OVER_21)),
    'check(subject, OVER_21)',
  );
  if (checkOver18 !== claims.over18) {
    throw new Error(
      `on-chain check(OVER_18) = ${String(checkOver18)} disagrees with the derived claim set ` +
        `(${String(claims.over18)})`,
    );
  }

  await emit({
    id: 'check',
    title: 'Verify on chain (check)',
    detail:
      `check(subject, OVER_18) = ${String(checkOver18)}, exactly what the claim set derived from ` +
      `the date of birth says. check(subject, OVER_21) = ${String(checkOver21)}: the proof never ` +
      'disclosed that attribute, so the chain never learned it.',
    status: 'ok',
    data: { over18: checkOver18, over21: checkOver21 },
  });

  return { ok: true, subject: cAddr, txHash, claimBitmap, revocationIndex };
}

/** Run the onboarding pipeline for a wallet the caller owns. */
export async function runOnboardingPipeline(
  deps: DemoDeps,
  args: { cAddr: string; answer: 'GREEN' | 'RED'; applicant?: Applicant; emit: EmitStep },
): Promise<OnboardingResult> {
  const applicant = args.applicant ?? DEFAULT_APPLICANT;
  const { sessionId, sessionToken, applicantId } = await openSessionAndDecide(deps, {
    ...args,
    applicant,
  });
  const context: RunContext = {
    cAddr: args.cAddr,
    sessionId,
    sessionToken,
    applicantId,
    applicant,
    emit: args.emit,
  };
  try {
    return args.answer === 'GREEN'
      ? await runApprovedPath(deps, context)
      : await runRejectedPath(deps, context);
  } finally {
    deps.kyc.forgetApplicant(applicantId);
  }
}

/* -------------------------------------------------------------------------- */
/* Read-only view of a subject's record                                        */
/* -------------------------------------------------------------------------- */

export interface OnChainRecordView {
  subject: string;
  hasRecord: boolean;
  record: Record<string, unknown> | null;
  check: { over18: boolean; over21: boolean };
}

export async function readOnChainRecord(deps: DemoDeps, cAddr: string): Promise<OnChainRecordView> {
  const server = new rpc.Server(deps.rpcUrl);
  const submitter = new AttestSubmitter({
    server,
    networkPassphrase: deps.networkPassphrase,
    submitter: deps.submitter,
  });

  let record: Record<string, unknown> | null = null;
  try {
    const raw = await submitter.simulateRead(
      contractCall(deps.gateContractId, 'claim_record', addrScVal(cAddr)),
      'claim_record',
    );
    const safe = jsonSafe(raw);
    record =
      safe !== null && typeof safe === 'object' && !Array.isArray(safe)
        ? (safe as Record<string, unknown>)
        : null;
  } catch {
    record = null;
  }

  const readBool = async (op: ReturnType<typeof contractCall>, label: string): Promise<boolean> => {
    try {
      return (await submitter.simulateRead(op, label)) === true;
    } catch {
      return false;
    }
  };

  const over18 = await readBool(
    contractCall(deps.gateContractId, 'check', addrScVal(cAddr), u32(CLAIM_OVER_18)),
    'check(OVER_18)',
  );
  const over21 = await readBool(
    contractCall(deps.gateContractId, 'check', addrScVal(cAddr), u32(CLAIM_OVER_21)),
    'check(OVER_21)',
  );

  return { subject: cAddr, hasRecord: record !== null, record, check: { over18, over21 } };
}
