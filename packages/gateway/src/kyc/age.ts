/**
 * Age arithmetic, in UTC, from a date of birth that is DISCARDED immediately afterwards.
 *
 * packages/identity/src/schema.ts header): BBS+ cannot range-prove a date of birth. `deriveProof`
 * takes `disclosedMessageIndexes` — a set of WHOLE-message reveal/hide selectors — and there is no
 * bounds, threshold, range or predicate parameter anywhere in
 * draft-irtf-cfrg-bbs-signatures-08. So the holder either reveals `dob=1990-05-04` in full or proves
 * NOTHING about it, and a disclosed DOB is a near-unique correlation handle (1-in-36,500 before you
 * even add a country). Therefore the ISSUER computes the booleans and signs THOSE. The DOB exists in
 * this process's memory for the duration of one function call and is never persisted, logged or put
 * in an error message. Do not propose range proofs here; do not reach for
 * `@docknetwork/crypto-wasm-ts`, which is on the enforced denylist in
 * scripts/check-single-stellar-sdk.mjs.
 *
 * THE TIMEZONE IS UTC, ALWAYS, AND THAT IS A DECISION.
 *
 * A birthday is a civil-calendar fact and a person turns 18 at midnight in THEIR jurisdiction, which
 * is not the same instant as midnight in ours. There are three candidate answers and only one is
 * defensible for this system:
 *
 *   1. UTC (chosen). Deterministic, reproducible from the stored inputs alone, identical on every
 *      host, and identical for the same applicant regardless of which region the gateway replica ran
 *      in. It can be up to ~14 hours EARLY relative to a jurisdiction at UTC-11 and up to ~14 hours
 *      LATE relative to one at UTC+14, on the birthday itself only.
 *   2. The host's local timezone. REFUSED. "Whatever `TZ` happened to be set to in this container"
 *      is not a policy; it makes two replicas disagree about one applicant on one day a year, and it
 *      makes the result unreproducible during an audit.
 *   3. The applicant's residence timezone. Refused for now — it needs a country in the derivation
 *      input, a country-to-timezone table with the multi-zone countries resolved, and it still gets
 *      the answer wrong for a person who is travelling. It would also mean the residence country
 *      influencing the boolean in a way that is invisible in the credential, which conflicts with
 *      the honest fix is a per-jurisdiction OFFSET applied to `at`, not a change here.
 *
 * The conservative direction, if anyone wants to eliminate case 1's early window: subtract a day of
 * grace from `at`. That trades "up to 14 hours early in UTC-11" for "up to 34 hours late
 * everywhere", i.e. it denies service to a legitimately-18 applicant for a day. Not done; recorded
 * so the trade is visible rather than rediscovered.
 */

export class AgeError extends Error {
  override readonly name = 'AgeError';
}

/**
 * `YYYY-MM-DD`, and nothing else. Deliberately narrower than `Date`'s parser.
 *
 * `new Date('1990-5-4')` is implementation-defined, `new Date('05/04/1990')` is ambiguous between
 * two continents' conventions, and `new Date('1990-02-30')` silently becomes 2 March. All three are
 * ways to compute a confident wrong age, so the format is pinned and the components are
 * round-trip-checked below.
 */
const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

export interface CalendarDate {
  readonly year: number;
  readonly month: number;
  readonly day: number;
}

/**
 * Parse `YYYY-MM-DD` into calendar components, rejecting anything that is not a real date.
 *
 * The round-trip through `Date.UTC` is what catches `1990-02-30` and `2023-02-29`: JavaScript rolls
 * those forward, so if the reconstructed components differ from the supplied ones, the supplied ones
 * named a day that does not exist.
 *
 * The ERROR MESSAGE NEVER CONTAINS THE INPUT. This function's input is a date of birth, and spec
 * §3.2 hard rule 1 forbids a DOB in "gateway storage, logs, traces, or error payloads" — error
 * payloads specifically. `"1990-05-04" is not a valid date` would be a PII leak in a stack trace,
 * and a stack trace is the single most-copied artefact in an incident channel.
 */
export function parseCalendarDate(value: unknown): CalendarDate {
  if (typeof value !== 'string') {
    throw new AgeError(
      'refusing to derive an age because the date of birth is not a string; the value is not ' +
        'echoed here because the design forbids a DOB in any error payload',
    );
  }
  const m = ISO_DATE.exec(value);
  if (m === null) {
    throw new AgeError(
      'refusing to derive an age because the date of birth is not in YYYY-MM-DD form (the value ' +
        'is deliberately not echoed; the design forbids a DOB in an error payload). Date parsing is ' +
        'strict on purpose: new Date("05/04/1990") is ambiguous between two continents and ' +
        'new Date("1990-02-30") silently becomes 2 March.',
    );
  }
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const roundTrip = new Date(Date.UTC(year, month - 1, day));
  if (
    roundTrip.getUTCFullYear() !== year ||
    roundTrip.getUTCMonth() !== month - 1 ||
    roundTrip.getUTCDate() !== day
  ) {
    throw new AgeError(
      'refusing to derive an age because the date of birth names a day that does not exist ' +
        '(e.g. 30 February, or 29 February in a non-leap year); the value is not echoed, per ' +
        'the no-PII rule',
    );
  }
  return { year, month, day };
}

/**
 * Completed years between `dobIso` and `at`, evaluated in UTC.
 *
 * 29 FEBRUARY, and this is the case everyone gets wrong. A person born 2004-02-29 has no birthday in
 * 2021. The comparison below is on the (month, day) PAIR, so on 2021-02-28 the pair (2,28) is before
 * (2,29) and the age is 16; on 2021-03-01 the pair (3,1) is after (2,29) and the age is 17. That is
 * the widely-used common-law convention (England & Wales, and the US majority rule): the leapling
 * has their birthday on 1 March in a common year. Some jurisdictions say 28 February instead. The
 * difference is ONE DAY, ONCE EVERY FOUR YEARS, in the CONSERVATIVE direction (we say not-yet-18
 * for one extra day), which is the safe way to be wrong for a compliance boolean. Recorded so that
 * whoever gets the regulator's question already has the answer.
 *
 * A FUTURE DOB is refused rather than returned as a negative number. A negative age would compare
 * `>= 18` as false and therefore fail safe, but it would fail safe by accident — and it is a signal
 * that the provider payload or our clock is wrong, which is worth an alert rather than a `false`.
 */
export function ageAtUtc(dobIso: unknown, at: Date): number {
  if (!(at instanceof Date) || Number.isNaN(at.getTime())) {
    throw new AgeError('refusing to derive an age against an invalid evaluation instant');
  }
  const dob = parseCalendarDate(dobIso);
  let age = at.getUTCFullYear() - dob.year;
  const atMonth = at.getUTCMonth() + 1;
  const atDay = at.getUTCDate();
  const beforeBirthday = atMonth < dob.month || (atMonth === dob.month && atDay < dob.day);
  if (beforeBirthday) age -= 1;
  if (age < 0) {
    throw new AgeError(
      'refusing to derive an age from a date of birth in the FUTURE; a negative age would compare ' +
        'as "not over 18" and fail safe by accident, which hides a bad provider payload or a bad ' +
        'clock instead of surfacing it',
    );
  }
  // A 150-year-old applicant is a data error, not a customer. Same reasoning as the future case:
  // failing safe by accident is not failing safe.
  if (age > 150) {
    throw new AgeError(
      `refusing to derive an age of ${age} years; this is a malformed provider payload, not an ` +
        'applicant',
    );
  }
  return age;
}

/** Age thresholds this system asserts. Mirrors CLAIM_INDEX.over18 / over21 in identity's schema. */
export const AGE_THRESHOLDS = Object.freeze({ over18: 18, over21: 21 });

/**
 * The only two age facts the credential carries, computed together so a caller cannot compute one
 * and forget the other. Both come from a single parse, so a DOB that is unusable for one is unusable
 * for both — there is no path where `over18` is derived and `over21` is silently defaulted to
 * `false`, which would understate a 25-year-old's claims.
 */
export function deriveAgeClaims(
  dobIso: unknown,
  at: Date,
): { readonly over18: boolean; readonly over21: boolean } {
  const age = ageAtUtc(dobIso, at);
  return { over18: age >= AGE_THRESHOLDS.over18, over21: age >= AGE_THRESHOLDS.over21 };
}
