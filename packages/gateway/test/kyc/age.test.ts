/**
 * K3 age arithmetic. The classic source of off-by-one-day bugs, so every boundary the brief named
 * has a test: the exact birthday, the day before, the day after, 29 February in and out of leap
 * years, a timezone-shifted boundary, a future DOB, an unparseable DOB, and an absent DOB.
 *
 * THE TIMEZONE IS UTC AND THAT IS THE DECISION. See src/kyc/age.ts's header for the full argument
 * (three candidates, only one reproducible). The `TZ` test below is what makes it a fact rather than
 * an intention.
 */

import { describe, expect, it } from 'vitest';

import {
  AGE_THRESHOLDS,
  AgeError,
  ageAtUtc,
  deriveAgeClaims,
  parseCalendarDate,
} from '../../src/kyc/age.js';

const utc = (iso: string): Date => new Date(`${iso}T12:00:00.000Z`);

describe('the age boundary lands on the exact right day', () => {
  it('is 17 the DAY BEFORE the 18th birthday', () => {
    expect(ageAtUtc('2008-06-15', utc('2026-06-14'))).toBe(17);
  });

  it('is 18 ON the 18th birthday', () => {
    expect(ageAtUtc('2008-06-15', utc('2026-06-15'))).toBe(18);
  });

  it('is 18 the DAY AFTER the 18th birthday', () => {
    expect(ageAtUtc('2008-06-15', utc('2026-06-16'))).toBe(18);
  });

  it('flips over18 exactly at the birthday, not a day either side', () => {
    const dob = '2008-06-15';
    expect(deriveAgeClaims(dob, utc('2026-06-14')).over18).toBe(false);
    expect(deriveAgeClaims(dob, utc('2026-06-15')).over18).toBe(true);
    expect(deriveAgeClaims(dob, utc('2026-06-16')).over18).toBe(true);
  });

  it('flips over21 three years later than over18, independently', () => {
    const dob = '2005-06-15';
    expect(deriveAgeClaims(dob, utc('2023-06-15'))).toEqual({ over18: true, over21: false });
    expect(deriveAgeClaims(dob, utc('2026-06-14'))).toEqual({ over18: true, over21: false });
    expect(deriveAgeClaims(dob, utc('2026-06-15'))).toEqual({ over18: true, over21: true });
  });

  it('handles a month boundary: 31 Dec -> 1 Jan', () => {
    expect(ageAtUtc('2008-01-01', utc('2025-12-31'))).toBe(17);
    expect(ageAtUtc('2008-01-01', utc('2026-01-01'))).toBe(18);
  });

  it('handles a birthday on 31 December', () => {
    expect(ageAtUtc('2007-12-31', utc('2025-12-30'))).toBe(17);
    expect(ageAtUtc('2007-12-31', utc('2025-12-31'))).toBe(18);
  });

  it('pins the two thresholds against the schema claim names', () => {
    expect(AGE_THRESHOLDS.over18).toBe(18);
    expect(AGE_THRESHOLDS.over21).toBe(21);
    expect(Object.isFrozen(AGE_THRESHOLDS)).toBe(true);
  });
});

describe('29 FEBRUARY, the case everyone gets wrong', () => {
  /**
   * A person born 2004-02-29 has NO birthday in 2021 (not a leap year). The implementation compares
   * the (month, day) PAIR, so (2,28) < (2,29) -> not yet, and (3,1) > (2,29) -> yes. That is the
   * common-law convention (England & Wales, US majority rule): the leapling's birthday is 1 March in
   * a common year. Some jurisdictions say 28 February. The difference is ONE DAY, ONCE IN FOUR YEARS,
   * in the CONSERVATIVE direction — we say not-yet-18 for one extra day.
   */
  it('a 2004-02-29 leapling turns 17 on 1 MARCH 2021, not 28 February (common-law convention)', () => {
    expect(ageAtUtc('2004-02-29', utc('2021-02-27'))).toBe(16);
    expect(ageAtUtc('2004-02-29', utc('2021-02-28'))).toBe(16);
    expect(ageAtUtc('2004-02-29', utc('2021-03-01'))).toBe(17);
  });

  it('the SAME leapling turns 20 ON 29 February 2024, a real birthday in a leap year', () => {
    expect(ageAtUtc('2004-02-29', utc('2024-02-28'))).toBe(19);
    expect(ageAtUtc('2004-02-29', utc('2024-02-29'))).toBe(20);
    expect(ageAtUtc('2004-02-29', utc('2024-03-01'))).toBe(20);
  });

  it('errs CONSERVATIVELY: a leapling is never reported as over18 a day early', () => {
    // 18th birthday falls in 2022, a common year. Under the 28-Feb convention they would be 18 on
    // 2022-02-28; we say 17. Being a day LATE is the safe direction for a compliance boolean.
    expect(deriveAgeClaims('2004-02-29', utc('2022-02-28')).over18).toBe(false);
    expect(deriveAgeClaims('2004-02-29', utc('2022-03-01')).over18).toBe(true);
  });

  it('2000-02-29 is valid (a century leap year, divisible by 400)', () => {
    expect(parseCalendarDate('2000-02-29')).toEqual({ year: 2000, month: 2, day: 29 });
  });

  it('1900-02-29 is REJECTED (divisible by 100 but not 400, so not a leap year)', () => {
    expect(() => parseCalendarDate('1900-02-29')).toThrow(AgeError);
  });

  it('2023-02-29 is REJECTED rather than silently rolled to 1 March', () => {
    // new Date('2023-02-29') silently becomes 1 March. The round-trip check catches it.
    expect(() => parseCalendarDate('2023-02-29')).toThrow(AgeError);
  });
});

describe('the timezone the boundary is evaluated in is UTC, provably, not "whatever TZ is set to"', () => {
  /**
   * THE TEST THAT MAKES UTC A FACT. An instant just after midnight UTC on the birthday: in UTC the
   * person is 18. A host in a NEGATIVE offset zone (say UTC-5) reading that same instant with LOCAL
   * calendar functions sees the PREVIOUS day and would answer 17. Because the implementation uses
   * getUTC* exclusively, the answer does not move.
   */
  it('gives the same answer for an instant near midnight regardless of the host TZ', () => {
    const justAfterMidnightUtc = new Date('2026-06-15T00:00:30.000Z');
    const justBeforeMidnightUtc = new Date('2026-06-14T23:59:30.000Z');
    const original = process.env['TZ'];
    try {
      for (const tz of ['UTC', 'America/Los_Angeles', 'Asia/Tokyo', 'Pacific/Kiritimati', 'Etc/GMT+11']) {
        process.env['TZ'] = tz;
        expect(ageAtUtc('2008-06-15', justAfterMidnightUtc), `TZ=${tz} after midnight`).toBe(18);
        expect(ageAtUtc('2008-06-15', justBeforeMidnightUtc), `TZ=${tz} before midnight`).toBe(17);
      }
    } finally {
      if (original === undefined) delete process.env['TZ'];
      else process.env['TZ'] = original;
    }
  });

  it('an evaluation instant is read in UTC at both ends of a day', () => {
    expect(ageAtUtc('2008-06-15', new Date('2026-06-15T00:00:00.000Z'))).toBe(18);
    expect(ageAtUtc('2008-06-15', new Date('2026-06-15T23:59:59.999Z'))).toBe(18);
    expect(ageAtUtc('2008-06-15', new Date('2026-06-14T23:59:59.999Z'))).toBe(17);
  });

  it('documents UTC as a DECISION in the source, with the rejected alternatives named', async () => {
    const source = await import('node:fs/promises').then((fs) =>
      fs.readFile(new URL('../../src/kyc/age.ts', import.meta.url), 'utf8'),
    );
    expect(source).toContain('THE TIMEZONE IS UTC, ALWAYS, AND THAT IS A DECISION');
    expect(source).toContain("The host's local timezone. REFUSED");
    // And the implementation must not read a local-calendar getter anywhere.
    expect(source).not.toMatch(/\.getFullYear\(\)/);
    expect(source).not.toMatch(/\.getMonth\(\)/);
    expect(source).not.toMatch(/\.getDate\(\)/);
  });
});

describe('a DOB we cannot trust is an ERROR, never a false', () => {
  /**
   * `over18=false` from an unparseable DOB is indistinguishable from a legitimately 17-year-old
   * applicant, and the operational response to the two is completely different. So it throws.
   */
  it.each([
    ['absent', undefined],
    ['null', null],
    ['an empty string', ''],
    ['a number', 19900504],
    ['a Date object', new Date('1990-05-04')],
    ['an object', { dob: '1990-05-04' }],
    ['an array', ['1990-05-04']],
  ])('refuses a DOB that is %s', (_label, value) => {
    expect(() => ageAtUtc(value, utc('2026-06-15'))).toThrow(AgeError);
    expect(() => deriveAgeClaims(value, utc('2026-06-15'))).toThrow(AgeError);
  });

  it.each([
    ['single-digit month', '1990-5-04'],
    ['single-digit day', '1990-05-4'],
    ['US slash form, ambiguous between two continents', '05/04/1990'],
    ['European dot form', '04.05.1990'],
    ['a full ISO instant', '1990-05-04T00:00:00Z'],
    ['a two-digit year', '90-05-04'],
    ['month 13', '1990-13-01'],
    ['month 00', '1990-00-01'],
    ['day 00', '1990-05-00'],
    ['day 32', '1990-05-32'],
    ['30 February', '1990-02-30'],
    ['31 April', '1990-04-31'],
    ['trailing whitespace', '1990-05-04 '],
    ['leading whitespace', ' 1990-05-04'],
    ['a five-digit year', '19900-05-04'],
  ])('refuses %s', (_label, value) => {
    expect(() => parseCalendarDate(value)).toThrow(AgeError);
  });

  it('refuses a DOB in the FUTURE rather than returning a negative age that fails safe by ACCIDENT', () => {
    // A negative age would compare `>= 18` as false, i.e. it WOULD fail safe — but by accident, and
    // it would hide a bad provider payload or a bad clock.
    expect(() => ageAtUtc('2030-01-01', utc('2026-06-15'))).toThrow(/FUTURE/);
    expect(() => ageAtUtc('2026-06-16', utc('2026-06-15'))).toThrow(/FUTURE/);
  });

  it('refuses an absurd age (a 150+ year old is a data error, not a customer)', () => {
    expect(() => ageAtUtc('1800-01-01', utc('2026-06-15'))).toThrow(/malformed provider payload/);
  });

  it('refuses an invalid evaluation instant', () => {
    expect(() => ageAtUtc('1990-05-04', new Date('not a date'))).toThrow(AgeError);
    expect(() => ageAtUtc('1990-05-04', 0 as unknown as Date)).toThrow(AgeError);
  });

  /**
   * most-copied artefact in an incident channel. So the DOB must not appear in the message OR the
   * stack.
   */
  it('NEVER echoes the DOB into the error message or the stack', () => {
    // Deliberately NOT date-shaped like the static examples in age.ts's own message — see the
    // caveat test below for why that distinction had to be made explicit.
    for (const bad of ['2001/07/23', '2001-7-3', '23-07-2001', 'redacted-dob', '2001-02-30']) {
      let caught: Error | undefined;
      try {
        parseCalendarDate(bad);
      } catch (e) {
        caught = e as Error;
      }
      expect(caught).toBeInstanceOf(AgeError);
      expect(caught?.message, `"${bad}" must not be echoed`).not.toContain(bad);
      expect(caught?.stack ?? '', `"${bad}" must not reach the stack`).not.toContain(bad);
    }
  });

  it('the same holds for ageAtUtc and deriveAgeClaims, not just the parser', () => {
    for (const fn of [
      () => ageAtUtc('2001/07/23', utc('2026-06-15')),
      () => deriveAgeClaims('2001/07/23', utc('2026-06-15')),
      () => ageAtUtc('2030-07-23', utc('2026-06-15')), // the future-DOB path
    ]) {
      let caught: Error | undefined;
      try {
        fn();
      } catch (e) {
        caught = e as Error;
      }
      expect(caught).toBeInstanceOf(AgeError);
      expect(caught?.message).not.toContain('2001/07/23');
      expect(caught?.message).not.toContain('2030-07-23');
      expect(caught?.stack ?? '').not.toContain('2001/07/23');
    }
  });

  /**
   * A CAVEAT I FOUND BY WRITING THE TEST ABOVE, recorded rather than papered over.
   *
   * age.ts's message text contains two STATIC EXAMPLE DATES — `new Date("05/04/1990")` and
   * `new Date("1990-02-30")` — as documentation of why the parser is strict. They are constants in
   * the source and carry no applicant data. But they mean a naive "the DOB never appears in an error
   * message" scan produces a FALSE POSITIVE for the single applicant whose malformed DOB happens to
   * equal one of those literals. `1990-02-30` cannot be anyone's real DOB (it is not a real day, which
   * is why it is the example), and `05/04/1990` is not in the accepted input format at all, so the
   * false positive is unreachable in practice. It is pinned here so a future contributor who adds a
   * date-shaped example to an error message finds out that it interacts with the PII detector.
   */
  it('CAVEAT: the message carries STATIC example dates, which are documentation and not applicant data', () => {
    let caught: Error | undefined;
    try {
      parseCalendarDate('1990/05/04');
    } catch (e) {
      caught = e as Error;
    }
    // The static examples are present...
    expect(caught?.message).toContain('new Date("05/04/1990")');
    expect(caught?.message).toContain('new Date("1990-02-30")');
    expect(caught?.message).not.toContain('1990/05/04');
  });

  it('says WHY the value is withheld, so nobody "fixes" the message by adding it back', () => {
    let caught: Error | undefined;
    try {
      parseCalendarDate('1990/05/04');
    } catch (e) {
      caught = e as Error;
    }
    expect(caught?.message).toMatch(/not echoed|forbids a DOB/);
  });
});

describe('over18 and over21 are derived TOGETHER from one parse', () => {
  it('a DOB unusable for one is unusable for both — no silent over21=false for a 25-year-old', () => {
    // There must be no path where over18 is derived and over21 is defaulted to false.
    expect(deriveAgeClaims('1995-01-01', utc('2026-06-15'))).toEqual({ over18: true, over21: true });
    expect(() => deriveAgeClaims('bad', utc('2026-06-15'))).toThrow(AgeError);
  });

  it('over21 implies over18 for every DOB in a 40-year sweep (no inverted pair, ever)', () => {
    const at = utc('2026-06-15');
    for (let year = 1986; year <= 2026; year += 1) {
      for (const md of ['01-01', '02-28', '06-15', '12-31']) {
        let claims: { over18: boolean; over21: boolean };
        try {
          claims = deriveAgeClaims(`${year}-${md}`, at);
        } catch {
          continue; // future DOBs in 2026 throw, correctly
        }
        if (claims.over21) {
          expect(claims.over18, `${year}-${md}: over21 without over18 is impossible`).toBe(true);
        }
      }
    }
  });
});
