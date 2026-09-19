/**
 * The run registry that turns a KYC submission into a STREAMABLE run.
 *
 * THE PROBLEM IT SOLVES. `POST /api/kyc/submit` carries the wizard's payload (a JSON body, so it
 * must be a POST), but the progress has to arrive as Server-Sent Events, and a browser
 * `EventSource` can only issue a GET (the same constraint `scripts/demo-web.ts` documents for
 * `/demo/run`). Rather than smuggle form data through a query string, the POST starts the run and
 * returns an id; the page then opens `GET /api/kyc/stream?runId=…` and receives the frames.
 *
 * THE RACE THE BUFFER CLOSES. The stream almost never connects before the first step has already
 * been emitted — the pipeline starts the moment the POST returns. So every event is BUFFERED on
 * the run, and a late subscriber has the backlog replayed to it synchronously before it starts
 * receiving live events. Without that, the first frames would simply be lost and the page would
 * look like the run started halfway through.
 *
 * OWNERSHIP IS CHECKED AT SUBSCRIBE TIME. A run id is a bearer capability; `subscribe` takes the
 * caller's account id and refuses a run it does not own, so one signed-in account cannot read
 * another's stream even if it guesses an id.
 */

import { randomUUID } from 'node:crypto';

import type { DemoStep, EmitStep } from '../demo/demo-flow.js';

/** One frame of a run's life. `step` frames stream; `done`/`error` are terminal. */
export type RunEvent<R = unknown> =
  | { readonly type: 'step'; readonly step: DemoStep }
  | { readonly type: 'done'; readonly result: R }
  | { readonly type: 'error'; readonly message: string };

/** What the registry hands back when a run finishes, so the caller can persist the outcome. */
export interface RunCompletion<R = unknown> {
  readonly result?: R;
  readonly error?: string;
  /**
   * The runner settled AFTER the run was already abandoned by the timeout. Nothing was published
   * to subscribers (the stream is long closed), but the outcome is real — a record may have
   * landed on chain — so the completion callback still gets it and may persist it.
   */
  readonly late?: boolean;
}

/** What a runner may ask mid-flight. */
export interface RunContext {
  /** True once the run has been abandoned (timeout): persist nothing that would race a retry. */
  readonly finished: () => boolean;
}

interface RunState<R> {
  readonly id: string;
  readonly accountId: string;
  readonly events: RunEvent<R>[];
  done: boolean;
  readonly listeners: Set<(event: RunEvent<R>) => void>;
}

export interface RunRegistryOptions {
  /** A run still open after this long is abandoned with an `error` event. Default 5 min. */
  readonly timeoutMs?: number;
  /** How long a finished run stays readable (for late reattaches). Default 1 h. */
  readonly retainMs?: number;
}

/**
 * In-memory registry of in-flight and just-finished runs.
 *
 * A run is abandoned with an `error` event after `timeoutMs` (the runner is NOT cancelled — see
 * `finish` — but its account can start again), and a finished run stays readable for `retainMs`
 * so a page that reconnects still gets the tail, then is evicted. This backs a long-lived hosted
 * process, so both bounds matter.
 */
export class InMemoryRunRegistry<R = unknown> {
  readonly #runs = new Map<string, RunState<R>>();
  readonly #timeoutMs: number;
  readonly #retainMs: number;

  constructor(options: RunRegistryOptions = {}) {
    this.#timeoutMs = options.timeoutMs ?? 5 * 60_000;
    this.#retainMs = options.retainMs ?? 60 * 60_000;
  }

  /**
   * Register a run and start it immediately (without awaiting). `runner` is the pipeline; it is
   * handed an emitter that buffers and fans out. `onComplete` fires exactly once, after the
   * terminal event, so the caller can write the verdict to the account store.
   */
  start(
    accountId: string,
    runner: (emit: EmitStep, ctx: RunContext) => Promise<R>,
    onComplete?: (completion: RunCompletion<R>) => void,
  ): string {
    const id = randomUUID();
    const state: RunState<R> = {
      id,
      accountId,
      events: [],
      done: false,
      listeners: new Set(),
    };
    this.#runs.set(id, state);

    // Exactly ONE terminal outcome per run, whichever comes first: the runner settling or the
    // timeout. A runner that settles after the timeout is dropped on the floor (its account
    // state was already left `pending` by the timeout's completion); a hung RPC or relayer call
    // can therefore never pin `activeRunId` forever.
    let completed = false;
    const finish = (event: RunEvent<R>, completion: RunCompletion<R>): void => {
      if (completed) {
        // The runner settling after the timeout: not published, but not dropped either.
        if (event.type !== 'error' || completion.result !== undefined) onComplete?.({ ...completion, late: true });
        return;
      }
      completed = true;
      clearTimeout(timer);
      this.#publish(state, event);
      onComplete?.(completion);
      const evict = setTimeout(() => this.#runs.delete(id), this.#retainMs);
      evict.unref?.();
    };
    const timer = setTimeout(() => {
      const message =
        `the run exceeded ${Math.round(this.#timeoutMs / 60_000)} minutes and was abandoned; ` +
        'it may still finish on chain — refresh the page to check your status';
      finish({ type: 'error', message }, { error: message });
    }, this.#timeoutMs);
    timer.unref?.();

    void (async () => {
      const emit: EmitStep = (step) => {
        if (!completed) this.#publish(state, { type: 'step', step });
      };
      try {
        const result = await runner(emit, { finished: () => completed });
        finish({ type: 'done', result }, { result });
      } catch (err) {
        const message = String((err as Error)?.message ?? err);
        finish({ type: 'error', message }, { error: message });
      }
    })();

    return id;
  }

  #publish(state: RunState<R>, event: RunEvent<R>): void {
    state.events.push(event);
    if (event.type !== 'step') state.done = true;
    // Copy before iterating: a listener that unsubscribes itself (a stream that closed) must not
    // mutate the set mid-dispatch.
    for (const listener of [...state.listeners]) listener(event);
  }

  /**
   * Replay a run's buffered events to `listener`, then keep it subscribed for live ones.
   *
   * Returns an unsubscribe function, or `undefined` when the run does not exist or belongs to
   * another account — the caller answers that case with 404 rather than leaking whether the id
   * exists.
   */
  subscribe(
    runId: string,
    accountId: string,
    listener: (event: RunEvent<R>) => void,
  ): (() => void) | undefined {
    const state = this.#runs.get(runId);
    if (state === undefined || state.accountId !== accountId) return undefined;
    for (const event of state.events) listener(event);
    if (state.done) return () => {};
    state.listeners.add(listener);
    return () => {
      state.listeners.delete(listener);
    };
  }

  /** Whether a run exists and has reached a terminal event. */
  isDone(runId: string): boolean {
    return this.#runs.get(runId)?.done ?? false;
  }

  /**
   * The run's owning account and terminal state, or `undefined` when no such run exists.
   *
   * This is the ownership check the SSE route makes BEFORE it writes any headers, so an unknown or
   * foreign run id answers 404 rather than opening a stream that will never carry anything.
   */
  describe(runId: string): { accountId: string; done: boolean } | undefined {
    const state = this.#runs.get(runId);
    return state === undefined ? undefined : { accountId: state.accountId, done: state.done };
  }

  /** The id of the account's open run, if any — so a page can reattach instead of erroring. */
  activeRunId(accountId: string): string | undefined {
    for (const state of this.#runs.values()) {
      if (state.accountId === accountId && !state.done) return state.id;
    }
    return undefined;
  }

  /** True iff this account has a run that has not yet reached a terminal event. */
  hasActiveRun(accountId: string): boolean {
    return this.activeRunId(accountId) !== undefined;
  }

  get activeCount(): number {
    let n = 0;
    for (const state of this.#runs.values()) if (!state.done) n += 1;
    return n;
  }

  get size(): number {
    return this.#runs.size;
  }
}
