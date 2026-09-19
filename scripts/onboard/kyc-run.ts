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

import type { DemoStep, EmitStep, OnboardingResult } from '../demo/demo-flow.js';

/** One frame of a run's life. `step` frames stream; `done`/`error` are terminal. */
export type RunEvent =
  | { readonly type: 'step'; readonly step: DemoStep }
  | { readonly type: 'done'; readonly result: OnboardingResult }
  | { readonly type: 'error'; readonly message: string };

/** What the registry hands back when a run finishes, so the caller can persist the outcome. */
export interface RunCompletion {
  readonly result?: OnboardingResult;
  readonly error?: string;
}

interface RunState {
  readonly id: string;
  readonly accountId: string;
  readonly events: RunEvent[];
  done: boolean;
  readonly listeners: Set<(event: RunEvent) => void>;
}

/** In-memory registry of in-flight and just-finished runs. */
export class InMemoryRunRegistry {
  readonly #runs = new Map<string, RunState>();

  /**
   * Register a run and start it immediately (without awaiting). `runner` is the pipeline; it is
   * handed an emitter that buffers and fans out. `onComplete` fires exactly once, after the
   * terminal event, so the caller can write the verdict to the account store.
   */
  start(
    accountId: string,
    runner: (emit: EmitStep) => Promise<OnboardingResult>,
    onComplete?: (completion: RunCompletion) => void,
  ): string {
    const id = randomUUID();
    const state: RunState = {
      id,
      accountId,
      events: [],
      done: false,
      listeners: new Set(),
    };
    this.#runs.set(id, state);

    void (async () => {
      const emit: EmitStep = (step) => {
        this.#publish(state, { type: 'step', step });
      };
      try {
        const result = await runner(emit);
        this.#publish(state, { type: 'done', result });
        onComplete?.({ result });
      } catch (err) {
        const message = String((err as Error)?.message ?? err);
        this.#publish(state, { type: 'error', message });
        onComplete?.({ error: message });
      }
    })();

    return id;
  }

  #publish(state: RunState, event: RunEvent): void {
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
    listener: (event: RunEvent) => void,
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

  /** True iff this account has a run that has not yet reached a terminal event. */
  hasActiveRun(accountId: string): boolean {
    for (const state of this.#runs.values()) {
      if (state.accountId === accountId && !state.done) return true;
    }
    return false;
  }

  get size(): number {
    return this.#runs.size;
  }
}
