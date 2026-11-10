// Runs inside a worker thread with resource limits. Parses only; never evaluates target code.
import { parentPort } from 'node:worker_threads';
import ts from 'typescript';
import { measure, type JsJob } from './js-measure.js';

parentPort!.on('message', (job: JsJob) => {
  try {
    parentPort!.postMessage({ ok: true, result: measure(ts, job) });
  } catch (e) {
    const err = e as Error;
    parentPort!.postMessage({ ok: false, error: `${err.name}: ${err.message}`.slice(0, 500), stackExhausted: err instanceof RangeError });
  }
});
