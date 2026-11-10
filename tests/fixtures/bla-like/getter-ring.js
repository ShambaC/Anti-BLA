// Owned synthetic fixture: getters that would recurse forever if evaluated.
globalThis.__antiBlaGetterExecuted = false;
export const ring = {
  get alpha() { globalThis.__antiBlaGetterExecuted = true; return this.beta; },
  get beta() { return this.gamma; },
  get gamma() { return this.alpha; },
};
export class Self { get next() { return this.next; } }
