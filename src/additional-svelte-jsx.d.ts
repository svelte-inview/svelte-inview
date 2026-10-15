import type { Attributes } from './types';

declare global {
  namespace svelteHTML {
    interface HTMLAttributes<T> extends Attributes {}
  }
}

declare module 'svelte/elements' {
  export interface HTMLAttributes<T extends EventTarget> extends Attributes {}
}

export {};
