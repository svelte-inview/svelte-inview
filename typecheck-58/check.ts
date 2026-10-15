import { inview } from 'svelte-inview';
import type { HTMLAttributes } from 'svelte/elements';

const attrs: HTMLAttributes<HTMLDivElement> = {
  oninview_enter(event) {
    event.detail.inView;
  },
  'on:inview_enter'(event) {
    event.detail.observer;
  }
};

void inview;
void attrs;
