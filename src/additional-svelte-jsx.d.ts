// Due to an ambivalent nature of .d.ts files, we can't import or export
// anything in this file. That is the cause we need to manually put ScrollDirection
// and Details types to ensure correct typings in the app.

type Direction = 'up' | 'down' | 'left' | 'right';

type ScrollDirection = {
  vertical?: Direction;
  horizontal?: Direction;
};

type Detail = {
  inView: boolean;
  entry: IntersectionObserverEntry;
  scrollDirection: ScrollDirection;
  observe: (target: Element) => void;
  unobserve: (target: Element) => void;
};

declare namespace svelte.JSX {
  interface HTMLProps<T> {
    onchange?: (event: CustomEvent<Detail>) => void;
    onenter?: (event: CustomEvent<Detail>) => void;
    onleave?: (event: CustomEvent<Detail>) => void;
  }
}
