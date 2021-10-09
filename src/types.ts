type Direction = 'up' | 'down' | 'left' | 'right';

export type Options = {
  root?: HTMLElement | null;
  rootMargin?: string;
  threshold?: number | number[];
  unobserveOnEnter: boolean;
};

export type Position = {
  x?: number;
  y?: number;
};

export type ScrollDirection = {
  vertical?: Direction;
  horizontal?: Direction;
};
