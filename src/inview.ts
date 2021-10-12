import type {
  Detail,
  Options,
  Position,
  ScrollDirection,
  Event,
} from './types';

const defaultOptions: Options = {
  root: null,
  rootMargin: '0px',
  threshold: 0,
  unobserveOnEnter: false,
};

const createEvent = (name: Event, detail: Detail): CustomEvent<Detail> =>
  new CustomEvent(name, { detail });

export function inview(node: HTMLElement, options: Options) {
  const { root, rootMargin, threshold, unobserveOnEnter }: Options = {
    ...defaultOptions,
    ...options,
  };

  let prevPos: Position = {
    x: undefined,
    y: undefined,
  };

  let scrollDirection: ScrollDirection = {
    vertical: undefined,
    horizontal: undefined,
  };

  if (typeof IntersectionObserver !== 'undefined' && node) {
    const observer = new IntersectionObserver(
      (entries, _observer) => {
        const observe = _observer.observe;
        const unobserve = _observer.unobserve;

        entries.forEach((singleEntry) => {
          const entry = singleEntry;

          if (prevPos.y > entry.boundingClientRect.y) {
            scrollDirection.vertical = 'up';
          } else {
            scrollDirection.vertical = 'down';
          }

          if (prevPos.x > entry.boundingClientRect.x) {
            scrollDirection.horizontal = 'left';
          } else {
            scrollDirection.horizontal = 'right';
          }

          prevPos = {
            y: entry.boundingClientRect.y,
            x: entry.boundingClientRect.x,
          };

          const detail: Detail = {
            inView: entry.isIntersecting,
            entry,
            scrollDirection,
            observe,
            unobserve,
          };

          node.dispatchEvent(createEvent('change', detail));

          if (entry.isIntersecting) {
            node.dispatchEvent(createEvent('enter', detail));

            unobserveOnEnter && _observer.unobserve(node);
          } else {
            node.dispatchEvent(createEvent('leave', detail));
          }
        });
      },
      {
        root,
        rootMargin,
        threshold,
      }
    );

    observer.observe(node);
    return {
      destroy() {
        observer.unobserve(node);
      },
    };
  }
}
