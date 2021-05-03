interface Options {
  root?: HTMLElement | null;
  rootMargin?: string;
  threshold?: number | number[];
  unobserveOnEnter: boolean;
}

type Direction = 'up' | 'down' | 'left' | 'right';

interface Position {
  x?: number;
  y?: number;
}

interface ScrollDirection {
  vertical?: Direction;
  horizontal?: Direction;
}

const defaultOptions: Options = {
  root: null,
  rootMargin: '0px',
  threshold: 0,
  unobserveOnEnter: false,
};

export function inview(node: HTMLElement, options: Options) {
  const actionOptions: Options = {
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

  let inView = false;

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

          prevPos.y = entry.boundingClientRect.y;
          prevPos.x = entry.boundingClientRect.x;

          inView = entry.isIntersecting;

          node.dispatchEvent(
            new CustomEvent('change', {
              detail: {
                inView,
                entry,
                scrollDirection,
                observe,
                unobserve,
              },
            })
          );

          if (entry.isIntersecting) {
            inView = true;

            node.dispatchEvent(
              new CustomEvent('enter', {
                detail: {
                  inView,
                  entry,
                  scrollDirection,
                  observe,
                  unobserve,
                },
              })
            );

            options.unobserveOnEnter && _observer.unobserve(node);
          } else {
            inView = false;
            node.dispatchEvent(
              new CustomEvent('leave', {
                detail: {
                  inView,
                  entry,
                  scrollDirection,
                  observe,
                  unobserve,
                },
              })
            );
          }
        });
      },
      {
        root: actionOptions.root,
        rootMargin: actionOptions.rootMargin,
        threshold: actionOptions.threshold,
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
