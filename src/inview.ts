import { tick } from 'svelte';
import type { ActionReturn } from 'svelte/action';
import type {
  ObserverEventDetails,
  Options,
  Position,
  ScrollDirection,
  Event,
  LifecycleEventDetails,
  Attributes,
} from './types';

const defaultOptions: Options = {
  root: null,
  rootMargin: '0px',
  threshold: 0,
  unobserveOnEnter: false,
};

const createEvent = <T = ObserverEventDetails>(
  name: Event,
  detail: T
): CustomEvent<T> => new CustomEvent(name, { detail });

const resolveOptions = (options: Options = {}): Options => ({
  ...defaultOptions,
  ...options,
});

const optionsChanged = (a: Options, b: Options): boolean =>
  a.root !== b.root ||
  a.rootMargin !== b.rootMargin ||
  a.threshold !== b.threshold ||
  a.unobserveOnEnter !== b.unobserveOnEnter;

export function inview(
  node: HTMLElement,
  options: Options = {}
): ActionReturn<Options, Attributes> {
  let generation = 0;
  let currentOptions = resolveOptions(options);
  let observer: IntersectionObserver | undefined;

  const prevPos: Position = {
    x: undefined,
    y: undefined,
  };

  const cancelPendingInit = () => {
    generation += 1;
  };

  const destroyObserver = () => {
    cancelPendingInit();
    observer?.disconnect();
    observer = undefined;
  };

  const createObserver = () => {
    const { root, rootMargin, threshold, unobserveOnEnter } = currentOptions;
    const initGeneration = generation;

    observer = new IntersectionObserver(
      (entries, _observer) => {
        entries.forEach((singleEntry) => {
          const scrollDirection: ScrollDirection = {
            vertical: undefined,
            horizontal: undefined,
          };

          if (prevPos.y !== undefined) {
            if (prevPos.y > singleEntry.boundingClientRect.y) {
              scrollDirection.vertical = 'up';
            } else {
              scrollDirection.vertical = 'down';
            }
          }

          if (prevPos.x !== undefined) {
            if (prevPos.x > singleEntry.boundingClientRect.x) {
              scrollDirection.horizontal = 'left';
            } else {
              scrollDirection.horizontal = 'right';
            }
          }

          prevPos.y = singleEntry.boundingClientRect.y;
          prevPos.x = singleEntry.boundingClientRect.x;

          const detail: ObserverEventDetails = {
            inView: singleEntry.isIntersecting,
            entry: singleEntry,
            scrollDirection,
            node,
            observer: _observer,
          };

          node.dispatchEvent(createEvent('inview_change', detail));
          //@ts-expect-error only for backward compatibility
          node.dispatchEvent(createEvent('change', detail));

          if (singleEntry.isIntersecting) {
            node.dispatchEvent(createEvent('inview_enter', detail));
            //@ts-expect-error only for backward compatibility
            node.dispatchEvent(createEvent('enter', detail));

            unobserveOnEnter && _observer.unobserve(node);
          } else {
            node.dispatchEvent(createEvent('inview_leave', detail));
            //@ts-expect-error only for backward compatibility
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

    tick().then(() => {
      if (initGeneration !== generation) {
        return;
      }

      node.dispatchEvent(
        createEvent<LifecycleEventDetails>('inview_init', { observer, node })
      );
      node.dispatchEvent(
        //@ts-expect-error only for backward compatibility
        createEvent<LifecycleEventDetails>('init', { observer, node })
      );
    });

    observer.observe(node);
  };

  if (typeof IntersectionObserver !== 'undefined' && node) {
    createObserver();

    return {
      update(newOptions: Options = {}) {
        const nextOptions = resolveOptions(newOptions);

        if (!optionsChanged(currentOptions, nextOptions)) {
          return;
        }

        currentOptions = nextOptions;
        destroyObserver();
        createObserver();
      },
      destroy() {
        destroyObserver();
      },
    };
  }
}
