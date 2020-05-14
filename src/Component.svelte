<script>
  import { createEventDispatcher, onMount } from 'svelte';

  let wrapper;
  let observe;
  let unobserve;
  let entry;
  let inView = false;
  let wrapperClass = '';
  let prevPos = {
    x: undefined,
    y: undefined,
  };
  let scrollDirection = {
    vertical: undefined,
    horizontal: undefined,
  };

  export let root = null;
  export let rootMargin = '0px';
  export let threshold = 0;
  export let unobserveOnEnter = false;
  export { wrapperClass as class };

  const dispatch = createEventDispatcher();

  onMount(() => {
    if (typeof IntersectionObserver !== 'undefined') {
      const observer = new IntersectionObserver(
        (entries, observer) => {
          observe = observer.observe;
          unobserve = observer.unobserve;

          entries.forEach((singleEntry) => {
            entry = singleEntry;

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
            dispatch('change', { entry, scrollDirection, observe, unobserve });

            if (entry.isIntersecting) {
              inView = true;
              dispatch('enter', {
                inView,
                entry,
                scrollDirection,
                observe,
                unobserve,
              });
              unobserveOnEnter && observer.unobserve(wrapper);
            } else {
              inView = false;
              dispatch('leave', {
                inView,
                entry,
                scrollDirection,
                observe,
                unobserve,
              });
            }
          });
        },
        { root, rootMargin, threshold }
      );

      observer.observe(wrapper);
      return () => observer.unobserve(wrapper);
    }
  });
</script>

<style>
  div {
    width: 100%;
    height: 100%;
  }
</style>

<div bind:this={wrapper} class={wrapperClass || ''}>
  <slot {inView} {observe} {unobserve} />
</div>
