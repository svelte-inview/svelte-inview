<script>
  import { createEventDispatcher, onMount } from 'svelte';

  let wrapper;
  let observe;
  let unobserve;
  let entry;
  let inView = false;

  export let options = {
    root: null,
    rootMargin: '0px',
    threshold: 0,
  };

  const dispatch = createEventDispatcher();

  onMount(() => {
    if (typeof IntersectionObserver !== 'undefined') {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach((singleEntry) => {
          dispatch('intersecting', singleEntry);
          entry = singleEntry;
          if (entry.isIntersecting) {
            inView = true;
          } else {
            inView = false;
          }
        });
      }, options);

      observe = observer.observe;
      unobserve = observer.unobserve;

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

<div bind:this={wrapper}>
  <slot {inView} {observe} {unobserve} {entry} />
</div>

<!-- +++++++++++++++++++++++++++++++++++++++++++++++++ TODO: expose inView and IO Entry(with entry info) props +++++++++++++++++++++++++++++++++++++++++++++++++-->
<!-- TODO: pass IO props-->
<!-- TODO: expose add events -> onChange, onEnter, onLeave-->
<!-- TODO: add scrollDirection detection -->
<!-- TODO: add unobserveOnEnter -->
<!-- +++++++++++++++++++++++++++++++++++++++++++++++++ TODO: expose observe and unObserve methods ++++++++++++++++++++++++++++++++++++++++++++++++++-->
<!-- TODO: in future handle IO v2 -->
<!-- TODO: add demo and examples in readme -->
