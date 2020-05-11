<script>
  import { createEventDispatcher, onMount } from 'svelte';

  let wrapper;
  export let inView = false;
  const dispatch = createEventDispatcher();

  onMount(() => {
    if(typeof IntersectionObserver !== 'undefined') {
      console.log(wrapper)
      const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          dispatch('intersecting', entry)
          if(entry.isIntersecting) {
            inView = true;
          } else {
            inView = false;
          }
        })

      })
      
      observer.observe(wrapper);
      return () => observer.unobserve(wrapper);
    }
  })
</script>

<style>
  div {
    width: 100px;
    height: 10px;
  }
</style>

<div bind:this={wrapper}>
  <slot {inView}/>
</div>