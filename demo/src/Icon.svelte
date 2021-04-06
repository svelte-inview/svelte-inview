<script>
  import Inview from 'svelte-inview';
  import { createEventDispatcher } from 'svelte';

  let ref;
  export let icon;

  const dispatch = createEventDispatcher();
</script>

<Inview
  wrapper={ref}
  on:enter={({ detail }) =>
    dispatch('entry', {
      verticalDirection: detail.scrollDirection.vertical,
      icon,
    })}
  threshold={0.5}
>
  <div class="icon-wrapper">
    <img src={`icons/${icon}.svg`} alt={icon} bind:this={ref} />
  </div>
</Inview>

<style>
  .icon-wrapper {
    height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 0 3rem;
  }

  img {
    width: 100%;
    max-height: 50%;
  }
</style>
