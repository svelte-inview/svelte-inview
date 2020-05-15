<script>
  import Inview from 'svelte-inview';

  let ref;
  export let emoji;
</script>

<style>
  .emoji {
    height: 100vh;
    font-size: 12rem;
    display: flex;
    justify-content: center;
    align-items: center;
    margin-right: 500px;
  }
</style>

<Inview
  wrapper={ref}
  on:enter={({ detail }) => console.log(detail.scrollDirection.vertical, ' - wjezdza', emoji)}
  on:leave={({ detail }) => console.log(detail.scrollDirection.vertical, ' - sie chowa', emoji)}
  threshold={0.5}>
  <div class="emoji" bind:this={ref}>{emoji}</div>
</Inview>
