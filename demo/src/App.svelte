<script>
  import Item from './Item.svelte';
  const emojis = ['👶🏼', '👦🏼', '👧🏼', '👨🏼', '👩🏼', '👱🏼‍♀️'];
</script>

<style>
  div {
    display: flex;
    flex-wrap: nowrap;
  }
</style>

<div>
  {#each emojis as emoji}
    <Item {emoji} />
  {/each}

</div>
