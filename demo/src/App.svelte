<script lang="ts">
  import Icon from './Icon.svelte';
  import Arrow from './Arrow.svelte';

  const icons = [
    'caravan',
    'hammock',
    'ice-cream',
    'island',
    'snorkel',
    'sunglasses',
  ];

  let current = icons[0];
  let direction;
  let arrowUp;
  let arrowDown;

  const animateArrow = (el) => {
    el.animate(
      [
        { transform: 'translate3d(0, 0, 0)' },
        { transform: 'translate3d(0, -2px, 0)' },
        { transform: 'translate3d(0, 6px, 0)' },
        { transform: 'translate3d(0, 0, 0)' },
      ],
      { duration: 300 }
    );
  };

  const handleEntry = ({ detail }) => {
    current = detail.icon;
    direction = detail.verticalDirection;
    if (detail.verticalDirection === 'up') {
      animateArrow(arrowUp.ref);
    } else {
      animateArrow(arrowDown.ref);
    }
  };
</script>

<div class="wrapper">
  <div class="header">
    <div class="text-wrapper">
      <span>Currently on the screen:</span>
      <img src={`icons/${current}.svg`} class="small-icon" alt={current} />
      <Arrow active={direction === 'up'} bind:this={arrowUp} />
      <Arrow
        direction="down"
        active={direction === 'down'}
        bind:this={arrowDown}
      />
    </div>
  </div>
</div>

{#each icons as icon}
  <Icon {icon} on:entry={handleEntry} />
{/each}

<a
  href="https://github.com/maciekgrzybek/svelte-inview"
  class="github"
  target="_blank"
>
  <img src="icons/github.svg" alt="github" />
</a>

<style>
  .wrapper {
    position: fixed;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    background: #353535;
    top: 0;
    left: 0;
    padding: 1.5rem 0;
    color: white;
  }

  .text-wrapper {
    font-size: 1.2rem;
    font-weight: 500;
    display: flex;
    align-items: center;
  }

  .text-wrapper span {
    margin-right: 0.75rem;
  }

  .small-icon {
    width: 1.8rem;
    height: 1.8rem;
    margin-right: 0.75rem;
  }

  .github {
    position: fixed;
    bottom: 1rem;
    right: 1rem;
    width: 30px;
    height: 30px;
  }
</style>
