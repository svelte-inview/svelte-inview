<svelte:options accessors={true} />

<script lang="ts">
	export let direction = 'up';
	export let active: boolean;
	export let ref: HTMLOrSVGElement;
</script>

{#if direction === 'up'}
	<svg
		bind:this={ref}
		class:active
		width="20"
		height="20"
		viewBox="0 0 492 492"
		xmlns="http://www.w3.org/2000/svg"
		fill-rule="evenodd"
		clip-rule="evenodd"
		stroke-linejoin="round"
		stroke-miterlimit="2"
	>
		<path
			d="M284.582 464.344l-.168.768V135.888l103.724 103.496c5.064 5.068 11.924
      7.848 19.124 7.848 7.2 0 14.012-2.78
      19.088-7.848l16.112-16.104c5.064-5.064 7.864-11.812 7.864-19.008
      0-7.2-2.78-13.952-7.844-19.016L265.086 7.844C260.002 2.76 253.23-.02
      246.026 0c-7.244-.02-14.02 2.76-19.096 7.844L49.518 185.256c-5.06
      5.064-7.844 11.812-7.844 19.016 0 7.196 2.788 13.944 7.844 19.008l16.112
      16.104c5.056 5.068 11.808 7.848 19.008 7.848 7.196 0 13.592-2.78
      18.652-7.848L207.594 134.72v329.992c0 14.828 12.78 27.288 27.6
      27.288h22.788c14.82 0 26.6-12.828 26.6-27.656z"
			fill-rule="nonzero"
		/>
	</svg>
{:else}
	<svg
		bind:this={ref}
		class:active
		width="20"
		height="20"
		viewBox="0 0 492 492"
		xmlns="http://www.w3.org/2000/svg"
		fill-rule="evenodd"
		clip-rule="evenodd"
		stroke-linejoin="round"
		stroke-miterlimit="2"
	>
		<path
			d="M207.418 27.656l.168-.768v329.224L103.862
      252.616c-5.064-5.068-11.924-7.848-19.124-7.848-7.2 0-14.012 2.78-19.088
      7.848L49.538 268.72c-5.064 5.064-7.864 11.812-7.864 19.008 0 7.2 2.78
      13.952 7.844 19.016l177.396 177.412c5.084 5.084 11.856 7.864 19.06 7.844
      7.244.02 14.02-2.76 19.096-7.844l177.412-177.412c5.06-5.064 7.844-11.812
      7.844-19.016
      0-7.196-2.788-13.944-7.844-19.008l-16.112-16.104c-5.056-5.068-11.808-7.848-19.008-7.848-7.196
      0-13.592 2.78-18.652 7.848L284.406
      357.28V27.288c0-14.828-12.78-27.288-27.6-27.288h-22.788c-14.82 0-26.6
      12.828-26.6 27.656z"
			fill-rule="nonzero"
		/>
	</svg>
{/if}

<style>
	svg {
		fill: lightgray;
		transition: fill 0.3s;
	}

	.active {
		fill: lime;
	}
</style>
