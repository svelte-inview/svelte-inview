<script lang="ts">
	import { inview } from 'svelte-inview';
	import { createEventDispatcher } from 'svelte';

	let ref: HTMLOrSVGElement;
	export let icon: string;

	const dispatch = createEventDispatcher();
</script>

<div
	class="icon-wrapper"
	use:inview={{ threshold: 0.5 }}
	on:enter={({ detail }) =>
		dispatch('entry', {
			verticalDirection: detail.scrollDirection.vertical,
			icon
		})}
>
	<img src={`icons/${icon}.svg`} alt={icon} bind:this={ref} />
</div>

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
