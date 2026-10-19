<script lang="ts">
	import { inview } from 'svelte-inview';

	type EntryDetail = {
		icon: string;
		verticalDirection: 'up' | 'down' | 'left' | 'right';
	};

	let {
		icon,
		onentry
	}: {
		icon: string;
		onentry?: (detail: EntryDetail) => void;
	} = $props();
</script>

<div
	class="icon-wrapper"
	use:inview={{ threshold: 0.5 }}
	oninview_enter={({ detail }) => {
		const verticalDirection = detail.scrollDirection.vertical;
		if (!verticalDirection) return;
		onentry?.({ verticalDirection, icon });
	}}
>
	<img src={`icons/${icon}.svg`} alt={icon} />
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
