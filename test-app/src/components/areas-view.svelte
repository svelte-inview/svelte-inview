<script lang="ts">
	import { inview } from '../../../dist';
	import type { Options } from '../../../dist';

	export let inviewOptions: Options = {};
	export let showDirection = false;
	let isInView = false;
	let direction: string;
</script>

<div>
	<div class="initial-block" />
	<div
		class="target-block"
		use:inview={inviewOptions}
		on:inview_leave={() => {
			isInView = false;
		}}
		on:inview_change={({ detail }) => (direction = detail.scrollDirection?.vertical ?? '')}
		on:inview_enter={() => {
			isInView = true;
		}}
	>
		{#if showDirection}
			{direction}
		{/if}

		{#if isInView}
			yes
		{:else}
			no
		{/if}
	</div>
	<div class="last-block">nothing to see here</div>
</div>

<style>
	.initial-block {
		height: 100vh;
		background: yellow;
		margin-bottom: 1px;
	}

	.target-block {
		display: flex;
		justify-content: center;
		align-items: center;
		height: 200px;
		background: greenyellow;
	}

	.last-block {
		display: flex;
		justify-content: center;
		align-items: center;
		height: 100vh;
		margin-bottom: 1px;
		background: yellow;
	}
</style>
