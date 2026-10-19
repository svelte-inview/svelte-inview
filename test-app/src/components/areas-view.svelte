<script lang="ts">
	import { inview } from '../../../dist';
	import type { Options, ScrollDirection } from '../../../dist';

	export let inviewOptions: Options = {};
	export let showDirection = false;
	let isInView = false;
	let direction: string;
	let firstScrollDirection: ScrollDirection | undefined;
</script>

<div>
	<div class="initial-block"></div>
	<div
		class="target-block"
		use:inview={inviewOptions}
		on:inview_leave={() => {
			isInView = false;
		}}
		on:inview_change={({ detail }) => {
			direction = detail.scrollDirection?.vertical ?? '';
			if (!firstScrollDirection) {
				firstScrollDirection = detail.scrollDirection;
			}
		}}
		on:inview_enter={() => {
			isInView = true;
		}}
	>
		{#if showDirection}
			{direction}
			<span data-testid="first-scroll-vertical">{firstScrollDirection?.vertical ?? ''}</span>
			{#if firstScrollDirection}
				<span data-testid="first-observation" hidden>done</span>
			{/if}
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
