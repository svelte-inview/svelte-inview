<script lang="ts">
	import { inview } from '../../../../dist';
	import type { Options } from '../../../../dist';

	let inviewOptions = $state<Options>({ rootMargin: '-25%' });
	let isInView = $state(false);

	function applyZeroMargin() {
		inviewOptions = { rootMargin: '0px' };
	}
</script>

<div>
	<div class="initial-block"></div>
	<div
		class="target-block"
		use:inview={inviewOptions}
		oninview_leave={() => {
			isInView = false;
		}}
		oninview_enter={() => {
			isInView = true;
		}}
	>
		{#if isInView}
			yes
		{:else}
			no
		{/if}
	</div>
	<div class="last-block">nothing to see here</div>
	<button type="button" data-testid="apply-zero-margin" onclick={applyZeroMargin}>
		Apply 0px root margin
	</button>
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
