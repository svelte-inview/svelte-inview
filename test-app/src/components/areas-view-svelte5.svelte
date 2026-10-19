<script lang="ts">
	import { inview } from '../../../dist';
	import type { Options } from '../../../dist';

	let { inviewOptions = {} }: { inviewOptions?: Options } = $props();
	let isInView = $state(false);
</script>

<div>
	<div class="initial-block"></div>
	<div
		class="target-block"
		use:inview={inviewOptions}
		oninview_enter={() => {
			isInView = true;
		}}
		oninview_leave={() => {
			isInView = false;
		}}
	>
		{isInView ? 'yes' : 'no'}
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
