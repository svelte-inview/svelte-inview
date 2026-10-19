<script lang="ts">
	import { inview } from '../../../../dist';

	let showTarget = $state(true);
	let initCount = $state(0);

	function mountAndUnmount(node: HTMLElement) {
		const action = inview(node);
		showTarget = false;
		return action;
	}
</script>

<div>
	{#if showTarget}
		<div
			class="target-block"
			use:mountAndUnmount
			oninview_init={() => {
				initCount += 1;
			}}
		/>
	{/if}
	<p class="init-count" data-testid="init-count">{initCount}</p>
</div>

<style>
	.target-block {
		height: 200px;
		background: greenyellow;
	}
</style>
