<script lang="ts">
	import AreasView from '../../components/areas-view.svelte';
	import type { Options } from '../../../../dist';

	let inviewOptions = $state<Options>({ rootMargin: '-25%' });

	function applyZeroMargin() {
		inviewOptions = { rootMargin: '0px' };
	}
</script>

<button
	type="button"
	class="apply-margin"
	data-testid="apply-zero-margin"
	onclick={applyZeroMargin}
>
	Apply 0px root margin
</button>

<AreasView {inviewOptions} />

<style>
	.apply-margin {
		position: fixed;
		top: 0;
		left: 0;
		z-index: 1;
	}
</style>
