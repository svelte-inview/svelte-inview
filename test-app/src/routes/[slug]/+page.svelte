<script lang="ts">
	import AreasView from '../../components/areas-view.svelte';
	import type { PageData } from './$types';

	export let data: PageData;
</script>

<AreasView inviewOptions={data.inViewOptions} showDirection={data.showDirection} />
