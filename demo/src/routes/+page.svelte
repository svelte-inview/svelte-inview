<script lang="ts">
	import Icon from '../components/icon.svelte';
	import Arrow from '../components/arrow.svelte';

	const icons = ['caravan', 'hammock', 'ice-cream', 'island', 'snorkel', 'sunglasses'];

	let current = $state(icons[0]);
	let direction = $state<'up' | 'down' | undefined>(undefined);
	let arrowUp = $state<SVGSVGElement | undefined>(undefined);
	let arrowDown = $state<SVGSVGElement | undefined>(undefined);

	const animateArrow = (el: Element) => {
		el.animate(
			[
				{ transform: 'translate3d(0, 0, 0)' },
				{ transform: 'translate3d(0, -2px, 0)' },
				{ transform: 'translate3d(0, 6px, 0)' },
				{ transform: 'translate3d(0, 0, 0)' }
			],
			{ duration: 300 }
		);
	};

	const handleEntry = (detail: {
		icon: string;
		verticalDirection: 'up' | 'down' | 'left' | 'right';
	}) => {
		current = detail.icon;
		if (detail.verticalDirection === 'up' || detail.verticalDirection === 'down') {
			direction = detail.verticalDirection;
		}
		if (detail.verticalDirection === 'up' && arrowUp) {
			animateArrow(arrowUp);
		} else if (arrowDown) {
			animateArrow(arrowDown);
		}
	};
</script>

<div class="wrapper">
	<div class="header">
		<div class="text-wrapper">
			<span>Currently on the screen:</span>
			<img src={`icons/${current}.svg`} class="small-icon" alt={current} />
			<Arrow active={direction === 'up'} bind:ref={arrowUp} />
			<Arrow direction="down" active={direction === 'down'} bind:ref={arrowDown} />
		</div>
	</div>
</div>

{#each icons as icon (icon)}
	<Icon {icon} onentry={handleEntry} />
{/each}

<a href="https://github.com/maciekgrzybek/svelte-inview" class="github" target="_blank">
	<img src="icons/github.svg" alt="github" />
</a>

<style>
	.wrapper {
		position: fixed;
		display: flex;
		align-items: center;
		justify-content: center;
		width: 100%;
		background: #353535;
		top: 0;
		left: 0;
		padding: 1.5rem 0;
		color: white;
	}

	.text-wrapper {
		font-size: 1.2rem;
		font-weight: 500;
		display: flex;
		align-items: center;
	}

	.text-wrapper span {
		margin-right: 0.75rem;
	}

	.small-icon {
		width: 1.8rem;
		height: 1.8rem;
		margin-right: 0.75rem;
	}

	.github {
		position: fixed;
		bottom: 1rem;
		right: 1rem;
		width: 30px;
		height: 30px;
	}
</style>
