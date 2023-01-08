import { error } from '@sveltejs/kit';
import type { RouteParams } from './$types';

export function load({ params }: { params: RouteParams }) {
	if (params.slug === 'default-settings') {
		return {
			inViewOptions: {}
		};
	}
	if (params.slug === 'root-margin') {
		return {
			inViewOptions: { rootMargin: '-25%' }
		};
	}
	if (params.slug === 'threshold') {
		return {
			inViewOptions: { threshold: 1 }
		};
	}
	if (params.slug === 'unobserve-on-enter') {
		return {
			inViewOptions: { unobserveOnEnter: true, threshold: 1 }
		};
	}
	if (params.slug === 'direction') {
		return {
			showDirection: true
		};
	}

	throw error(404, 'Not found');
}
