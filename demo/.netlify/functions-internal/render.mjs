import { init } from '../serverless.js';

export const handler = init({
	appDir: "_app",
	appPath: "_app",
	assets: new Set(["favicon.png","icons/caravan.svg","icons/github.svg","icons/hammock.svg","icons/ice-cream.svg","icons/island.svg","icons/snorkel.svg","icons/sunglasses.svg"]),
	mimeTypes: {".png":"image/png",".svg":"image/svg+xml"},
	_: {
		entry: {"file":"_app/immutable/start-0570927c.js","imports":["_app/immutable/start-0570927c.js","_app/immutable/chunks/index-44dfb30b.js","_app/immutable/chunks/singletons-23acf279.js","_app/immutable/chunks/control-f5b05b5f.js"],"stylesheets":[],"fonts":[]},
		nodes: [
			() => import('../server/nodes/0.js'),
			() => import('../server/nodes/1.js'),
			() => import('../server/nodes/2.js'),
			() => import('../server/nodes/3.js')
		],
		routes: [
			{
				id: "/",
				pattern: /^\/$/,
				params: [],
				page: { layouts: [0], errors: [1], leaf: 2 },
				endpoint: null
			},
			{
				id: "/[slug]",
				pattern: /^\/([^/]+?)\/?$/,
				params: [{"name":"slug","optional":false,"rest":false,"chained":false}],
				page: { layouts: [0], errors: [1], leaf: 3 },
				endpoint: null
			}
		],
		matchers: async () => {
			
			return {  };
		}
	}
});
