import { c as create_ssr_component, e as escape, v as validate_component } from "../../../chunks/index.js";
const areasView_svelte_svelte_type_style_lang = "";
const css = {
  code: ".initial-block.svelte-11tgbrc{height:100vh;background:yellow;margin-bottom:1px}.target-block.svelte-11tgbrc{display:flex;justify-content:center;align-items:center;height:200px;background:greenyellow}.last-block.svelte-11tgbrc{display:flex;justify-content:center;align-items:center;height:100vh;margin-bottom:1px;background:yellow}",
  map: null
};
const Areas_view = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  let { inviewOptions = {} } = $$props;
  let { showDirection = false } = $$props;
  let direction;
  if ($$props.inviewOptions === void 0 && $$bindings.inviewOptions && inviewOptions !== void 0)
    $$bindings.inviewOptions(inviewOptions);
  if ($$props.showDirection === void 0 && $$bindings.showDirection && showDirection !== void 0)
    $$bindings.showDirection(showDirection);
  $$result.css.add(css);
  return `<div><div class="${"initial-block svelte-11tgbrc"}"></div>
	<div class="${"target-block svelte-11tgbrc"}">${showDirection ? `${escape(direction)}` : ``}

		${`no`}</div>
	<div class="${"last-block svelte-11tgbrc"}">nothing to see here</div>
</div>`;
});
const Page = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  let { data } = $$props;
  if ($$props.data === void 0 && $$bindings.data && data !== void 0)
    $$bindings.data(data);
  return `${validate_component(Areas_view, "AreasView").$$render(
    $$result,
    {
      inviewOptions: data.inViewOptions,
      showDirection: data.showDirection
    },
    {},
    {}
  )}`;
});
export {
  Page as default
};
