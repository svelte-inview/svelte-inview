import { c as create_ssr_component, d as createEventDispatcher, f as add_attribute, v as validate_component, h as each } from "../../chunks/index.js";
const icon_svelte_svelte_type_style_lang = "";
const css$2 = {
  code: ".icon-wrapper.svelte-fsdkll{height:100vh;display:flex;justify-content:center;align-items:center;padding:0 3rem}img.svelte-fsdkll{width:100%;max-height:50%}",
  map: null
};
const Icon = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  let ref;
  let { icon } = $$props;
  createEventDispatcher();
  if ($$props.icon === void 0 && $$bindings.icon && icon !== void 0)
    $$bindings.icon(icon);
  $$result.css.add(css$2);
  return `<div class="${"icon-wrapper svelte-fsdkll"}"><img${add_attribute("src", `icons/${icon}.svg`, 0)}${add_attribute("alt", icon, 0)} class="${"svelte-fsdkll"}"${add_attribute("this", ref, 0)}>
</div>`;
});
const arrow_svelte_svelte_type_style_lang = "";
const css$1 = {
  code: "svg.svelte-1eu0q0s{fill:lightgray;transition:fill 0.3s}.active.svelte-1eu0q0s{fill:lime}",
  map: null
};
const Arrow = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  let { direction = "up" } = $$props;
  let { active } = $$props;
  let { ref } = $$props;
  if ($$props.direction === void 0 && $$bindings.direction && direction !== void 0)
    $$bindings.direction(direction);
  if ($$props.active === void 0 && $$bindings.active && active !== void 0)
    $$bindings.active(active);
  if ($$props.ref === void 0 && $$bindings.ref && ref !== void 0)
    $$bindings.ref(ref);
  $$result.css.add(css$1);
  return `



${direction === "up" ? `<svg width="${"20"}" height="${"20"}" viewBox="${"0 0 492 492"}" xmlns="${"http://www.w3.org/2000/svg"}" fill-rule="${"evenodd"}" clip-rule="${"evenodd"}" stroke-linejoin="${"round"}" stroke-miterlimit="${"2"}" class="${["svelte-1eu0q0s", active ? "active" : ""].join(" ").trim()}"${add_attribute("this", ref, 0)}><path d="${"M284.582 464.344l-.168.768V135.888l103.724 103.496c5.064 5.068 11.924\n      7.848 19.124 7.848 7.2 0 14.012-2.78\n      19.088-7.848l16.112-16.104c5.064-5.064 7.864-11.812 7.864-19.008\n      0-7.2-2.78-13.952-7.844-19.016L265.086 7.844C260.002 2.76 253.23-.02\n      246.026 0c-7.244-.02-14.02 2.76-19.096 7.844L49.518 185.256c-5.06\n      5.064-7.844 11.812-7.844 19.016 0 7.196 2.788 13.944 7.844 19.008l16.112\n      16.104c5.056 5.068 11.808 7.848 19.008 7.848 7.196 0 13.592-2.78\n      18.652-7.848L207.594 134.72v329.992c0 14.828 12.78 27.288 27.6\n      27.288h22.788c14.82 0 26.6-12.828 26.6-27.656z"}" fill-rule="${"nonzero"}"></path></svg>` : `<svg width="${"20"}" height="${"20"}" viewBox="${"0 0 492 492"}" xmlns="${"http://www.w3.org/2000/svg"}" fill-rule="${"evenodd"}" clip-rule="${"evenodd"}" stroke-linejoin="${"round"}" stroke-miterlimit="${"2"}" class="${["svelte-1eu0q0s", active ? "active" : ""].join(" ").trim()}"${add_attribute("this", ref, 0)}><path d="${"M207.418 27.656l.168-.768v329.224L103.862\n      252.616c-5.064-5.068-11.924-7.848-19.124-7.848-7.2 0-14.012 2.78-19.088\n      7.848L49.538 268.72c-5.064 5.064-7.864 11.812-7.864 19.008 0 7.2 2.78\n      13.952 7.844 19.016l177.396 177.412c5.084 5.084 11.856 7.864 19.06 7.844\n      7.244.02 14.02-2.76 19.096-7.844l177.412-177.412c5.06-5.064 7.844-11.812\n      7.844-19.016\n      0-7.196-2.788-13.944-7.844-19.008l-16.112-16.104c-5.056-5.068-11.808-7.848-19.008-7.848-7.196\n      0-13.592 2.78-18.652 7.848L284.406\n      357.28V27.288c0-14.828-12.78-27.288-27.6-27.288h-22.788c-14.82 0-26.6\n      12.828-26.6 27.656z"}" fill-rule="${"nonzero"}"></path></svg>`}`;
});
const _page_svelte_svelte_type_style_lang = "";
const css = {
  code: ".wrapper.svelte-110g6si.svelte-110g6si{position:fixed;display:flex;align-items:center;justify-content:center;width:100%;background:#353535;top:0;left:0;padding:1.5rem 0;color:white}.text-wrapper.svelte-110g6si.svelte-110g6si{font-size:1.2rem;font-weight:500;display:flex;align-items:center}.text-wrapper.svelte-110g6si span.svelte-110g6si{margin-right:0.75rem}.small-icon.svelte-110g6si.svelte-110g6si{width:1.8rem;height:1.8rem;margin-right:0.75rem}.github.svelte-110g6si.svelte-110g6si{position:fixed;bottom:1rem;right:1rem;width:30px;height:30px}",
  map: null
};
const Page = create_ssr_component(($$result, $$props, $$bindings, slots) => {
  const icons = ["caravan", "hammock", "ice-cream", "island", "snorkel", "sunglasses"];
  let current = icons[0];
  let direction;
  let arrowUp;
  let arrowDown;
  $$result.css.add(css);
  let $$settled;
  let $$rendered;
  do {
    $$settled = true;
    $$rendered = `<div class="${"wrapper svelte-110g6si"}"><div class="${"header"}"><div class="${"text-wrapper svelte-110g6si"}"><span class="${"svelte-110g6si"}">Currently on the screen:</span>
			<img${add_attribute("src", `icons/${current}.svg`, 0)} class="${"small-icon svelte-110g6si"}"${add_attribute("alt", current, 0)}>
			${validate_component(Arrow, "Arrow").$$render(
      $$result,
      {
        active: direction === "up",
        this: arrowUp
      },
      {
        this: ($$value) => {
          arrowUp = $$value;
          $$settled = false;
        }
      },
      {}
    )}
			${validate_component(Arrow, "Arrow").$$render(
      $$result,
      {
        direction: "down",
        active: direction === "down",
        this: arrowDown
      },
      {
        this: ($$value) => {
          arrowDown = $$value;
          $$settled = false;
        }
      },
      {}
    )}</div></div></div>

${each(icons, (icon) => {
      return `${validate_component(Icon, "Icon").$$render($$result, { icon }, {}, {})}`;
    })}

<a href="${"https://github.com/maciekgrzybek/svelte-inview"}" class="${"github svelte-110g6si"}" target="${"_blank"}"><img src="${"icons/github.svg"}" alt="${"github"}">
</a>`;
  } while (!$$settled);
  return $$rendered;
});
export {
  Page as default
};
