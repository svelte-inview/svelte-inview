# Svelte Inview

A Svelte action that monitors an element enters or leaves the viewport/parent element. Performant and efficient thanks to using [Intersection Observer](https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API) under the hood. Can be used in multiple projects including lazy loading images, infinite scrolling, playing/pausing the video when in the viewport, tracking user behaviour firing link pre-fetching and animations and many many more.

<img src="https://raw.githubusercontent.com/maciekgrzybek/svelte-inview/master/demo/static/demo.gif" width="600px" align="center">

🔥 Check it out live [here](https://svelte-inview.netlify.app/)

Support if you like it ☕ 🔥 <br />
[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/yellow_img.png)](https://www.buymeacoffee.com/maciekgrzybek)

## Why bother?

- 👓️ Watch for any element that enters or leaves the viewport (or another wrapper/parent element).
- 🏎️ Thanks to using [Intersection Observer](https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API), Svelte Inview is blazing fast and doesn't block the main thread.
- 📦️ Tiny, yet powerful (just ~2kb). No external dependencies (well, apart from Svelte).
- 🎛️ Use it in several different scenarios such as lazy loading images, infinite scrolling, playing/pausing the video when in the viewport, firing link pre-fetching, animations and many many more.
- 🐥 Easy to use API.
- ↕️ Detects the scrolling direction.

## Installation

The only thing you need is Svelte itself.

Svelte Inview is distributed via [npm](https://www.npmjs.com/package/svelte-inview).

```sh
$ yarn add svelte-inview
# or
$ npm install --save svelte-inview
```

> ⚠️ Modern browsers have the full support of Intersection Observer, but if you need to support ones like IE you can use this [simple polyfill](https://www.npmjs.com/package/intersection-observer). Just install it and import it in your project.

## Usage

### Basic Use Case

This is the most basic use case for `svelte-inview`. Just add the action to the element you want to track - `use:inview`. You can also pass other [configuration props](#props). You can see if the element is visible by checking the `inView` flag from `on:inview_change` (Svelte 3 and 4) or `oninview_change` (Svelte 5).

```html

<script lang="ts">
  import { inview } from 'svelte-inview';

  let isInView: boolean;
  const options = {};
</script>

  <div
    use:inview={options}
    on:inview_change={(event) => {
      const { inView, entry, scrollDirection, observer, node} = event.detail;
      isInView = inView;
    }}
    on:inview_enter={(event) => {
      const { inView, entry, scrollDirection, observer, node} = event.detail;
      isInView = inView;
    }}
    on:inview_leave={(event) => {
      const { inView, entry, scrollDirection, observer, node} = event.detail;
      isInView = inView;
    }}
    on:inview_init={(event) => {
      const { observer, node } = event.detail;
    }}>{isInView ? 'Hey I am in the viewport' : 'Bye, Bye'}</div>
```

### Svelte 5

In Svelte 5 the same events are element attributes. `event.detail` is unchanged.

```html
<script lang="ts">
  import { inview } from 'svelte-inview';

  let isInView = $state(false);
  const options = {};
</script>

<div
  use:inview={options}
  oninview_change={(event) => {
    const { inView, entry, scrollDirection, observer, node } = event.detail;
    isInView = inView;
  }}
  oninview_enter={(event) => {
    const { inView, entry, scrollDirection, observer, node } = event.detail;
    isInView = inView;
  }}
  oninview_leave={(event) => {
    const { inView, entry, scrollDirection, observer, node } = event.detail;
    isInView = inView;
  }}
  oninview_init={(event) => {
    const { observer, node } = event.detail;
  }}
>
  {isInView ? 'Hey I am in the viewport' : 'Bye, Bye'}
</div>
```

### Lazy Loading Images

Svelte Inview lets you easily lazy load images. For a better UX we can pass a `rootMargin="50px"` props, so the image will be loaded when scroll is 50px before the viewport. After it appears in the viewport, you don't want to observe it anymore, hence the `unobserveOnEnter` props set to true.

```html
<script lang="ts">
  import { inview } from 'svelte-inview';
  import type { ObserverEventDetails, Options } from 'svelte-inview';

  let isInView;
  const options: Options = {
    rootMargin: '50px',
    unobserveOnEnter: true,
  };

  const handleChange = ({ detail }: CustomEvent<ObserverEventDetails>) =>
    (isInView = detail.inView);
</script>

<div use:inview="{options}" on:inview_change="{handleChange}">
  {#if isInView}
  <img src="path/to/image.jpg" />
  {:else}
  <div class="placeholder" />
  {/if}
</div>
```

### Video Control

You can play/pause a video when it's in/out of the viewport. Simply pass correct methods in `on:inview_enter` and `on:inview_leave` callbacks.

```html
<script lang="ts">
  import { inview } from 'svelte-inview';
  import type { ObserverEventDetails } from 'svelte-inview';

  let isInView: boolean;
  let videoRef: HTMLElement;
</script>

  <div
    use:inview
    on:inview_enter={() => videoRef.play()}
    on:inview_leave={() => videoRef.pause()}
  >
    <video width="500" controls bind:this={videoRef}>
      <source src="path/to/video.mp4" type="video/mp4" />
    </video>
  </div>
```

### Animations

You can also add some cool animations when an element enters the viewport. To make sure the animation won't fire too soon you can pass a negative value to `rootMargin`. When `inView` is true, add an animation class to your target. Additionally, you can detect the scroll direction to make the animations even cooler!

```html

<script lang="ts">
  import { inview } from 'svelte-inview';
  import type { ObserverEventDetails, ScrollDirection, Options } from 'svelte-inview';

  let isInView: boolean;
  let scrollDirection: ScrollDirection;
  const options: Options = {
    rootMargin: '-50px',
    unobserveOnEnter: true,
  };

  const handleChange = ({ detail }: CustomEvent<ObserverEventDetails>) => {
    isInView = detail.inView;
    scrollDirection = detail.scrollDirection.vertical;
  };
</script>

  <div use:inview={options} on:inview_change={handleChange}>
    <div
      class:animate={isInView}
      class:animateFromBottom={scrollDirection === 'down'}
      class:animateFromTop={scrollDirection === 'up'}>
      Animate me!
    </div>
  </div>
```

### Important information about breaking changes in previous versions

#### Version 5 removes legacy event names

Version 4 renamed events to `'inview_change' | 'inview_leave' | 'inview_enter' | 'inview_init'` so they work correctly with TypeScript and Svelte typings. Version 5 drops the old names `'change'`, `'leave'`, `'enter'`, and `'init'` entirely.

If you still listen for the legacy names, migrate to the `inview_*` events:

```js
// Svelte 3 and 4
on:inview_change={(event) => {
  const { inView, entry, scrollDirection, observer, node } = event.detail;
  isInView = inView;
}}
```

```js
// Svelte 5
oninview_change={(event) => {
  const { inView, entry, scrollDirection, observer, node } = event.detail;
  isInView = inView;
}}
```

Use `on:inview_enter`, `on:inview_leave`, and `on:inview_init` (or `oninview_enter`, `oninview_leave`, and `oninview_init` in Svelte 5) the same way.

#### Version 2 was returning `observe` and `unobserve` methods on the events. In version 3 they were removed, and the `observer` and `node` are being returned instead. So if you used those methods before like this:

```js
event.detail.observe(node);
```

You'll need to change it to:

```js
event.detail.observer.observe(node);
```

#### Version 1 was using an `Inview` component. In version 2 that was changed to `action` - API is easier to consume, plus the obsolete wrapper is not longer needed. If you still want to use the component, [check the documentation for version 1](https://github.com/maciekgrzybek/svelte-inview/tree/v-1.0.0).

## API

### Props

| Name                     | Type                   | Default  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Required |
| ------------------------ | ---------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| options.root             | `HTMLElement`          | `null`   | The element that is used as the viewport for checking visibility of the target. Must be the ancestor of the target. `null` uses the browser viewport.                                                                                                                                                                                                                                                                                                                       | `false`  |
| options.rootMargin       | `string`               | `0px`    | Margin around the root element. Values similar to the CSS margin property, e.g. "10px 20px 30px 40px". Can also be a percentage. [See more](#usage-with-rootmargin).                                                                                                                                                                                                                                                                                                        | `false`  |
| options.threshold        | `number` or `number[]` | `0`      | Either a single number or an array of numbers which indicate at what percentage of the target's visibility the observer's callback should be executed. If you only want to detect when visibility passes the 50% mark, you can use a value of 0.5. If you want the callback to run every time visibility passes another 25%, you would specify the array [0, 0.25, 0.5, 0.75, 1]. The default is 0 (meaning as soon as even one pixel is visible, the callback will be run) | `false`  |
| options.unobserveOnEnter | `boolean`              | `false`  | If true, target element stops being observed after the first time it appears in the viewport. Can be used when you want to fire the callback only once.                                                                                                                                                                                                                                                                                                                     | `false`  |
| on:inview_change         | `function`             | -        | Event fired every time the target element meets the specified threshold. Receives `event` object as an argument. Inside of `event.detail` you can find all the arguments specified [here](#observer-events-arguments).                                                                                                                                                                                                                                                      | `false`  |
| on:inview_enter          | `function`             | -        | Event fired every time the target element enters the viewport. Receives `event` object as an argument. Inside of `event.detail` you can find all the arguments specified [here](#observer-events-arguments) .                                                                                                                                                                                                                                                               | `false`  |
| on:inview_leave          | `function`             | -        | Event fired every time the target element leaves the viewport. Receives `event` object as an argument. Inside of `event.detail` you can find all the arguments specified [here](#observer-events-arguments) .                                                                                                                                                                                                                                                               | `false`  |
| on:inview_init           | `function`             | -        | Event fired on action initialization, before the observer starts observing the element. Receives lifecycle arguments specified [here](#lifecycle-events-arguments). In Svelte 5 these four handlers are `oninview_change`, `oninview_enter`, `oninview_leave`, and `oninview_init`.                                                                                                                                                                                       | `false`  |

### Observer events arguments

| Name                       | Type                        | Description                                                                                                                                                                                                 |
| -------------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| inView                     | `boolean`                   | Visibility state of the target element. If it's `true`, target passed at least the value of the `threshold` props.                                                                                          |
| entry                      | `IntersectionObserverEntry` | [Intersection Observer entry object](https://developer.mozilla.org/en-US/docs/Web/API/IntersectionObserverEntry) generated every time when IO callback is fired.                                            |
| scrollDirection.vertical   | `up` or `down`              | Vertical scrolling direction.                                                                                                                                                                               |
| scrollDirection.horizontal | `left` or `right`           | Horizontal scrolling direction.                                                                                                                                                                             |
| node                       | `HTMLElement`               | Element that is being observed                                                                                                                                                                              |
| observer                   | `IntersectionObserver`      | [Intersection Observer instance](https://developer.mozilla.org/en-US/docs/Web/API/IntersectionObserver) for the observed element. Among others, it allows to "turn off" the observer at the very beginning. |

### Lifecycle events arguments

| Name     | Type                   | Description                                                                                                                                                                                                 |
| -------- | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| node     | `HTMLElement`          | Element that is being observed                                                                                                                                                                              |
| observer | `IntersectionObserver` | [Intersection Observer instance](https://developer.mozilla.org/en-US/docs/Web/API/IntersectionObserver) for the observed element. Among others, it allows to "turn off" the observer at the very beginning. |

## Additional Info

### Usage with rootMargin

If you want to increase or decrease the area of the root, just pass the `rootMargin`. On the image below you can see the blue area being the `root`. It means that every time, the target element will enter or leave that area (or meet the specified threshold), a callback will be fired.

![Usage of rootMargin](https://raw.githubusercontent.com/maciekgrzybek/svelte-inview/master/demo/static/rootMargin.jpg)

## License

Distributed under the MIT License. See [LICENSE](./license.md) for more information.

## Contact

Maciek Grzybek - [@grzybek_maciek](https://twitter.com/grzybek_maciek) - maciekgrzybek1@gmail.com - [www.maciekgrzybek.dev](https://www.maciekgrzybek.dev)
