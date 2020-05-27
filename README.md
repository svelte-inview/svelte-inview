# Svelte Inview

A Svelte component that monitors an element enters or leaves the viewport/parent element. Performant and efficient thanks to using [Intersection Observer](https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API) under the hood. Can be used in multiple projects including lazy loading images, infinite scrolling, playing/pausing the video when in the viewport, tracking user behaviour firing link pre-fetching and animations and many many more.

<img src="https://raw.githubusercontent.com/maciekgrzybek/svelte-inview/master/demo/public/demo.gif" width="600px" align="center">

🔥Check it out live [here](https://svelte-inview.netlify.app/)

## Why bother?
- 👓️Watch for any element that enters or leaves the viewport (or another wrapper/parent element).
- 🏎️Thanks to using [Intersection Observer](https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API), Svelte Inview is blazing fast and doesn't block the main thread.
- 📦️ Tiny, yet powerful (just ~2kb). No external dependencies (well, apart from Svelte).
- 🎛️ Use it in several different scenarios such as lazy loading images, infinite scrolling, playing/pausing the video when in the viewport, firing link pre-fetching, animations and many many more.
- 🐥Easy to use API.
- ↕️ Detects the scrolling direction.

## Installation
The only thing you need is Svelte itself.

## Installation

Svelte Inview is distributed via [npm](https://www.npmjs.com/package/svelte-inview).

```sh
$ yarn add svelte-inview
# or
$ npm install --save svelte-inview
```

> ⚠️ Modern browsers have the full support of Intersection Observer, but if you need to support ones like IE you can use this [simple polyfill](https://www.npmjs.com/package/intersection-observer). Just install it and import it in your project.

## Usage

### Basic Use Case
This is the most basic use case for `svelte-inview`. The `ref` props is required. You can also pass other [configuration props](#props). You can check if the element is visible by getting the `inView` from the component or from the inside of the callback method - `on:change`.

```html

<script>
  import Inview from 'svelte-inview';
  let ref;
</script>

<Inview
  let:inView
  wrapper={ref}
  on:change={(event) => {
    const { inView, entry, scrollDirection, observe, unobserve } = event.detail;
  }}
  on:enter={(event) => {
    const { entry, scrollDirection, observe, unobserve } = event.detail;
  }}
  on:leave={(event) => {
    const { entry, scrollDirection, observe, unobserve } = event.detail;
  }}>
  <div bind:this={ref}>{inView ? 'Hey I am in the viewport' : 'Bye, Bye'}</div>

</Inview>
```
### Lazy Loading Images
Svelte Inview lets you easily lazy load images. For a better UX we can pass a `rootMargin="50px"` props, so the image will be loaded when scroll is 50px before the viewport. After it's in the DOM, you don't want to observe it anymore, hence the `unobserveOnEnter` props set to true.

```html

<script>
  import
  import Inview from 'svelte-inview';
  let ref;
</script>

<Inview
  let:inView={inView}
  wrapper={ref}
  rootMargin="50px"
  unobserveOnEnter={true}
  <div bind:this={ref}>
    {#if inView}
      <img src="path/to/image.jpg">
    {:else}
      <div class="placeholder" />
    {/if}
  </div>

</Inview>
```

### Video Control
You can play/pause a video when it's in/out of the viewport. Simply pass correct methods in `on:enter` and `on:leave` callbacks.

```html
<script>
  import Inview from 'svelte-inview';
  let ref;
  let videoRef;
</script>

<Inview
  wrapper={ref}
  on:enter={() => videoRef.play()}
  on:leave={() => videoRef.pause()}>
  <div bind:this={ref}>
    <video width="500" controls bind:this={videoRef}>
      <source src="path/to/video.mp4" type="video/mp4" />
    </video>
  </div>
</Inview>
```

### Animations
You can also add some cool animations when an element enters the viewport. To make sure the animation won't fire too soon you can pass a negative value to `rootMargin`. When `inView` is true add an animation class to your target. Additionally, you can detect the scroll direction to make the animations even cooler!
```html

<script>
  import
  import Inview from 'svelte-inview';
  let ref;
</script>

<Inview
  let:inView
  let:scrollDirection
  wrapper={ref}
  rootMargin="-50px"
  unobserveOnEnter={true}>
  <div bind:this={ref}>
    <div
      class:animate={inView}
      class:animateFromBottom={scrollDirection.vertical === 'down'}
      class:animateFromTop={scrollDirection.vertical === 'top'}>
      Animate me!
    </div>
  </div>

</Inview>
```

## API
### Props
|Name  |Type   |Default   |Description   |Required  |
|---|---|---|---|---|
| wrapper  | `HTMLElement`  | - |The target element.   |`true`   |
|root   | `HTMLElement`   | `window`   | The element that is used as the viewport for checking visibility of the target. Must be the ancestor of the target.   |  `false` |
|rootMargin   |`string`   |`0px`   | Margin around the root element. Values similar to the CSS margin property, e.g. "10px 20px 30px 40px". Can also be a percentage. [See more](#usage-with-rootmargin).   |`false` |
| threshold  | `number` or `number[]`  |  `0` |  Either a single number or an array of numbers which indicate at what percentage of the target's visibility the observer's callback should be executed. If you only want to detect when visibility passes the 50% mark, you can use a value of 0.5. If you want the callback to run every time visibility passes another 25%, you would specify the array [0, 0.25, 0.5, 0.75, 1]. The default is 0 (meaning as soon as even one pixel is visible, the callback will be run) | `false`  |
| unobserveOnEnter  | `boolean`  |  `false` | If true, target element stops being observed after the first time it appears in the viewport. Can be used when you want to fire the callback only once.  | `false`  |
|on:change   | `function`  | -  | Callback fired every time the target element meets the specified threshold. Receives `event` object as an argument. Inside of `event.detail` you can find all the callback arguments specified [here](#callback-arguments).   | `false`  |
|on:enter   | `function`  | -  | Callback fired every time the target element enters the viewport. Receives `event` object as an argument. Inside of `event.detail` you can find all the callback arguments specified [here](#callback-arguments) (except for `inView` as this will always be `true` for this callback).   | `false`  |
|on:change   | `function`  | -  | Callback fired every time the target element leaves the viewport. Receives `event` object as an argument. Inside of `event.detail` you can find all the callback arguments specified [here](#callback-arguments) (except for `inView` as this will always be `false` for this callback).   | `false`  |

### Callback arguments
|Name  |Type   |Description|
|---|---|---|
|  inView |  `boolean` | Visibility state of the target element. If it's `true`, target passed at least the value of the `threshold` props.  | 
| entry | `IntersectionObserverEntry`|[Intersection Observer entry object](https://developer.mozilla.org/en-US/docs/Web/API/IntersectionObserverEntry) generated every time when IO callback is fired. | 
| scrollDirection.vertical | `up` or `down` | Vertical scrolling direction. | 
| scrollDirection.horizontal | `left` or `right` | Horizontal scrolling direction. | 
| unobserve | `function` | Allows to stop observing the element. | 
| observe | `function` | Allows to re-start observing the element. | 

## Additional Info
### Usage with rootMargin
If you want to increase or decrease the area of the root, just pass the `rootMargin`. On the image below you can see the blue area being the `root`. It means that every time, the target element will enter or leave that area (or meet the specified threshold), a callback will be fired.

![Usage of rootMargin](https://raw.githubusercontent.com/maciekgrzybek/svelte-inview/master/demo/public/rootMargin.jpg)

## License
Distributed under the MIT License. See `LICENSE` for more information.

## Contact
Maciek Grzybek - [@maciek_g88](https://twitter.com/maciek_g88) - maciekgrzybek1@gmail.com - [www.maciekgrzybek.dev](www.maciekgrzybek.dev)