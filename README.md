# Svelte Inview

A Svelte component that monitors an element enters or leaves the viewport / parent element. Performant and efficient thanks to using [Intersection Observer](https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API) under the hood. Can be used in multiple projects including lazy loading images, infinite scrolling, playing/pausing video when in viewport, tracking user behavior firing link pre-fetching and animations and many many more.

<img src="demo/public/demo.gif" width="600px" align="center">

## Why bother?
- 👓️Watch for any element that enters or leaves the viewport (or another wrapper/parent element).
- 🏎️Thanks to using [Intersection Observer](https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API), Svelte Inview is blazing fast and doesn't block the main thread.
- 📦️ Tiny, yet powerful (just ~2kb). No external dependencies (well, apart from Svelte).
- 🎛️ Use it in number of different scenarios such as lazy loading images, infinite scrolling, playing/pausing video when in viewport, firing link pre-fetching, animations and many many more.
- 🐥Easy to use API.
- ↕️ Detects the scrolling direction.

## Installation
Only thing you need is Svelte itself.

## Installation

Svelte Inview is distributed via [npm](https://www.npmjs.com/package/svelte-inview).

```sh
$ yarn add svelte-inview
# or
$ npm install --save svelte-inview
```

> ⚠️ Modern browsers have full support of Intersection Observer, but if you need to support ones like IE you can use this [simple polyfill](https://www.npmjs.com/package/intersection-observer). Just install it and import it in your project.

## Usage

### Basic Use Case
This is the most basic use case for `svelte-inview`. The `ref` props is required. You can also pass other [configuration props](#props). You can check if element is visible by getting the `inView` from the component or from the inside of the callback methods - `on:enter` or `on:leave`.

```html

<script>
  import Inview from 'svelte-inview';
  let ref;
</script>

<Inview
  let:inView
  wrapper={ref}
  on:change={(event) => {
    const { entry, scrollDirection, observe, unobserve } = event.detail;
  }}
  on:enter={(event) => {
    const { inView, entry, scrollDirection, observe, unobserve } = event.detail;
  }}
  on:leave={(event) => {
    const { inView, entry, scrollDirection, observe, unobserve } = event.detail;
  }}>
  <div bind:this={ref}>{inView ? 'Hey I am in the viewport' : 'Bye, Bye'}</div>

</Inview>
```
### Lazy Loading Images
Svelte Inview let's you easily lazy load images. For a better UX we can pass a `rootMargin="50px"` props, so the image will be loaded when scroll is 50px before the viewport. After it's in the DOM, you don't want to observe it anymore, hence the `unobserveOnEnter` props set to true.

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
### Infinite Scrolling
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
You can also add some cool animations when element enters the viewport. To make sure the animation won't fire too soon you can pass negative value to `rootMargin`. When `inView` is true add an animation class to your target. Additionally you can detect the scroll direction to make the animations even cooler!
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
### Callback arguments