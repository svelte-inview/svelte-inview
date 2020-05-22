# Svelte Inview

A Svelte component that monitors an element enters or leaves the viewport / parent element. Performant and efficient thanks to using [Intersection Observer](https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API) under the hood. Can be used in multiple projects including lazy loading images, infinite scrolling, playing/pausing video when in viewport, tracking user behavior firing link pre-fetching and animations and many many more.

<img src="demo/public/demo.gif" width="600px" align="center">

## Why bother?
- 👓️Watch for any element that enters or leaves the viewport (or another wrapper/parent element).
- 🏎️Thanks to using [Intersection Observer](https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API), Svelte Inview is blazing fast and doesn't block the main thread.
- 📦️ Tiny, yet powerful (just ~1tb). No external dependencies.
- 🎛️ Use it in number of different scenarios such as lazy loading images, infinite scrolling, playing/pausing video when in viewport, tracking user behavior firing link pre-fetching, animations and many many more.
- 🐥Easy to use API.
- ↕️ Detects the scrolling direction.

## Installation

Svelte Inview is distributed via [npm](https://www.npmjs.com/package/svelte-inview).

```sh
$ yarn add svelte-inview
# or
$ npm install --save svelte-inview
```