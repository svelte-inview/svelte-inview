import { e as error } from "../../../chunks/index2.js";
function load({ params }) {
  if (params.slug === "default-settings") {
    return {
      inViewOptions: {}
    };
  }
  if (params.slug === "root-margin") {
    return {
      inViewOptions: { rootMargin: "-25%" }
    };
  }
  if (params.slug === "threshold") {
    return {
      inViewOptions: { threshold: 1 }
    };
  }
  if (params.slug === "unobserve-on-enter") {
    return {
      inViewOptions: { unobserveOnEnter: true, threshold: 1 }
    };
  }
  if (params.slug === "direction") {
    return {
      showDirection: true
    };
  }
  throw error(404, "Not found");
}
export {
  load
};
