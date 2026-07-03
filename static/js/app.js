// app.js — entry point. Bootstraps the UI on DOMContentLoaded.


import { init } from "./ui.js";

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init, { once: true });
} else {
  init();
}
