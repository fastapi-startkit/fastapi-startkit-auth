import { createApp, h, type DefineComponent } from "vue";
import { createInertiaApp } from "@inertiajs/vue3";
import "../css/app.css";

createInertiaApp({
  resolve: (name) => {
    const pages = import.meta.glob<{ default: DefineComponent }>(
      "./Pages/**/*.vue",
      { eager: true },
    );
    const page = pages[`./Pages/${name}.vue`];
    if (!page) {
      throw new Error(`Unknown Inertia page: ${name}`);
    }
    return page.default;
  },
  setup({ el, App, props, plugin }) {
    createApp({ render: () => h(App, props) })
      .use(plugin)
      .mount(el);
  },
});
