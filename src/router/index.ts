import { createRouter, createWebHistory } from "vue-router";
import HomeView from "../views/HomeView.vue";
import DashboardView from "../views/DashboardView.vue";
import { auth } from "../auth";

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: "/",
      name: "home",
      component: HomeView,
      beforeEnter: (to, from, next) => {
        if (auth.isAuthenticated.value) {
          next("/dashboard");
        } else {
          next();
        }
      },
    },
    {
      path: "/dashboard",
      name: "dashboard",
      component: DashboardView,
      beforeEnter: (to, from, next) => {
        if (!auth.isAuthenticated.value) {
          next("/");
        } else {
          next();
        }
      },
    },
    // Adding /callback as a route as well if needed, but App.vue handles it globally for now
    {
      path: "/callback",
      redirect: "/",
    },
  ],
});

export default router;
