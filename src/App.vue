<script setup lang="ts">
import { onMounted } from "vue";
import { useRouter } from "vue-router";
import { auth } from "./auth";

const router = useRouter();

onMounted(async () => {
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.has("code") && urlParams.has("state")) {
    console.log("[Debug] Callback detected in URL, processing...");
    await auth.handleCallback();
    console.log(
      "[Debug] Callback processed, authenticated:",
      auth.isAuthenticated.value,
    );
    // Redirect to dashboard after successful callback
    console.log("[Debug] Pushing to /dashboard");
    router.push("/dashboard");
    // window.history.replaceState({}, document.title, window.location.pathname);
  }
});
</script>

<template>
  <div class="container mx-auto p-4">
    <h1 class="text-2xl font-bold mb-4">OAuth Demo</h1>
    <RouterView />
  </div>
</template>
