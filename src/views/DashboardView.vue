<script setup lang="ts">
import { auth } from "../auth";
import { useRouter } from "vue-router";

const router = useRouter();

const handleLogout = async () => {
  await auth.logout();
  router.push("/");
};
</script>

<template>
  <div class="p-4 bg-green-100 rounded">
    <h2 class="text-xl font-bold mb-4">Dashboard</h2>
    <p class="mb-2">Welcome! You are logged in.</p>

    <div v-if="auth.client.getTokens()" class="mb-4">
      <p class="font-semibold text-sm text-gray-700 mb-1">Your Access Token:</p>
      <div
        class="bg-white p-3 rounded border border-green-200 break-all text-xs font-mono"
      >
        {{ auth.client.getTokens().accessToken }}
      </div>
    </div>

    <button
      @click="handleLogout"
      class="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded"
    >
      Logout
    </button>
  </div>
</template>
