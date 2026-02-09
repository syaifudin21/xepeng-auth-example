<script setup lang="ts">
import { auth } from "../auth";
</script>

<template>
  <div class="p-4 bg-gray-100 rounded">
    <p class="mb-2">You are not logged in.</p>
    <button
      @click="auth.login"
      :disabled="auth.isLoading.value"
      class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded disabled:opacity-50"
    >
      {{ auth.isLoading.value ? "Loading..." : "Login with Xepeng" }}
    </button>
  </div>

  <div v-if="auth.error.value" class="mt-4 p-2 bg-red-100 text-red-700 rounded">
    Error: {{ auth.error.value }}
  </div>
</template>
