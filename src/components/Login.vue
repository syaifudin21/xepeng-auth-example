<template>
  <div class="flex-1 flex flex-col items-center justify-center p-6 sm:p-12">
    <!-- Login Card -->
    <div class="w-full max-w-[440px] bg-white dark:bg-[#242424] rounded-xl shadow-sm border border-neutral-200 dark:border-neutral-800 p-8 sm:p-12 flex flex-col items-center">
      <!-- Brand Logo -->
      <div class="mb-8 flex items-center justify-center">
        <div class="w-12 h-12 bg-primary dark:bg-white rounded-xl flex items-center justify-center">
          <span class="material-symbols-outlined text-white dark:text-primary text-3xl">fingerprint</span>
        </div>
      </div>
      <!-- Greeting -->
      <h1 class="text-primary dark:text-white text-3xl font-bold leading-tight tracking-tight text-center mb-2">
        Welcome Back!
      </h1>
      <p class="text-neutral-500 dark:text-neutral-400 text-base font-normal text-center mb-10">
        Please sign in to your account to continue.
      </p>
      <!-- Primary Action: Google Login -->
      <div class="w-full mb-6">
        <button class="w-full flex items-center justify-center gap-3 bg-white dark:bg-white h-14 px-6 rounded-lg border border-neutral-300 dark:border-transparent hover:bg-neutral-50 dark:hover:bg-neutral-100 transition-colors group">
          <div class="w-6 h-6 flex items-center justify-center">
            <svg height="24px" viewbox="0 0 24 24" width="24px" xmlns="http://www.w3.org/2000/svg">
              <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"></path>
              <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"></path>
              <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"></path>
              <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 12-4.53z" fill="#EA4335"></path>
            </svg>
          </div>
          <span class="text-neutral-800 font-semibold text-lg">Continue with Google</span>
        </button>
      </div>
      <!-- Divider -->
      <div class="w-full flex items-center gap-4 mb-8">
        <div class="flex-1 h-px bg-neutral-200 dark:bg-neutral-800"></div>
        <span class="text-neutral-400 text-xs font-bold uppercase tracking-widest">or</span>
        <div class="flex-1 h-px bg-neutral-200 dark:bg-neutral-800"></div>
      </div>
      <!-- Secondary Actions -->
      <div class="w-full text-center">
        <a class="text-primary dark:text-white text-sm font-semibold hover:underline flex items-center justify-center gap-2" href="#">
          Other sign-in methods
          <span class="material-symbols-outlined text-sm">arrow_forward</span>
        </a>
      </div>
    </div>
    <!-- External Help Links -->
    <div class="mt-8 flex gap-6 text-sm font-medium text-neutral-500 dark:text-neutral-500">
      <a class="hover:text-primary dark:hover:text-white transition-colors" href="#">Help Center</a>
      <a class="hover:text-primary dark:hover:text-white transition-colors" href="#">Privacy Policy</a>
      <a class="hover:text-primary dark:hover:text-white transition-colors" href="#">Terms of Service</a>
    </div>
  </div>
  <!-- Footer Security Note -->
  <footer class="p-8 flex justify-center items-center gap-2 text-neutral-400">
    <span class="material-symbols-outlined text-lg">lock</span>
    <span class="text-xs uppercase tracking-widest font-bold">Secure Encrypted Authentication</span>
  </footer>
</template>

<script lang="ts">
import { defineComponent } from 'vue';

export default defineComponent({
  name: 'Login',
});
</script>

<style scoped>
/* You can add component-specific styles here if needed,
   but Tailwind classes are handling most of the styling. */
</style>
