<script setup lang="ts">
import { router } from "@inertiajs/vue3";

defineProps<{
  user: {
    id: number;
    email: string;
  };
}>();

function logout(): void {
  router.post("/logout");
}
</script>

<template>
  <main
    class="grid min-h-screen place-items-center bg-zinc-100 p-6 text-zinc-900 dark:bg-zinc-900 dark:text-zinc-100"
  >
    <div
      class="grid w-full max-w-sm gap-4 rounded-xl bg-white p-8 shadow-md dark:bg-zinc-800"
    >
      <h1 class="text-xl font-semibold">Dashboard</h1>
      <p>
        You are signed in as <strong>{{ user.email }}</strong> (user #{{ user.id }}).
      </p>
      <p class="text-sm text-zinc-500 dark:text-zinc-400">
        This page is protected: without a valid <code>startkit_session</code>
        cookie the server redirects to the login page.
      </p>
      <button
        type="button"
        class="cursor-pointer rounded-lg bg-indigo-500 px-3 py-2 text-base font-semibold text-white hover:bg-indigo-600"
        @click="logout"
      >
        Log out
      </button>
    </div>
  </main>
</template>
