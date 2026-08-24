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
  <main class="page">
    <div class="card">
      <h1>Dashboard</h1>
      <p>
        You are signed in as <strong>{{ user.email }}</strong> (user #{{ user.id }}).
      </p>
      <p class="hint">
        This page is protected: without a valid <code>startkit_session</code>
        cookie the server redirects to the login page.
      </p>
      <button type="button" @click="logout">Log out</button>
    </div>
  </main>
</template>
