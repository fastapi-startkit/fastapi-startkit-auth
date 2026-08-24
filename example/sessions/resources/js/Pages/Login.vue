<script setup lang="ts">
import { useForm } from "@inertiajs/vue3";

const form = useForm({
  email: "",
  password: "",
});

function submit(): void {
  form.post("/login", {
    onFinish: () => form.reset("password"),
  });
}
</script>

<template>
  <main class="page">
    <form class="card" @submit.prevent="submit">
      <h1>Sign in</h1>
      <p class="hint">Demo credentials: <code>demo@example.com</code> / <code>password</code></p>

      <label class="field">
        <span>Email</span>
        <input
          v-model="form.email"
          type="email"
          name="email"
          autocomplete="username"
          required
          autofocus
        />
      </label>

      <label class="field">
        <span>Password</span>
        <input
          v-model="form.password"
          type="password"
          name="password"
          autocomplete="current-password"
          required
        />
      </label>

      <p v-if="form.errors.email" class="error" role="alert">
        {{ form.errors.email }}
      </p>

      <button type="submit" :disabled="form.processing">
        {{ form.processing ? "Signing in…" : "Sign in" }}
      </button>
    </form>
  </main>
</template>
