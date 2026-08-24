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

const inputClass =
  "rounded-lg border border-zinc-300 bg-transparent px-3 py-2 text-base " +
  "focus:outline-2 focus:outline-offset-1 focus:outline-indigo-500 dark:border-zinc-600";
</script>

<template>
  <main
    class="grid min-h-screen place-items-center bg-zinc-100 p-6 text-zinc-900 dark:bg-zinc-900 dark:text-zinc-100"
  >
    <form
      class="grid w-full max-w-sm gap-4 rounded-xl bg-white p-8 shadow-md dark:bg-zinc-800"
      @submit.prevent="submit"
    >
      <h1 class="text-xl font-semibold">Sign in</h1>
      <p class="text-sm text-zinc-500 dark:text-zinc-400">
        Demo credentials: <code>demo@example.com</code> / <code>password</code>
      </p>

      <label class="grid gap-1 text-sm font-medium">
        <span>Email</span>
        <input
          v-model="form.email"
          type="email"
          name="email"
          autocomplete="username"
          required
          autofocus
          :class="inputClass"
        />
      </label>

      <label class="grid gap-1 text-sm font-medium">
        <span>Password</span>
        <input
          v-model="form.password"
          type="password"
          name="password"
          autocomplete="current-password"
          required
          :class="inputClass"
        />
      </label>

      <p v-if="form.errors.email" class="text-sm text-red-600" role="alert">
        {{ form.errors.email }}
      </p>

      <button
        type="submit"
        :disabled="form.processing"
        class="cursor-pointer rounded-lg bg-indigo-500 px-3 py-2 text-base font-semibold text-white hover:bg-indigo-600 disabled:cursor-default disabled:opacity-60"
      >
        {{ form.processing ? "Signing in…" : "Sign in" }}
      </button>
    </form>
  </main>
</template>
