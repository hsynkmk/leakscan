<script setup lang="ts">
import { ref } from 'vue'
import type { ScanRequest } from '../api'

defineProps<{ loading: boolean }>()
const emit = defineEmits<{ scan: [req: ScanRequest] }>()

const repoUrl = ref('')

function scanRepo() {
  // The server validates the URL again: client-side checks are only for UX.
  emit('scan', { repo_url: repoUrl.value.trim() })
}
</script>

<template>
  <form class="scan-form" @submit.prevent="scanRepo">
    <input
      v-model="repoUrl"
      type="url"
      required
      placeholder="https://github.com/owner/repository"
      aria-label="Repository URL"
      :disabled="loading"
    />
    <button type="submit" :disabled="loading">Scan repository</button>
    <button type="button" class="secondary" :disabled="loading" @click="emit('scan', { demo: true })">
      Scan demo project
    </button>
  </form>
</template>

<style scoped>
.scan-form { display: flex; gap: 8px; flex-wrap: wrap; }
.scan-form input { flex: 1 1 320px; }
</style>
