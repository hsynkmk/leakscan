<script setup lang="ts">
import ScanForm from './components/ScanForm.vue'
import ScoreCard from './components/ScoreCard.vue'
import FindingsTable from './components/FindingsTable.vue'
import { useScan } from './composables/useScan'

const { report, loading, error, run } = useScan()
</script>

<template>
  <main class="layout">
    <header class="hero">
      <h1>leakscan</h1>
      <p class="muted">Find hardcoded secrets before they reach the main branch.</p>
    </header>

    <section class="card">
      <ScanForm :loading="loading" @scan="run" />
      <p v-if="loading" class="muted">Scanning…</p>
      <p v-else-if="error" class="error" role="alert">{{ error }}</p>
    </section>

    <template v-if="report && !loading">
      <ScoreCard :report="report" />
      <FindingsTable :findings="report.findings" />
    </template>
  </main>
</template>
