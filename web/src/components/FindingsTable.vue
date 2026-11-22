<script setup lang="ts">
import { computed, ref } from 'vue'
import { severityRank, type Finding, type Severity } from '../api'
import SeverityBadge from './SeverityBadge.vue'

const props = defineProps<{ findings: Finding[] }>()

const minSeverity = ref<Severity>('low')
const query = ref('')
const sortBy = ref<'severity' | 'file'>('severity')

// computed: cached, recalculated only when findings, filters or sort order change.
const visible = computed(() => {
  const q = query.value.trim().toLowerCase()
  const min = severityRank[minSeverity.value]
  const rows = props.findings.filter(
    (f) =>
      (severityRank[f.severity] ?? 0) >= min &&
      (!q || f.file.toLowerCase().includes(q) || f.rule_id.includes(q)),
  )
  // Copy before sorting: props are read-only and must never be mutated.
  return [...rows].sort((a, b) =>
    sortBy.value === 'severity'
      ? severityRank[b.severity] - severityRank[a.severity] || a.file.localeCompare(b.file)
      : a.file.localeCompare(b.file) || a.line - b.line,
  )
})
</script>

<template>
  <section class="card">
    <header class="toolbar">
      <h2>Findings <span class="muted">({{ visible.length }} of {{ findings.length }})</span></h2>
      <select v-model="minSeverity" aria-label="Minimum severity">
        <option value="low">All severities</option>
        <option value="medium">Medium and above</option>
        <option value="high">High and above</option>
        <option value="critical">Critical only</option>
      </select>
      <select v-model="sortBy" aria-label="Sort by">
        <option value="severity">Sort by severity</option>
        <option value="file">Sort by file</option>
      </select>
      <input v-model="query" type="search" placeholder="Filter by file or rule" aria-label="Filter findings" />
    </header>

    <table v-if="visible.length">
      <thead>
        <tr><th>Severity</th><th>Rule</th><th>Location</th><th>Secret (masked)</th></tr>
      </thead>
      <tbody>
        <!-- Stable :key from the fingerprint, never the index. -->
        <tr v-for="f in visible" :key="f.fingerprint">
          <td><SeverityBadge :level="f.severity" /></td>
          <td>
            <strong>{{ f.rule_id }}</strong>
            <div class="muted">{{ f.description }}</div>
          </td>
          <!--
            Everything is rendered with {{ }} interpolation, which HTML-escapes.
            v-html is deliberately never used: file names and contents come from the
            scanned repository and are attacker-controlled (XSS).
          -->
          <td><code>{{ f.file }}:{{ f.line }}:{{ f.column }}</code></td>
          <td><code>{{ f.masked }}</code></td>
        </tr>
      </tbody>
    </table>
    <p v-else class="muted">No findings match the current filters.</p>
  </section>
</template>

<style scoped>
.toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.toolbar h2 { margin: 0 auto 0 0; font-size: 18px; }
</style>
