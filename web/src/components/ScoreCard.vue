<script setup lang="ts">
import { computed } from 'vue'
import type { Report } from '../api'
import SeverityBadge from './SeverityBadge.vue'

const props = defineProps<{ report: Report }>()

const gradeClass = computed(() => {
  const g = props.report.score.grade
  return g === 'A' || g === 'B' ? 'good' : g === 'C' ? 'warn' : 'bad'
})
</script>

<template>
  <section class="card score">
    <div :class="['grade', gradeClass]" aria-label="Grade">{{ report.score.grade }}</div>

    <div class="details">
      <h2>{{ report.score.value }} / 100</h2>
      <p class="muted">
        {{ report.target }} · {{ report.files_scanned }} files scanned ·
        {{ report.files_skipped }} skipped · {{ report.duration_ms }} ms
      </p>
      <p v-if="report.score.capped" class="note">⚠ {{ report.score.reason }}</p>
      <p v-if="report.incomplete" class="note">⚠ Scan incomplete: {{ report.errors.length }} files could not be read</p>

      <!-- Explainability: every lost point traces back to a severity level. -->
      <table v-if="report.score.breakdown.length" class="breakdown">
        <thead>
          <tr><th>Severity</th><th>Findings</th><th>Weight</th><th>Points lost</th></tr>
        </thead>
        <tbody>
          <tr v-for="c in report.score.breakdown" :key="c.severity">
            <td><SeverityBadge :level="c.severity" /></td>
            <td>{{ c.count }}</td>
            <td>× {{ c.weight }}</td>
            <td>−{{ c.penalty }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted">No secrets found.</p>
    </div>
  </section>
</template>

<style scoped>
.score { display: flex; gap: 24px; align-items: flex-start; }
.grade {
  flex: 0 0 96px; height: 96px; border-radius: 16px;
  display: grid; place-items: center;
  font-size: 56px; font-weight: 800; color: #fff;
}
.good { background: #16a34a; }
.warn { background: #d97706; }
.bad { background: #b91c1c; }
.details { flex: 1; }
.details h2 { margin: 0 0 4px; }
.note { color: #b45309; margin: 4px 0; }
.breakdown { margin-top: 12px; width: auto; }
.breakdown td, .breakdown th { padding: 4px 16px 4px 0; }
</style>
