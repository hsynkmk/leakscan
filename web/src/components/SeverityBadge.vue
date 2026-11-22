<script setup lang="ts">
import type { Severity } from '../api'

defineProps<{ level: Severity }>()
</script>

<template>
  <!-- Text + color: severity is never conveyed by color alone (accessibility). -->
  <span :class="['badge', `badge--${level}`]">{{ level }}</span>
</template>

<style scoped>
.badge {
  display: inline-block;
  min-width: 64px;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-align: center;
  text-transform: uppercase;
}
.badge--critical { background: #7f1d1d; color: #fff; }
.badge--high { background: #dc2626; color: #fff; }
.badge--medium { background: #f59e0b; color: #1f2937; }
.badge--low { background: #3b82f6; color: #fff; }
</style>
