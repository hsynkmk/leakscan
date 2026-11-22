import { ref, shallowRef } from 'vue'
import { startScan, type Report, type ScanRequest } from '../api'

// useScan wraps one scan request with loading and error state.
// A new scan aborts the previous one, so a slow old response can never
// overwrite a newer result (a classic race condition in UIs).
export function useScan() {
  const report = shallowRef<Report | null>(null) // large, replaced as a whole: no deep reactivity needed
  const loading = ref(false)
  const error = ref<string | null>(null)
  let controller: AbortController | null = null

  async function run(req: ScanRequest) {
    controller?.abort()
    controller = new AbortController()
    loading.value = true
    error.value = null
    try {
      report.value = await startScan(req, controller.signal)
    } catch (e) {
      if ((e as Error).name !== 'AbortError') {
        error.value = (e as Error).message
        report.value = null
      }
    } finally {
      loading.value = false
    }
  }

  return { report, loading, error, run }
}
