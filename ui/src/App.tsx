import { useState, useEffect, useRef, useCallback } from 'react'
import {
  Play,
  Square,
  Settings as SettingsIcon,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Terminal,
  ShieldAlert,
  GitBranch,
  History,
  Activity,
  Layers,
  Sparkles,
  RefreshCw,
  FolderOpen,
  Wifi,
  WifiOff,
  ShieldCheck,
  Check,
  X,
  Code2
} from 'lucide-react'
import { API_BASE, WS_BASE } from './config'
import './App.css'

interface TaskStep {
  id?: string
  step: number
  type: 'thought' | 'tool_call' | 'tool_result' | 'status' | 'error'
  title: string
  content: string
  metadata?: any
  timestamp: string
}

interface VerificationCheck {
  check_name: string
  check_type: string
  command?: string
  success: boolean
  exit_code?: number
  output: string
  evidence_summary: string
}

interface TaskReport {
  task_id: string
  goal: string
  status: string
  summary_of_actions: string[]
  files_created_or_modified: string[]
  diff_summary?: string
  executed_verification_checks: VerificationCheck[]
  skipped_or_failed_checks: string[]
  unresolved_risks_or_limitations: string[]
}

interface ApprovalRequest {
  approval_id: string
  task_id: string
  tool_name: string
  arguments: any
  permission_level: string
  reason: string
  sequence_id?: number
}

interface DiffFile {
  filename: string
  oldPath: string
  newPath: string
  additions: number
  deletions: number
  isNew?: boolean
  isDeleted?: boolean
  isRenamed?: boolean
  lines: { type: 'add' | 'delete' | 'normal' | 'chunk' | 'header'; text: string }[]
}

function parseGitDiff(rawDiff: string): DiffFile[] {
  if (!rawDiff || !rawDiff.trim()) return []
  const files: DiffFile[] = []
  const rawFiles = rawDiff.split(/(?=diff --git )/g)

  for (const block of rawFiles) {
    if (!block.trim()) continue
    const lines = block.split('\n')
    let filename = 'Modified File'
    const headerMatch = lines[0].match(/diff --git a\/(.+?) b\/(.+)/)
    if (headerMatch) {
      filename = headerMatch[2]
    }

    let additions = 0
    let deletions = 0
    let isNew = false
    let isDeleted = false
    let isRenamed = false
    const parsedLines: { type: 'add' | 'delete' | 'normal' | 'chunk' | 'header'; text: string }[] = []

    for (const line of lines) {
      if (line.startsWith('new file mode') || line.startsWith('--- /dev/null')) {
        isNew = true
      } else if (line.startsWith('deleted file mode') || line.startsWith('+++ /dev/null')) {
        isDeleted = true
        if (headerMatch) filename = headerMatch[1]
      } else if (line.startsWith('rename from ') || line.startsWith('rename to ')) {
        isRenamed = true
      }

      if (
        line.startsWith('diff --git') ||
        line.startsWith('index ') ||
        line.startsWith('---') ||
        line.startsWith('+++') ||
        line.startsWith('similarity ') ||
        line.startsWith('rename ')
      ) {
        parsedLines.push({ type: 'header', text: line })
      } else if (line.startsWith('@@')) {
        parsedLines.push({ type: 'chunk', text: line })
      } else if (line.startsWith('+')) {
        additions++
        parsedLines.push({ type: 'add', text: line })
      } else if (line.startsWith('-')) {
        deletions++
        parsedLines.push({ type: 'delete', text: line })
      } else {
        parsedLines.push({ type: 'normal', text: line })
      }
    }

    files.push({
      filename,
      oldPath: headerMatch ? headerMatch[1] : filename,
      newPath: headerMatch ? headerMatch[2] : filename,
      additions,
      deletions,
      isNew,
      isDeleted,
      isRenamed,
      lines: parsedLines,
    })
  }
  return files
}

export default function App() {
  // State
  const [goal, setGoal] = useState('')
  const [provider, setProvider] = useState('gemini')
  const [model, setModel] = useState('gemini-2.5-flash')
  const [maxSteps, setMaxSteps] = useState(30)
  const [currentWorkspace, setCurrentWorkspace] = useState('')
  const [activeTab, setActiveTab] = useState<'timeline' | 'diff' | 'verification' | 'history'>('timeline')

  const [currentTaskId, setCurrentTaskId] = useState<string | null>(null)
  const currentTaskIdRef = useRef<string | null>(null)
  useEffect(() => {
    currentTaskIdRef.current = currentTaskId
  }, [currentTaskId])

  const [taskStatus, setTaskStatus] = useState<string>('IDLE')
  const [currentStep, setCurrentStep] = useState<number>(0)
  const [timeline, setTimeline] = useState<TaskStep[]>([])
  const [gitDiff, setGitDiff] = useState<string>('')
  const [selectedDiffFile, setSelectedDiffFile] = useState<number>(0)
  const [finalReport, setFinalReport] = useState<TaskReport | null>(null)

  // Approval state & error handling
  const [pendingApproval, setPendingApproval] = useState<ApprovalRequest | null>(null)
  const pendingApprovalRef = useRef<ApprovalRequest | null>(null)
  useEffect(() => {
    pendingApprovalRef.current = pendingApproval
  }, [pendingApproval])

  const [approvalResolving, setApprovalResolving] = useState(false)
  const [approvalError, setApprovalError] = useState<string | null>(null)

  // Modals
  const [showSettings, setShowSettings] = useState(false)
  const [showWorkspaceModal, setShowWorkspaceModal] = useState(false)
  const [workspaceInput, setWorkspaceInput] = useState('')
  const [historyTasks, setHistoryTasks] = useState<any[]>([])
  const [settingsError, setSettingsError] = useState<string | null>(null)
  const [workspaceError, setWorkspaceError] = useState<string | null>(null)
  const [isCancelling, setIsCancelling] = useState(false)
  const [cancelError, setCancelError] = useState<string | null>(null)

  // Accessibility refs for focus management
  const approveBtnRef = useRef<HTMLButtonElement | null>(null)
  const approvalModalRef = useRef<HTMLDivElement | null>(null)

  // WebSocket Connection State
  const [wsStatus, setWsStatus] = useState<'connected' | 'connecting' | 'disconnected' | 'error'>('connecting')
  const reconnectTimerRef = useRef<number | null>(null)

  // Settings State
  const [settings, setSettings] = useState({
    openai_api_key_set: false,
    anthropic_api_key_set: false,
    gemini_api_key_set: false,
    ollama_base_url: 'http://localhost:11434/v1',
    auto_approve_routine: true,
    auto_approve_sensitive: false,
    current_workspace: '',
  })
  const [inputApiKey, setInputApiKey] = useState('')

  const authTokenRef = useRef<string>('')
  const wsRef = useRef<WebSocket | null>(null)
  const timelineEndRef = useRef<HTMLDivElement | null>(null)

  const authFetch = useCallback(async (url: string, options: RequestInit = {}) => {
    const headers = new Headers(options.headers || {})
    if (authTokenRef.current) {
      headers.set('X-Agent-Auth-Token', authTokenRef.current)
    }
    return fetch(url, { ...options, headers })
  }, [])

  const loadSettings = useCallback(async (tok?: string) => {
    try {
      const headers: Record<string, string> = {}
      const token = tok || authTokenRef.current
      if (token) headers['X-Agent-Auth-Token'] = token
      const res = await fetch(`${API_BASE}/api/settings`, { headers })
      if (res.ok) {
        const data = await res.json()
        setSettings(data)
        if (data.current_workspace) {
          setCurrentWorkspace(data.current_workspace)
          setWorkspaceInput(data.current_workspace)
        }
      }
    } catch {
      // API may be temporarily offline
    }
  }, [])

  const loadWorkspaces = useCallback(async (tok?: string) => {
    try {
      const headers: Record<string, string> = {}
      const token = tok || authTokenRef.current
      if (token) headers['X-Agent-Auth-Token'] = token
      const res = await fetch(`${API_BASE}/api/workspaces`, { headers })
      if (res.ok) {
        const data = await res.json()
        if (data.current) {
          setCurrentWorkspace(data.current)
          setWorkspaceInput(data.current)
        }
      }
    } catch {
      // Ignore background fetch error
    }
  }, [])

  const fetchPendingApprovals = useCallback(async (tok?: string) => {
    try {
      const headers: Record<string, string> = {}
      const token = tok || authTokenRef.current
      if (token) headers['X-Agent-Auth-Token'] = token
      const res = await fetch(`${API_BASE}/api/approvals/pending`, { headers })
      if (res.ok) {
        const data = await res.json()
        const list: ApprovalRequest[] = data.approvals || []
        if (list.length > 0) {
          // Select the latest pending approval or active run's approval
          const activeRunApproval = currentTaskIdRef.current
            ? list.find((a) => a.task_id === currentTaskIdRef.current)
            : list[list.length - 1]
          const target = activeRunApproval || list[list.length - 1]
          setPendingApproval(target)
          setApprovalError(null)
          setTaskStatus('PENDING_APPROVAL')
        } else {
          setPendingApproval(null)
          setApprovalError(null)
        }
      }
    } catch {
      // Ignore pending approvals fetch error
    }
  }, [])

  const loadTaskHistory = useCallback(async (tok?: string) => {
    try {
      const headers: Record<string, string> = {}
      const token = tok || authTokenRef.current
      if (token) headers['X-Agent-Auth-Token'] = token
      const res = await fetch(`${API_BASE}/api/tasks`, { headers })
      if (res.ok) {
        const data = await res.json()
        setHistoryTasks(data.tasks || [])
      }
    } catch {
      // Ignore background fetch error
    }
  }, [])

  const fetchDiff = useCallback(async (workspace?: string) => {
    try {
      const ws = workspace || currentWorkspace
      const url = ws ? `${API_BASE}/api/diff?workspace_path=${encodeURIComponent(ws)}` : `${API_BASE}/api/diff`
      const res = await authFetch(url)
      if (res.ok) {
        const data = await res.json()
        setGitDiff(data.diff || '')
      }
    } catch {
      // Ignore diff fetch error
    }
  }, [authFetch, currentWorkspace])

  const handleSocketEvent = useCallback((type: string, data: any) => {
    const timestamp = new Date().toLocaleTimeString()

    // Validate task_id for task-scoped events if task_id is present in event data
    if (
      data &&
      data.task_id &&
      currentTaskIdRef.current &&
      data.task_id !== currentTaskIdRef.current
    ) {
      // Ignore stale event belonging to another or previous task run
      return
    }

    if (type === 'task_status') {
      setTaskStatus(data.status)
      if (['CANCELLED', 'FAILED', 'COMPLETED', 'PARTIALLY_COMPLETED'].includes(data.status)) {
        setIsCancelling(false)
        setCancelError(null)
      }
    } else if (type === 'step_start') {
      setCurrentStep(data.step)
      setTimeline((prev) => [
        ...prev,
        {
          step: data.step,
          type: 'status',
          title: `Step ${data.step} / ${data.max_steps}`,
          content: 'Reasoning and inspecting workspace...',
          timestamp,
        },
      ])
    } else if (type === 'agent_thought') {
      setTimeline((prev) => [
        ...prev,
        {
          step: data.step,
          type: 'thought',
          title: 'Agent Reasoning',
          content: data.thought,
          timestamp,
        },
      ])
    } else if (type === 'tool_executing') {
      setTimeline((prev) => [
        ...prev,
        {
          step: currentStep,
          type: 'tool_call',
          title: `Tool: ${data.tool}`,
          content: JSON.stringify(data.arguments, null, 2),
          timestamp,
        },
      ])
    } else if (type === 'tool_result') {
      setTimeline((prev) => [
        ...prev,
        {
          step: currentStep,
          type: 'tool_result',
          title: `Result: ${data.tool} (${data.success ? 'Success' : 'Failed'})`,
          content: data.output || data.error || '(no output)',
          metadata: { success: data.success },
          timestamp,
        },
      ])
      fetchDiff()
    } else if (type === 'approval_required') {
      // Sequence and task_id validation
      const currentPending = pendingApprovalRef.current
      if (data.approval) {
        if (
          currentPending &&
          data.approval.sequence_id !== undefined &&
          currentPending.sequence_id !== undefined &&
          data.approval.sequence_id < currentPending.sequence_id
        ) {
          // Reject older / stale approval event
          return
        }
        setTaskStatus('PENDING_APPROVAL')
        setPendingApproval(data.approval)
        setApprovalError(null)
      }
    } else if (type === 'approval_resolved') {
      const currentPending = pendingApprovalRef.current
      if (
        currentPending &&
        data.approval_id &&
        currentPending.approval_id !== data.approval_id
      ) {
        // Unrelated or old approval resolution; ignore
        return
      }
      setPendingApproval(null)
      setApprovalError(null)
    } else if (type === 'task_completed') {
      setTaskStatus(data.status)
      setIsCancelling(false)
      setCancelError(null)
      setFinalReport(data.report)
      fetchDiff()
      loadTaskHistory()
    } else if (type === 'task_error') {
      setTaskStatus('FAILED')
      setTimeline((prev) => [
        ...prev,
        {
          step: currentStep,
          type: 'error',
          title: 'Task Error',
          content: data.error,
          timestamp,
        },
      ])
    }
  }, [currentStep, fetchDiff, loadTaskHistory])

  const resolveApproval = useCallback(async (approved: boolean) => {
    if (!pendingApproval || approvalResolving) return
    setApprovalResolving(true)
    setApprovalError(null)

    try {
      const res = await authFetch(`${API_BASE}/api/approvals/${pendingApproval.approval_id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approved }),
      })

      if (!res.ok) {
        let errMsg = `Failed to resolve approval (HTTP ${res.status})`
        try {
          const data = await res.json()
          if (data && data.detail) errMsg = data.detail
        } catch {}
        if (res.status === 404) {
          // Approval already resolved, cancelled, or expired on server
          setPendingApproval(null)
          setApprovalError(null)
          return
        }
        setApprovalError(errMsg)
        // Keep pendingApproval intact on server error
        return
      }

      // Confirmed success:
      setPendingApproval(null)
      setApprovalError(null)
    } catch (err: any) {
      setApprovalError(err?.message || 'Network error while submitting approval resolution.')
    } finally {
      setApprovalResolving(false)
    }
  }, [pendingApproval, approvalResolving, authFetch])

  const setupWebSocketRef = useRef<((tok?: string) => void) | null>(null)

  const setupWebSocket = useCallback((token?: string) => {
    if (reconnectTimerRef.current) {
      window.clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }

    if (wsRef.current) {
      wsRef.current.onclose = null
      wsRef.current.onerror = null
      wsRef.current.onmessage = null
      wsRef.current.close()
      wsRef.current = null
    }

    setWsStatus('connecting')
    const tok = token || authTokenRef.current
    const wsUrl = `${WS_BASE}/ws?token=${encodeURIComponent(tok)}`
    
    try {
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        setWsStatus('connected')
        fetchPendingApprovals(tok)
      }

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          handleSocketEvent(msg.type, msg.data)
        } catch (err) {
          console.error('WebSocket parse error:', err)
        }
      }

      ws.onerror = () => {
        setWsStatus('error')
      }

      ws.onclose = () => {
        setWsStatus('disconnected')
        reconnectTimerRef.current = window.setTimeout(() => {
          setupWebSocketRef.current?.()
        }, 3000)
      }
    } catch {
      setWsStatus('error')
      reconnectTimerRef.current = window.setTimeout(() => {
        setupWebSocketRef.current?.()
      }, 4000)
    }
  }, [handleSocketEvent, fetchPendingApprovals])

  useEffect(() => {
    setupWebSocketRef.current = setupWebSocket
  }, [setupWebSocket])

  // Initialize Auth & Data
  useEffect(() => {
    const initAuthAndData = async () => {
      try {
        const tokenRes = await fetch(`${API_BASE}/api/auth/token`)
        if (tokenRes.ok) {
          const { token } = await tokenRes.json()
          authTokenRef.current = token
          await loadSettings(token)
          await loadWorkspaces(token)
          await loadTaskHistory(token)
          setupWebSocket(token)
        }
      } catch (err) {
        console.warn('Initial session auth failed or server offline', err)
        setWsStatus('disconnected')
      }
    }

    initAuthAndData()

    return () => {
      if (reconnectTimerRef.current) {
        window.clearTimeout(reconnectTimerRef.current)
      }
      if (wsRef.current) {
        wsRef.current.onclose = null
        wsRef.current.close()
      }
    }
  }, [loadSettings, loadWorkspaces, loadTaskHistory, setupWebSocket])

  // Auto-scroll timeline
  useEffect(() => {
    timelineEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [timeline])

  // Focus management when approval modal opens
  useEffect(() => {
    if (pendingApproval) {
      setTimeout(() => {
        approveBtnRef.current?.focus()
      }, 50)
    }
  }, [pendingApproval])

  // Keyboard shortcut listener for approvals and closing modals
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (showSettings) setShowSettings(false)
        if (showWorkspaceModal) setShowWorkspaceModal(false)
      }
      if (pendingApproval && !approvalResolving) {
        if (e.altKey && e.key.toLowerCase() === 'a') {
          resolveApproval(true)
        } else if (e.altKey && e.key.toLowerCase() === 'd') {
          resolveApproval(false)
        }
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [pendingApproval, approvalResolving, resolveApproval, showSettings, showWorkspaceModal])

  // Modal keyboard tab-trap helper
  const handleModalKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Tab') {
      const modal = approvalModalRef.current
      if (!modal) return
      const focusable = modal.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      )
      if (focusable.length === 0) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (e.shiftKey && document.activeElement === first) {
        last.focus()
        e.preventDefault()
      } else if (!e.shiftKey && document.activeElement === last) {
        first.focus()
        e.preventDefault()
      }
    }
  }

  const startTask = async () => {
    if (!goal.trim()) return

    // Clean state transition: clear previous diff, report and timeline
    setTimeline([])
    setFinalReport(null)
    setGitDiff('')
    setSelectedDiffFile(0)
    setCurrentTaskId(null)
    currentTaskIdRef.current = null
    setTaskStatus('PLANNING')
    setCurrentStep(0)
    setActiveTab('timeline')

    try {
      const res = await authFetch(`${API_BASE}/api/tasks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          goal,
          model_provider: provider,
          model_name: model,
          max_steps: maxSteps,
          workspace_path: currentWorkspace,
        }),
      })

      if (!res.ok) {
        const err = await res.json()
        alert(err.detail || 'Failed to start task')
        setTaskStatus('IDLE')
        return
      }

      const data = await res.json()
      setCurrentTaskId(data.task_id)
      currentTaskIdRef.current = data.task_id
    } catch (e: any) {
      alert(`Error starting task: ${e.message}`)
      setTaskStatus('IDLE')
    }
  }

  const cancelTask = async () => {
    if (!currentTaskId || isCancelling) return
    setIsCancelling(true)
    setCancelError(null)
    setTaskStatus('CANCELLING...')
    try {
      const res = await authFetch(`${API_BASE}/api/tasks/${currentTaskId}/cancel`, { method: 'POST' })
      if (!res.ok) {
        let errDetail = `Server returned status ${res.status}`
        try {
          const body = await res.json()
          if (body.detail) errDetail = body.detail
        } catch {
          // fallback to status code
        }
        setCancelError(`Cancellation failed: ${errDetail}`)
        setIsCancelling(false)
        loadTaskHistory()
        return
      }
      // Cancellation request accepted; retain CANCELLING... until backend emits confirmed status
      fetchDiff()
    } catch (err: any) {
      setCancelError(err?.message || 'Network error while requesting task cancellation.')
      setIsCancelling(false)
    }
  }

  const saveSettingsToServer = async () => {
    setSettingsError(null)
    try {
      const payload: any = {
        auto_approve_routine: settings.auto_approve_routine,
        auto_approve_sensitive: settings.auto_approve_sensitive,
        ollama_base_url: settings.ollama_base_url,
      }
      if (inputApiKey.trim()) {
        if (provider === 'gemini') payload.gemini_api_key = inputApiKey.trim()
        if (provider === 'openai') payload.openai_api_key = inputApiKey.trim()
        if (provider === 'anthropic') payload.anthropic_api_key = inputApiKey.trim()
      }

      const res = await authFetch(`${API_BASE}/api/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!res.ok) {
        let errMsg = 'Failed to save settings'
        try {
          const d = await res.json()
          if (d && d.detail) errMsg = d.detail
        } catch {}
        setSettingsError(errMsg)
        return
      }
      setInputApiKey('')
      setShowSettings(false)
      loadSettings()
    } catch (err: any) {
      setSettingsError(err?.message || 'Network error while saving settings.')
    }
  }

  const applyWorkspaceChange = async () => {
    if (!workspaceInput.trim()) return
    const newWs = workspaceInput.trim()
    setWorkspaceError(null)
    try {
      const res = await authFetch(`${API_BASE}/api/workspaces/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workspace_path: newWs }),
      })
      if (!res.ok) {
        let errMsg = 'Failed to approve workspace'
        try {
          const d = await res.json()
          if (d && d.detail) errMsg = d.detail
        } catch {}
        setWorkspaceError(errMsg)
        return
      }
      setCurrentWorkspace(newWs)
      setShowWorkspaceModal(false)
      fetchDiff(newWs)
      loadWorkspaces()
    } catch (err: any) {
      setWorkspaceError(err?.message || 'Network error while approving workspace.')
    }
  }

  const loadHistoricalTask = async (taskId: string) => {
    try {
      const res = await authFetch(`${API_BASE}/api/tasks/${taskId}`)
      if (!res.ok) return
      const data = await res.json()
      if (!data || !data.task) return

      const t = data.task
      setCurrentTaskId(t.id)
      setGoal(t.goal)
      setTaskStatus(t.status)
      setCurrentStep(t.current_step)
      setMaxSteps(t.max_steps)
      setFinalReport(t.final_report || null)
      if (t.workspace_path) {
        setCurrentWorkspace(t.workspace_path)
        fetchDiff(t.workspace_path)
      }

      if (data.steps && Array.isArray(data.steps)) {
        const mappedSteps: TaskStep[] = data.steps.map((s: any) => ({
          step_id: s.step_id,
          step_num: s.step_num,
          type: s.step_type as any,
          content: s.content,
          metadata: typeof s.metadata_json === 'string' ? JSON.parse(s.metadata_json) : (s.metadata_json || {}),
          timestamp: s.timestamp || Date.now(),
        }))
        setTimeline(mappedSteps)
      } else {
        setTimeline([])
      }
      setActiveTab('timeline')
    } catch (e) {
      console.error('Failed to load historical task details:', e)
    }
  }

  const isRunning = ['PLANNING', 'EXECUTING', 'PENDING_APPROVAL', 'VERIFYING'].includes(taskStatus)
  const diffFiles = parseGitDiff(gitDiff)

  return (
    <div className="app-container">
      {/* Top Header */}
      <header className="app-header glass-panel" role="banner">
        <div className="brand-badge">
          <div
            className="pulse-indicator"
            style={{ width: 10, height: 10, borderRadius: '50%', background: '#6366f1' }}
          />
          <div>
            <span className="brand-title">Antigravity Execution Agent</span>
            <span className="brand-tag" style={{ marginLeft: 8 }}>Local-First</span>
          </div>
        </div>

        <div className="header-controls">
          {/* Workspace Pill */}
          <button
            className="btn-ghost"
            style={{ padding: '6px 12px', fontSize: '0.82rem', gap: 8 }}
            onClick={() => setShowWorkspaceModal(true)}
            title="Click to switch workspace directory"
            aria-label="Current Workspace"
          >
            <FolderOpen size={16} color="#818cf8" />
            <span style={{ maxWidth: 220, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
              {currentWorkspace || 'Default Workspace'}
            </span>
          </button>

          {/* Model Selector */}
          <select
            className="select-pill"
            aria-label="Model Provider Selection"
            value={`${provider}:${model}`}
            onChange={(e) => {
              const [p, m] = e.target.value.split(':')
              setProvider(p)
              setModel(m)
            }}
          >
            <option value="gemini:gemini-2.5-flash">Google Gemini 2.5 Flash</option>
            <option value="gemini:gemini-2.5-pro">Google Gemini 2.5 Pro</option>
            <option value="openai:gpt-4o">OpenAI GPT-4o</option>
            <option value="openai:gpt-4o-mini">OpenAI GPT-4o Mini</option>
            <option value="anthropic:claude-3-7-sonnet-20250219">Anthropic Claude 3.7 Sonnet</option>
            <option value="ollama:qwen2.5-coder:latest">Ollama (Local Qwen2.5 Coder)</option>
          </select>

          {/* WebSocket Status Indicator */}
          <button
            className={`conn-badge conn-${wsStatus}`}
            onClick={() => setupWebSocket()}
            title={wsStatus === 'connected' ? 'WebSocket Connected' : 'WebSocket Disconnected - Click to reconnect'}
            aria-label="Connection Status"
          >
            {wsStatus === 'connected' ? <Wifi size={14} /> : <WifiOff size={14} />}
            <span>{wsStatus === 'connected' ? 'Live' : wsStatus === 'connecting' ? 'Connecting...' : 'Offline'}</span>
          </button>

          <button
            className="btn-ghost"
            onClick={() => setShowSettings(true)}
            title="Settings & Credentials"
            aria-label="Open Settings"
          >
            <SettingsIcon size={16} />
            Settings
          </button>
        </div>
      </header>

      {/* Urgent Persistent Approval Banner */}
      {pendingApproval && (
        <div className="urgent-approval-banner" role="alert" aria-live="assertive">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <ShieldAlert size={24} color="#fff" />
            <div>
              <strong style={{ color: '#fff', fontSize: '0.95rem' }}>
                ACTION REQUIRED: Elevated Permission Requested
              </strong>
              <div style={{ fontSize: '0.82rem', color: '#ffe4e6' }}>
                Tool <code style={{ background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: 4 }}>{pendingApproval.tool_name}</code> ({pendingApproval.permission_level}) needs authorization.
              </div>
              {approvalError && (
                <div style={{ color: '#fecdd3', fontSize: '0.78rem', marginTop: 4, fontWeight: 600 }}>
                  ⚠️ Error: {approvalError}
                </div>
              )}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="btn-danger"
              style={{ padding: '6px 14px', fontSize: '0.82rem' }}
              onClick={() => resolveApproval(false)}
              disabled={approvalResolving}
              aria-label="Deny Action"
            >
              <X size={15} /> Deny
            </button>
            <button
              className="btn-success"
              style={{ padding: '6px 14px', fontSize: '0.82rem' }}
              onClick={() => resolveApproval(true)}
              disabled={approvalResolving}
              aria-label="Approve Action"
            >
              <Check size={15} /> {approvalResolving ? 'Submitting...' : 'Approve'}
            </button>
          </div>
        </div>
      )}

      {/* Main Workspace Layout */}
      <main className="main-content">
        {/* Left Side: Task Configuration & Launch */}
        <aside className="task-panel glass-panel" aria-label="Task Composer">
          <div>
            <div className="section-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Task Assignment</span>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{goal.length} chars</span>
            </div>
            <textarea
              className="task-textarea"
              placeholder="e.g. Inspect this repository, add a new validation function in auth.py, run tests with pytest, and verify the outcome."
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
              disabled={isRunning}
              aria-label="Task Goal Input"
            />
          </div>

          <div>
            <div className="section-label">Quick Presets</div>
            <div className="preset-tags">
              <button
                className="preset-chip"
                onClick={() => setGoal('Inspect repository architecture, list key modules, and summarize technical design.')}
              >
                Audit Architecture
              </button>
              <button
                className="preset-chip"
                onClick={() => setGoal('Run test suite with run_verification tool, report JUnit XML evidence, and verify all tests pass.')}
              >
                Verify Test Suite
              </button>
              <button
                className="preset-chip"
                onClick={() => setGoal('Identify failing edge cases in unit tests, implement a surgical fix, and verify with pytest.')}
              >
                Bugfix & Verify
              </button>
              <button
                className="preset-chip"
                onClick={() => setGoal('Audit code against injection vulnerabilities and harden sensitive input boundaries.')}
              >
                Security Audit
              </button>
            </div>
          </div>

          <div>
            <div className="section-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Max Step Limit</span>
              <span>{maxSteps} steps</span>
            </div>
            <input
              type="range"
              min="5"
              max="60"
              value={maxSteps}
              onChange={(e) => setMaxSteps(Number(e.target.value))}
              disabled={isRunning}
              style={{ width: '100%', accentColor: 'var(--primary)' }}
              aria-label="Max Step Limit Slider"
            />
          </div>

          {/* Action Trigger */}
          <div style={{ marginTop: 'auto', display: 'flex', gap: 10 }}>
            {!isRunning ? (
              <button
                className="btn-primary"
                style={{ flex: 1 }}
                onClick={startTask}
                disabled={!goal.trim()}
                aria-label="Delegate Task"
              >
                <Play size={18} fill="#fff" />
                Delegate Task
              </button>
            ) : (
              <button
                className="btn-danger"
                style={{ flex: 1 }}
                onClick={cancelTask}
                disabled={isCancelling}
                aria-label="Stop Execution"
              >
                <Square size={18} fill="currentColor" />
                {isCancelling ? 'Cancelling...' : 'Stop Execution'}
              </button>
            )}
            {cancelError && (
              <div
                style={{
                  color: '#fb7185',
                  fontSize: '0.8rem',
                  marginTop: 8,
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <span>⚠️ {cancelError}</span>
              </div>
            )}
          </div>
        </aside>

        {/* Right Side: Tabbed Work View */}
        <section className="work-panel glass-panel" aria-label="Task Execution Workspace">
          {/* Tab Navigation Header */}
          <div className="tab-bar">
            <div className="tabs-group" role="tablist">
              <button
                role="tab"
                aria-selected={activeTab === 'timeline'}
                className={`tab-btn ${activeTab === 'timeline' ? 'active' : ''}`}
                onClick={() => setActiveTab('timeline')}
              >
                <Activity size={16} />
                Execution Feed
              </button>
              <button
                role="tab"
                aria-selected={activeTab === 'diff'}
                className={`tab-btn ${activeTab === 'diff' ? 'active' : ''}`}
                onClick={() => {
                  fetchDiff()
                  setActiveTab('diff')
                }}
              >
                <GitBranch size={16} />
                Git Changes {diffFiles.length > 0 ? `(${diffFiles.length})` : ''}
              </button>
              <button
                role="tab"
                aria-selected={activeTab === 'verification'}
                className={`tab-btn ${activeTab === 'verification' ? 'active' : ''}`}
                onClick={() => setActiveTab('verification')}
              >
                <CheckCircle2 size={16} />
                Verification & Report
              </button>
              <button
                role="tab"
                aria-selected={activeTab === 'history'}
                className={`tab-btn ${activeTab === 'history' ? 'active' : ''}`}
                onClick={() => {
                  loadTaskHistory()
                  setActiveTab('history')
                }}
              >
                <History size={16} />
                History
              </button>
            </div>

            {/* Current Status Pill */}
            <div className={`status-pill status-${taskStatus.toLowerCase().replace('_', '-')}`}>
              <div
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  background: 'currentColor',
                }}
              />
              {taskStatus} {isRunning ? `(Step ${currentStep}/${maxSteps})` : ''}
            </div>
          </div>

          {/* Tab 1: Live Timeline Feed */}
          {activeTab === 'timeline' && (
            <div className="timeline-content" role="log" aria-live="polite">
              {timeline.length === 0 ? (
                <div style={{ margin: 'auto', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <Sparkles size={36} style={{ marginBottom: 12, opacity: 0.4 }} />
                  <p>Assign a task to initiate the bounded execution cycle.</p>
                  <p style={{ fontSize: '0.8rem', marginTop: 4 }}>
                    The agent will plan, execute authorized tools, and verify outcomes.
                  </p>
                </div>
              ) : (
                timeline.map((item, idx) => (
                  <div key={idx} className="timeline-item">
                    <div className="timeline-header">
                      <span className="timeline-type">
                        {item.type === 'thought' && <Sparkles size={14} />}
                        {item.type === 'tool_call' && <Terminal size={14} />}
                        {item.type === 'tool_result' && <Layers size={14} />}
                        {item.type === 'error' && <AlertTriangle size={14} color="#f43f5e" />}
                        {item.title}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{item.timestamp}</span>
                    </div>

                    <div className="timeline-body">
                      {item.type === 'tool_result' || item.type === 'tool_call' ? (
                        <pre className="code-output">{item.content}</pre>
                      ) : (
                        item.content
                      )}
                    </div>
                  </div>
                ))
              )}
              <div ref={timelineEndRef} />
            </div>
          )}

          {/* Tab 2: Enhanced Multi-File Git Diff Viewer */}
          {activeTab === 'diff' && (
            <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 20px', borderBottom: '1px solid var(--border-color)' }}>
                <span style={{ fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Code2 size={16} color="#818cf8" /> Working Tree Unified Diffs ({diffFiles.length} file{diffFiles.length === 1 ? '' : 's'})
                </span>
                <button className="btn-ghost" style={{ padding: '4px 10px', fontSize: '0.78rem' }} onClick={() => fetchDiff()}>
                  <RefreshCw size={14} /> Refresh Diff
                </button>
              </div>

              {diffFiles.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', padding: '40px 20px', textAlign: 'center', margin: 'auto' }}>
                  <GitBranch size={32} style={{ opacity: 0.3, marginBottom: 8 }} />
                  <p>No uncommitted changes in current repository working tree.</p>
                </div>
              ) : (
                <div className="diff-view-layout">
                  {/* Diff File List Sidebar */}
                  <div className="diff-sidebar">
                    <div className="section-label">Modified Files</div>
                    {diffFiles.map((f, idx) => (
                      <div
                        key={idx}
                        className={`diff-file-item ${selectedDiffFile === idx ? 'selected' : ''}`}
                        onClick={() => setSelectedDiffFile(idx)}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                          {f.isDeleted && <span className="diff-badge-del">DEL</span>}
                          {f.isNew && <span className="diff-badge-new">NEW</span>}
                          {f.isRenamed && <span className="diff-badge-ren">REN</span>}
                          <span style={{ textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }} title={f.filename}>
                            {f.filename}
                          </span>
                        </div>
                        <div className="diff-file-stats">
                          {f.additions > 0 && <span className="stat-add">+{f.additions}</span>}
                          {f.deletions > 0 && <span className="stat-del">-{f.deletions}</span>}
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Diff Code Container */}
                  <div className="diff-container">
                    {diffFiles[selectedDiffFile] ? (
                      <div>
                        <div className="diff-file-header">
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span>{diffFiles[selectedDiffFile].filename}</span>
                            {diffFiles[selectedDiffFile].isDeleted && <span className="diff-badge-del">DELETED</span>}
                            {diffFiles[selectedDiffFile].isNew && <span className="diff-badge-new">NEW FILE</span>}
                            {diffFiles[selectedDiffFile].isRenamed && <span className="diff-badge-ren">RENAMED</span>}
                          </div>
                          <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                            +{diffFiles[selectedDiffFile].additions} / -{diffFiles[selectedDiffFile].deletions} lines
                          </span>
                        </div>
                        {diffFiles[selectedDiffFile].lines.map((l, lIdx) => {
                          let cls = 'diff-line-normal'
                          if (l.type === 'add') cls = 'diff-line-add'
                          if (l.type === 'delete') cls = 'diff-line-remove'
                          if (l.type === 'chunk') cls = 'diff-line-chunk'
                          return (
                            <span key={lIdx} className={cls}>
                              {l.text}
                            </span>
                          )
                        })}
                      </div>
                    ) : (
                      <div style={{ color: 'var(--text-muted)' }}>Select a file to inspect diff.</div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab 3: Verification Evidence & Final Report */}
          {activeTab === 'verification' && (
            <div className="timeline-content">
              {!finalReport ? (
                <div style={{ margin: 'auto', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <ShieldAlert size={36} style={{ marginBottom: 12, opacity: 0.4 }} />
                  <p>No verification evidence recorded for the active run yet.</p>
                  <p style={{ fontSize: '0.8rem', marginTop: 4 }}>
                    Automated tests, builds, and cryptographic verification checks will be presented here.
                  </p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  {/* Report Header Card */}
                  <div
                    className="glass-panel"
                    style={{
                      padding: 16,
                      borderLeft: `4px solid ${finalReport.status === 'COMPLETED' ? '#10b981' : '#f59e0b'}`,
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <h3 style={{ fontSize: '1.1rem' }}>Final Task Outcome</h3>
                      <span className={`status-pill status-${finalReport.status.toLowerCase().replace('_', '-')}`}>
                        {finalReport.status}
                      </span>
                    </div>
                    <p style={{ color: 'var(--text-secondary)', marginTop: 6, fontSize: '0.9rem' }}>
                      Goal: {finalReport.goal}
                    </p>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 10, fontSize: '0.8rem', color: '#818cf8' }}>
                      <ShieldCheck size={16} /> Cryptographically Signed Verification Record (RFC 8785 canonical serialization)
                    </div>
                  </div>

                  {/* Executed Checks */}
                  <div>
                    <h4 className="section-label">Automated Verification Checks</h4>
                    {finalReport.executed_verification_checks.length === 0 ? (
                      <div className="timeline-item" style={{ color: 'var(--accent-amber)' }}>
                        <AlertTriangle size={16} /> No automated test commands were executed.
                      </div>
                    ) : (
                      finalReport.executed_verification_checks.map((check, idx) => (
                        <div key={idx} className="timeline-item" style={{ marginBottom: 8 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontWeight: 600 }}>{check.check_name} ({check.check_type})</span>
                            <span
                              style={{
                                color: check.success ? '#34d399' : '#fb7185',
                                fontWeight: 600,
                                fontSize: '0.8rem',
                              }}
                            >
                              Exit Code: {check.exit_code} | {check.success ? 'PASSED' : 'FAILED'}
                            </span>
                          </div>
                          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                            Command: <code>{check.command}</code>
                          </div>
                          <pre className="code-output" style={{ maxHeight: 120 }}>
                            {check.output || check.evidence_summary}
                          </pre>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Modified Files */}
                  <div>
                    <h4 className="section-label">Modified / Created Files</h4>
                    {finalReport.files_created_or_modified.length === 0 ? (
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No files were created or updated.</div>
                    ) : (
                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {finalReport.files_created_or_modified.map((f, idx) => (
                          <span
                            key={idx}
                            style={{
                              background: 'rgba(99, 102, 241, 0.1)',
                              border: '1px solid rgba(99, 102, 241, 0.3)',
                              padding: '4px 8px',
                              borderRadius: 'var(--radius-sm)',
                              fontSize: '0.8rem',
                              display: 'flex',
                              alignItems: 'center',
                              gap: 6,
                            }}
                          >
                            <FileCode size={14} color="#818cf8" /> {f}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Unresolved Risks & Limitations */}
                  {finalReport.unresolved_risks_or_limitations.length > 0 && (
                    <div>
                      <h4 className="section-label">Unresolved Limitations & Caveats</h4>
                      <ul style={{ paddingLeft: 20, color: 'var(--accent-amber)', fontSize: '0.85rem' }}>
                        {finalReport.unresolved_risks_or_limitations.map((note, idx) => (
                          <li key={idx}>{note}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Tab 4: History */}
          {activeTab === 'history' && (
            <div className="timeline-content">
              <h4 className="section-label">Recent Completed & Interrupted Tasks</h4>
              {historyTasks.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', textAlign: 'center', margin: 'auto' }}>
                  No previous tasks in local database.
                </div>
              ) : (
                historyTasks.map((t, idx) => (
                  <div
                    key={idx}
                    className="timeline-item"
                    style={{ cursor: 'pointer', transition: 'background 0.15s ease' }}
                    onClick={() => loadHistoricalTask(t.id)}
                    role="button"
                    tabIndex={0}
                    aria-label={`Open historical task: ${t.goal}`}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        loadHistoricalTask(t.id)
                      }
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 600 }}>{t.goal}</span>
                      <span className={`status-pill status-${t.status.toLowerCase().replace('_', '-')}`}>
                        {t.status}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', gap: 14 }}>
                      <span>Model: {t.model_name}</span>
                      <span>Steps: {t.current_step}/{t.max_steps}</span>
                      <span>Workspace: {t.workspace_path}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </section>
      </main>

      {/* Human-in-the-Loop Approval Modal */}
      {pendingApproval && (
        <div
          className="modal-overlay"
          role="dialog"
          aria-modal="true"
          aria-labelledby="approval-title"
          onKeyDown={handleModalKeyDown}
        >
          <div className="modal-dialog" ref={approvalModalRef}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#fb7185' }}>
              <ShieldAlert size={28} />
              <h3 id="approval-title" style={{ fontSize: '1.2rem', color: '#fff' }}>Authorization Required</h3>
            </div>

            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              The agent has requested to execute a sensitive action requiring explicit human permission:
            </p>

            {approvalError && (
              <div className="approval-error-msg" role="alert">
                <AlertTriangle size={18} />
                <span>{approvalError}</span>
              </div>
            )}

            <div style={{ background: '#090d16', padding: 14, borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: 6 }}>
                TOOL: <strong style={{ color: '#818cf8' }}>{pendingApproval.tool_name}</strong> | PERMISSION LEVEL:{' '}
                <strong style={{ color: '#fbbf24' }}>{pendingApproval.permission_level}</strong>
              </div>
              <div style={{ fontSize: '0.85rem', marginBottom: 10, color: '#f1f5f9' }}>{pendingApproval.reason}</div>
              
              <div className="section-label">Arguments & Payload</div>
              <pre className="code-output">{JSON.stringify(pendingApproval.arguments, null, 2)}</pre>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 10 }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Hotkeys: <kbd>Alt+A</kbd> Approve | <kbd>Alt+D</kbd> Deny
              </span>
              <div style={{ display: 'flex', gap: 12 }}>
                <button
                  className="btn-danger"
                  onClick={() => resolveApproval(false)}
                  disabled={approvalResolving}
                  aria-label="Deny Action"
                >
                  Deny Action
                </button>
                <button
                  ref={approveBtnRef}
                  className="btn-primary"
                  onClick={() => resolveApproval(true)}
                  disabled={approvalResolving}
                  aria-label="Approve Action"
                >
                  {approvalResolving ? 'Submitting...' : 'Approve Action'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Workspace Switcher Modal */}
      {showWorkspaceModal && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="workspace-modal-title">
          <div className="modal-dialog">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 id="workspace-modal-title" style={{ fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: 8 }}>
                <FolderOpen size={20} color="#818cf8" /> Workspace Configuration
              </h3>
              <button className="btn-ghost" onClick={() => setShowWorkspaceModal(false)} aria-label="Close">
                ✕
              </button>
            </div>

            <div>
              <div className="section-label">Active Workspace Root Path</div>
              <input
                type="text"
                className="select-pill"
                style={{ width: '100%', boxSizing: 'border-box' }}
                placeholder="Enter absolute directory path (e.g. C:\projects\myapp or /home/user/repo)"
                value={workspaceInput}
                onChange={(e) => setWorkspaceInput(e.target.value)}
                aria-label="Workspace Root Directory Path"
              />
              {workspaceError && (
                <div style={{ color: '#fb7185', fontSize: '0.8rem', marginTop: 6, fontWeight: 600 }}>
                  ⚠️ {workspaceError}
                </div>
              )}
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginTop: 6 }}>
                All tool execution, file reading, code editing, and Git tracking remain strictly confined to this directory.
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 12 }}>
              <button className="btn-ghost" onClick={() => setShowWorkspaceModal(false)}>
                Cancel
              </button>
              <button className="btn-primary" onClick={applyWorkspaceChange}>
                Set Active Workspace
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Settings Modal */}
      {showSettings && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="settings-modal-title">
          <div className="modal-dialog">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 id="settings-modal-title" style={{ fontSize: '1.2rem' }}>Settings & Credentials</h3>
              <button className="btn-ghost" onClick={() => setShowSettings(false)} aria-label="Close">
                ✕
              </button>
            </div>

            {settingsError && (
              <div style={{ color: '#fb7185', fontSize: '0.8rem', marginBottom: 10, fontWeight: 600 }}>
                ⚠️ {settingsError}
              </div>
            )}

            {/* API Keys Configuration */}
            <div>
              <div className="section-label">Provider API Key ({provider})</div>
              <input
                type="password"
                className="select-pill"
                style={{ width: '100%', marginBottom: 6, boxSizing: 'border-box' }}
                placeholder={
                  provider === 'gemini'
                    ? settings.gemini_api_key_set ? '••••••••  (Saved)' : 'Enter Gemini API key'
                    : provider === 'openai'
                    ? settings.openai_api_key_set ? '••••••••  (Saved)' : 'Enter OpenAI API key'
                    : provider === 'anthropic'
                    ? settings.anthropic_api_key_set ? '••••••••  (Saved)' : 'Enter Anthropic API key'
                    : 'Ollama requires no key'
                }
                value={inputApiKey}
                onChange={(e) => setInputApiKey(e.target.value)}
                aria-label="Provider API Key"
              />
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Credentials are encrypted using OS-native DPAPI / protected vault and redacted from logs.
              </span>
            </div>

            {/* Ollama URL */}
            <div>
              <div className="section-label">Ollama Host URL</div>
              <input
                type="text"
                className="select-pill"
                style={{ width: '100%', boxSizing: 'border-box' }}
                value={settings.ollama_base_url}
                onChange={(e) => setSettings({ ...settings, ollama_base_url: e.target.value })}
                aria-label="Ollama Host URL"
              />
            </div>

            {/* Permissions Policy Toggles */}
            <div>
              <div className="section-label">Safety & Permission Policy</div>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem', marginBottom: 8, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={settings.auto_approve_routine}
                  onChange={(e) => setSettings({ ...settings, auto_approve_routine: e.target.checked })}
                />
                Auto-approve routine file edits within workspace
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={settings.auto_approve_sensitive}
                  onChange={(e) => setSettings({ ...settings, auto_approve_sensitive: e.target.checked })}
                />
                Auto-approve shell commands (tests, builds) without prompting
              </label>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 12 }}>
              <button className="btn-ghost" onClick={() => setShowSettings(false)}>
                Cancel
              </button>
              <button className="btn-primary" onClick={saveSettingsToServer}>
                Save Configuration
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
