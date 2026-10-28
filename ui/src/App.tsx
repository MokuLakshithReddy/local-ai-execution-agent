import { useState, useEffect, useRef } from 'react'
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
  FolderOpen
} from 'lucide-react'
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
  const [taskStatus, setTaskStatus] = useState<string>('IDLE')
  const [currentStep, setCurrentStep] = useState<number>(0)
  const [timeline, setTimeline] = useState<TaskStep[]>([])
  const [gitDiff, setGitDiff] = useState<string>('')
  const [finalReport, setFinalReport] = useState<TaskReport | null>(null)

  const [pendingApproval, setPendingApproval] = useState<ApprovalRequest | null>(null)
  const [showSettings, setShowSettings] = useState(false)
  const [historyTasks, setHistoryTasks] = useState<any[]>([])

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

  const authFetch = async (url: string, options: RequestInit = {}) => {
    const headers = new Headers(options.headers || {})
    if (authTokenRef.current) {
      headers.set('X-Agent-Auth-Token', authTokenRef.current)
    }
    return fetch(url, { ...options, headers })
  }

  // Initialize
  useEffect(() => {
    const initAuthAndData = async () => {
      try {
        const tokenRes = await fetch('http://localhost:8000/api/auth/token')
        if (tokenRes.ok) {
          const { token } = await tokenRes.json()
          authTokenRef.current = token
          loadSettings(token)
          loadWorkspaces(token)
          loadTaskHistory(token)
          setupWebSocket(token)
        }
      } catch (err) {
        console.warn('Initial session auth failed or server offline', err)
      }
    }

    initAuthAndData()

    return () => {
      if (wsRef.current) wsRef.current.close()
    }
  }, [])

  // Auto-scroll timeline
  useEffect(() => {
    timelineEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [timeline])

  const setupWebSocket = (token?: string) => {
    const tok = token || authTokenRef.current
    const wsUrl = `ws://${window.location.hostname || 'localhost'}:8000/ws?token=${encodeURIComponent(tok)}`
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        handleSocketEvent(msg.type, msg.data)
      } catch (err) {
        console.error('WebSocket parse error:', err)
      }
    }

    ws.onclose = () => {
      setTimeout(() => setupWebSocket(), 3000)
    }
  }

  const handleSocketEvent = (type: string, data: any) => {
    const now = new Date().toLocaleTimeString()

    if (type === 'task_status') {
      setTaskStatus(data.status)
    } else if (type === 'step_start') {
      setCurrentStep(data.step)
      setTimeline((prev) => [
        ...prev,
        {
          step: data.step,
          type: 'status',
          title: `Step ${data.step} / ${data.max_steps}`,
          content: 'Reasoning and inspecting workspace...',
          timestamp: now,
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
          timestamp: now,
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
          timestamp: now,
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
          timestamp: now,
        },
      ])
      // Refresh diff whenever files might have changed
      fetchDiff()
    } else if (type === 'approval_required') {
      setTaskStatus('PENDING_APPROVAL')
      setPendingApproval(data.approval)
    } else if (type === 'approval_resolved') {
      setPendingApproval(null)
    } else if (type === 'task_completed') {
      setTaskStatus(data.status)
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
          timestamp: now,
        },
      ])
    }
  }

  const loadSettings = async (tok?: string) => {
    try {
      const headers: any = {}
      if (tok || authTokenRef.current) headers['X-Agent-Auth-Token'] = tok || authTokenRef.current
      const res = await fetch('http://localhost:8000/api/settings', { headers })
      if (res.ok) {
        const data = await res.json()
        setSettings(data)
        if (data.current_workspace) setCurrentWorkspace(data.current_workspace)
      }
    } catch (e) {
      console.warn('API offline or loading', e)
    }
  }

  const loadWorkspaces = async (tok?: string) => {
    try {
      const headers: any = {}
      if (tok || authTokenRef.current) headers['X-Agent-Auth-Token'] = tok || authTokenRef.current
      const res = await fetch('http://localhost:8000/api/workspaces', { headers })
      if (res.ok) {
        const data = await res.json()
        if (data.current) setCurrentWorkspace(data.current)
      }
    } catch (e) {}
  }

  const loadTaskHistory = async (tok?: string) => {
    try {
      const headers: any = {}
      if (tok || authTokenRef.current) headers['X-Agent-Auth-Token'] = tok || authTokenRef.current
      const res = await fetch('http://localhost:8000/api/tasks', { headers })
      if (res.ok) {
        const data = await res.json()
        setHistoryTasks(data.tasks || [])
      }
    } catch (e) {}
  }

  const fetchDiff = async () => {
    try {
      const res = await authFetch('http://localhost:8000/api/diff')
      if (res.ok) {
        const data = await res.json()
        setGitDiff(data.diff || '')
      }
    } catch (e) {}
  }

  const startTask = async () => {
    if (!goal.trim()) return

    setTimeline([])
    setFinalReport(null)
    setTaskStatus('PLANNING')
    setCurrentStep(0)
    setActiveTab('timeline')

    try {
      const res = await authFetch('http://localhost:8000/api/tasks', {
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
    } catch (e: any) {
      alert(`Error starting task: ${e.message}`)
      setTaskStatus('IDLE')
    }
  }

  const cancelTask = async () => {
    if (!currentTaskId) return
    try {
      await authFetch(`http://localhost:8000/api/tasks/${currentTaskId}/cancel`, { method: 'POST' })
      setTaskStatus('CANCELLED')
    } catch (e) {}
  }

  const resolveApproval = async (approved: boolean) => {
    if (!pendingApproval) return
    try {
      await authFetch(`http://localhost:8000/api/approvals/${pendingApproval.approval_id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approved }),
      })
      setPendingApproval(null)
    } catch (e) {}
  }

  const saveSettingsToServer = async () => {
    try {
      const payload: any = {
        auto_approve_routine: settings.auto_approve_routine,
        auto_approve_sensitive: settings.auto_approve_sensitive,
        ollama_base_url: settings.ollama_base_url,
        current_workspace: currentWorkspace,
      }
      if (inputApiKey.trim()) {
        if (provider === 'gemini') payload.gemini_api_key = inputApiKey.trim()
        if (provider === 'openai') payload.openai_api_key = inputApiKey.trim()
        if (provider === 'anthropic') payload.anthropic_api_key = inputApiKey.trim()
      }

      await authFetch('http://localhost:8000/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      setInputApiKey('')
      setShowSettings(false)
      loadSettings()
    } catch (e) {}
  }

  const isRunning = ['PLANNING', 'EXECUTING', 'PENDING_APPROVAL', 'VERIFYING'].includes(taskStatus)

  return (
    <div className="app-container">
      {/* Top Header */}
      <header className="app-header glass-panel">
        <div className="brand-badge">
          <div className="pulse-indicator" style={{ width: 10, height: 10, borderRadius: '50%', background: '#6366f1' }}></div>
          <div>
            <span className="brand-title">Antigravity Execution Agent</span>
            <span className="brand-tag" style={{ marginLeft: 8 }}>Local-First</span>
          </div>
        </div>

        <div className="header-controls">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            <FolderOpen size={16} />
            <span style={{ maxWidth: 260, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }} title={currentWorkspace}>
              {currentWorkspace || 'Default Workspace'}
            </span>
          </div>

          {/* Model Selector */}
          <select
            className="select-pill"
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

          <button className="btn-ghost" onClick={() => setShowSettings(true)} title="Settings & Credentials">
            <SettingsIcon size={16} />
            Settings
          </button>
        </div>
      </header>

      {/* Main Workspace Layout */}
      <main className="main-content">
        {/* Left Side: Task Configuration & Launch */}
        <aside className="task-panel glass-panel">
          <div>
            <div className="section-label">Task Assignment</div>
            <textarea
              className="task-textarea"
              placeholder="e.g. Inspect this repository, add a new validation function in auth.py, run tests with pytest, and verify the outcome."
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
              disabled={isRunning}
            />
          </div>

          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button
              className="btn-ghost"
              style={{ fontSize: '0.75rem', padding: '4px 8px' }}
              onClick={() => setGoal('Inspect the workspace structure, list key directories, and report codebase summary.')}
            >
              Inspect Architecture
            </button>
            <button
              className="btn-ghost"
              style={{ fontSize: '0.75rem', padding: '4px 8px' }}
              onClick={() => setGoal('Add a test case in tests/ for input sanitization, execute pytest via run_verification, and report evidence.')}
            >
              Add Test & Verify
            </button>
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
            />
          </div>

          {/* Action Trigger */}
          <div style={{ marginTop: 'auto', display: 'flex', gap: 10 }}>
            {!isRunning ? (
              <button className="btn-primary" style={{ flex: 1 }} onClick={startTask} disabled={!goal.trim()}>
                <Play size={18} fill="#fff" />
                Delegate Task
              </button>
            ) : (
              <button className="btn-danger" style={{ flex: 1 }} onClick={cancelTask}>
                <Square size={18} fill="currentColor" />
                Stop Execution
              </button>
            )}
          </div>
        </aside>

        {/* Right Side: Tabbed Work View */}
        <section className="work-panel glass-panel">
          {/* Tab Navigation Header */}
          <div className="tab-bar">
            <div className="tabs-group">
              <button
                className={`tab-btn ${activeTab === 'timeline' ? 'active' : ''}`}
                onClick={() => setActiveTab('timeline')}
              >
                <Activity size={16} />
                Execution Feed
              </button>
              <button
                className={`tab-btn ${activeTab === 'diff' ? 'active' : ''}`}
                onClick={() => {
                  fetchDiff()
                  setActiveTab('diff')
                }}
              >
                <GitBranch size={16} />
                Git Changes
              </button>
              <button
                className={`tab-btn ${activeTab === 'verification' ? 'active' : ''}`}
                onClick={() => setActiveTab('verification')}
              >
                <CheckCircle2 size={16} />
                Verification & Report
              </button>
              <button
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
            <div className="timeline-content">
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

          {/* Tab 2: Git Diff Viewer */}
          {activeTab === 'diff' && (
            <div className="diff-container">
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
                <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Repository Working Tree Changes</span>
                <button className="btn-ghost" style={{ padding: '2px 8px' }} onClick={fetchDiff}>
                  <RefreshCw size={14} /> Refresh Diff
                </button>
              </div>

              {!gitDiff ? (
                <div style={{ color: 'var(--text-muted)', padding: '20px 0' }}>
                  No uncommitted changes in current repository working tree.
                </div>
              ) : (
                gitDiff.split('\n').map((line, idx) => {
                  let cls = 'diff-line-normal'
                  if (line.startsWith('+') && !line.startsWith('+++')) cls = 'diff-line-add'
                  if (line.startsWith('-') && !line.startsWith('---')) cls = 'diff-line-remove'
                  return (
                    <span key={idx} className={cls}>
                      {line}
                    </span>
                  )
                })
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
                    Automated tests, builds, and verification checks will be presented here.
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
                  <div key={idx} className="timeline-item" style={{ cursor: 'pointer' }}>
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
        <div className="modal-overlay">
          <div className="modal-dialog">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: '#fb7185' }}>
              <ShieldAlert size={28} />
              <h3 style={{ fontSize: '1.2rem', color: '#fff' }}>Authorization Required</h3>
            </div>

            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              The agent has requested to execute a sensitive action requiring explicit permission:
            </p>

            <div style={{ background: '#090d16', padding: 14, borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)' }}>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: 4 }}>
                TOOL: <strong style={{ color: '#818cf8' }}>{pendingApproval.tool_name}</strong> | LEVEL:{' '}
                <strong style={{ color: '#fbbf24' }}>{pendingApproval.permission_level}</strong>
              </div>
              <div style={{ fontSize: '0.85rem', marginBottom: 8 }}>{pendingApproval.reason}</div>
              <pre className="code-output">{JSON.stringify(pendingApproval.arguments, null, 2)}</pre>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12, marginTop: 10 }}>
              <button className="btn-danger" onClick={() => resolveApproval(false)}>
                Deny Action
              </button>
              <button className="btn-primary" onClick={() => resolveApproval(true)}>
                Approve Action
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Settings Modal */}
      {showSettings && (
        <div className="modal-overlay">
          <div className="modal-dialog" style={{ width: 600 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ fontSize: '1.2rem' }}>Settings & Credentials</h3>
              <button className="btn-ghost" onClick={() => setShowSettings(false)}>
                ✕
              </button>
            </div>

            {/* API Keys Configuration */}
            <div>
              <div className="section-label">Provider API Key ({provider})</div>
              <input
                type="password"
                className="select-pill"
                style={{ width: '100%', marginBottom: 6 }}
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
              />
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Credentials are saved to local SQLite database and redacted from logs and tool contexts.
              </span>
            </div>

            {/* Ollama URL */}
            <div>
              <div className="section-label">Ollama Host URL</div>
              <input
                type="text"
                className="select-pill"
                style={{ width: '100%' }}
                value={settings.ollama_base_url}
                onChange={(e) => setSettings({ ...settings, ollama_base_url: e.target.value })}
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
