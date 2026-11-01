import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import App from './App'

// Mock WebSocket implementation for interactive browser testing
class MockWebSocket {
  url: string
  onopen: (() => void) | null = null
  onmessage: ((ev: { data: string }) => void) | null = null
  onerror: ((err: any) => void) | null = null
  onclose: (() => void) | null = null
  readyState = 1 // OPEN
  static instances: MockWebSocket[] = []

  constructor(url: string) {
    this.url = url
    MockWebSocket.instances.push(this)
    setTimeout(() => {
      if (this.onopen) this.onopen()
    }, 10)
  }

  send(_data: string) {}
  close() {
    this.readyState = 3 // CLOSED
    if (this.onclose) this.onclose()
  }

  emitMessage(type: string, data: any) {
    if (this.onmessage) {
      this.onmessage({ data: JSON.stringify({ type, data }) })
    }
  }
}

describe('Dashboard Interactive Browser-Level Tests', () => {
  let originalFetch: any
  let originalWebSocket: any
  let fetchMock: any

  beforeEach(() => {
    window.HTMLElement.prototype.scrollIntoView = vi.fn()
    MockWebSocket.instances = []
    originalWebSocket = globalThis.WebSocket
    globalThis.WebSocket = MockWebSocket as any

    originalFetch = globalThis.fetch
    fetchMock = vi.fn(async (url: string, options?: any) => {
      const urlStr = String(url)
      const method = options?.method || 'GET'

      if (urlStr.includes('/api/auth/token')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ token: 'mock-session-token-123' }),
        }
      }
      if (urlStr.includes('/api/settings')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            default_provider: 'anthropic',
            default_model: 'claude-3-5-sonnet-20241022',
            current_workspace: '/mock/workspace',
            auto_approve_routine: true,
            auto_approve_sensitive: false,
            require_approval_destructive: true,
          }),
        }
      }
      if (urlStr.includes('/api/workspaces') && method === 'GET') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            workspaces: ['/mock/workspace', '/mock/workspace-2'],
            current_workspace: '/mock/workspace',
          }),
        }
      }
      if (urlStr.includes('/api/approvals/pending')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            approvals: [
              {
                approval_id: 'appr-abc-123',
                task_id: 'task-new-999',
                tool_name: 'run_command',
                arguments: { command: 'git commit --am --no-edit' },
                permission_level: 'DESTRUCTIVE_OPERATION',
                reason: 'Git commit history-rewriting operation requires human authorization.',
              },
            ],
          }),
        }
      }
      if (urlStr.includes('/api/tasks') && method === 'GET') {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            tasks: [
              {
                task_id: 'task-hist-1',
                goal: 'Existing completed task',
                status: 'COMPLETED',
                created_at: '2026-11-01T10:00:00Z',
              },
            ],
          }),
        }
      }
      if (urlStr.includes('/api/tasks') && method === 'POST') {
        const body = JSON.parse(options.body)
        return {
          ok: true,
          status: 200,
          json: async () => ({
            task_id: 'task-new-999',
            goal: body.goal,
            status: 'PLANNING',
          }),
        }
      }
      if (urlStr.includes('/cancel') && method === 'POST') {
        return {
          ok: true,
          status: 200,
          json: async () => ({ status: 'CANCELLING' }),
        }
      }
      if (urlStr.includes('/api/approvals/') && method === 'POST') {
        return {
          ok: true,
          status: 200,
          json: async () => ({ status: 'RESOLVED' }),
        }
      }
      if (urlStr.includes('/api/tasks/') && urlStr.includes('/diff')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ diff: '' }),
        }
      }

      return {
        ok: true,
        status: 200,
        json: async () => ({}),
      }
    })
    globalThis.fetch = fetchMock
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
    globalThis.WebSocket = originalWebSocket
    vi.restoreAllMocks()
  })

  it('1. Task creation: creates and submits a new task', async () => {
    render(<App />)

    // Wait for initial load
    await waitFor(() => {
      expect(screen.getByLabelText('Task Goal Input')).toBeDefined()
    })

    const goalInput = screen.getByLabelText('Task Goal Input') as HTMLTextAreaElement
    const startButton = screen.getByLabelText('Delegate Task')

    // Type goal
    fireEvent.change(goalInput, {
      target: { value: 'Fix authentication bug in security module' },
    })
    expect(goalInput.value).toBe('Fix authentication bug in security module')

    // Submit task
    fireEvent.click(startButton)

    await waitFor(() => {
      const taskCall = fetchMock.mock.calls.find(
        (call: any[]) => String(call[0]).includes('/api/tasks') && call[1]?.method === 'POST'
      )
      expect(taskCall).toBeDefined()
      const payload = JSON.parse(taskCall[1].body)
      expect(payload.goal).toBe('Fix authentication bug in security module')
    })
  })

  it('2. Approval flow: renders elevated permission banner and resolves approval', async () => {
    render(<App />)

    // Wait until live WebSocket connection is established
    await waitFor(() => {
      expect(screen.getByText('Live')).toBeDefined()
    })

    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]

    // Simulate backend requesting human approval for destructive operation
    act(() => {
      ws.emitMessage('approval_required', {
        approval: {
          approval_id: 'appr-abc-123',
          task_id: 'task-new-999',
          tool_name: 'run_command',
          arguments: { command: 'git commit --am --no-edit' },
          permission_level: 'DESTRUCTIVE_OPERATION',
          reason: 'Git commit history-rewriting operation requires human authorization.',
        },
      })
    })

    // Verify approval banner is rendered
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeDefined()
      expect(screen.getByText(/Elevated Permission Requested/i)).toBeDefined()
      expect(screen.getAllByText('run_command').length).toBeGreaterThan(0)
    })

    // Click Approve
    const approveBtn = screen.getAllByLabelText('Approve Action')[0]
    fireEvent.click(approveBtn)

    await waitFor(() => {
      const approvalCall = fetchMock.mock.calls.find(
        (call: any[]) =>
          String(call[0]).includes('/api/approvals/appr-abc-123') &&
          call[1]?.method === 'POST' &&
          call[1]?.body?.includes('"approved":true')
      )
      expect(approvalCall).toBeDefined()
    })
  })

  it('3. Execution logs: displays thoughts and tool execution events', async () => {
    render(<App />)

    // Wait until live WebSocket connection is established
    await waitFor(() => {
      expect(screen.getByText('Live')).toBeDefined()
    })

    const ws = MockWebSocket.instances[MockWebSocket.instances.length - 1]

    // Deliver task step events
    act(() => {
      ws.emitMessage('agent_thought', {
        step: 1,
        thought: 'Analyzing repository structure for security fixes.',
      })
      ws.emitMessage('tool_executing', {
        tool: 'run_command',
        arguments: { command: 'pytest tests/test_core_and_tools.py' },
      })
      ws.emitMessage('tool_result', {
        tool: 'run_command',
        output: '142 passed in 1.25s',
        success: true,
      })
    })

    await waitFor(() => {
      expect(screen.getByText('Analyzing repository structure for security fixes.')).toBeDefined()
      expect(screen.getByText(/"command": "pytest tests\/test_core_and_tools\.py"/)).toBeDefined()
      expect(screen.getByText('142 passed in 1.25s')).toBeDefined()
    })
  })

  it('4. Cancellation flow: stops active execution on user request', async () => {
    render(<App />)

    await waitFor(() => {
      expect(screen.getByLabelText('Task Goal Input')).toBeDefined()
    })

    // Start a task
    const goalInput = screen.getByLabelText('Task Goal Input')
    const startButton = screen.getByLabelText('Delegate Task')
    fireEvent.change(goalInput, { target: { value: 'Long running task to cancel' } })
    fireEvent.click(startButton)

    await waitFor(() => {
      expect(screen.getByLabelText('Stop Execution')).toBeDefined()
    })

    const stopButton = screen.getByLabelText('Stop Execution')
    fireEvent.click(stopButton)

    await waitFor(() => {
      const cancelCall = fetchMock.mock.calls.find(
        (call: any[]) =>
          String(call[0]).includes('/api/tasks/task-new-999/cancel') &&
          call[1]?.method === 'POST'
      )
      expect(cancelCall).toBeDefined()
    })
  })

  it('5. Error handling: displays user-facing error message on task start failure', async () => {
    // Override fetch to return 400 Bad Request
    fetchMock.mockImplementation(async (url: string, options?: any) => {
      const urlStr = String(url)
      if (urlStr.includes('/api/auth/token')) {
        return { ok: true, status: 200, json: async () => ({ token: 'mock-token' }) }
      }
      if (urlStr.includes('/api/settings')) {
        return { ok: true, status: 200, json: async () => ({ current_workspace: '/mock' }) }
      }
      if (urlStr.includes('/api/tasks') && options?.method === 'POST') {
        return {
          ok: false,
          status: 400,
          json: async () => ({ detail: 'Workspace path does not exist or is unauthorized' }),
        }
      }
      return { ok: true, status: 200, json: async () => ({}) }
    })

    // Spy on window.alert
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {})

    render(<App />)

    await waitFor(() => {
      expect(screen.getByLabelText('Task Goal Input')).toBeDefined()
    })

    const goalInput = screen.getByLabelText('Task Goal Input')
    const startButton = screen.getByLabelText('Delegate Task')

    fireEvent.change(goalInput, { target: { value: 'Test invalid workspace failure' } })
    fireEvent.click(startButton)

    await waitFor(() => {
      expect(alertSpy).toHaveBeenCalledWith('Workspace path does not exist or is unauthorized')
    })

    alertSpy.mockRestore()
  })
})
