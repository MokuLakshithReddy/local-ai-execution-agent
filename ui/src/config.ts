/**
 * Centralized API & WebSocket Endpoint Configuration.
 * Respects VITE_API_BASE_URL and VITE_WS_BASE_URL if configured,
 * otherwise dynamically determines endpoints from window location.
 */

export const getApiBaseUrl = (): string => {
  if (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL.replace(/\/+$/, '')
  }
  if (typeof window !== 'undefined' && window.location.port === '5173') {
    return `http://${window.location.hostname || 'localhost'}:8000`
  }
  return typeof window !== 'undefined' && window.location.origin ? window.location.origin : 'http://localhost:8000'
}

export const getWsBaseUrl = (): string => {
  if (typeof import.meta !== 'undefined' && import.meta.env?.VITE_WS_BASE_URL) {
    return import.meta.env.VITE_WS_BASE_URL.replace(/\/+$/, '')
  }
  const apiBase = getApiBaseUrl()
  if (apiBase.startsWith('https://')) {
    return apiBase.replace('https://', 'wss://')
  }
  return apiBase.replace('http://', 'ws://')
}

export const API_BASE = getApiBaseUrl()
export const WS_BASE = getWsBaseUrl()

