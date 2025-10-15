import axios from 'axios';
import type { Agent, Message, Stats, SystemLog } from './types';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const authAPI = {
  login: (email: string, password: string) =>
    api.post('/api/auth/login', { email, password }),

  register: (email: string, password: string, full_name: string) =>
    api.post('/api/auth/register', { email, password, full_name }),

  getMe: () => api.get('/api/auth/me'),
};

export const agentAPI = {
  list: () => api.get<Agent[]>('/api/agents'),
  get: (agentId: string) => api.get<Agent>(`/api/agents/${agentId}`),
  create: (data: { agent_id: string; public_key_fingerprint: string; capabilities: string[] }) =>
    api.post<Agent>('/api/agents', data),
};

export const messageAPI = {
  list: (limit = 100, offset = 0) =>
    api.get<Message[]>('/api/messages', { params: { limit, offset } }),
};

export const statsAPI = {
  get: () => api.get<Stats>('/api/stats'),
};

export const auditAPI = {
  list: (limit = 100, offset = 0) =>
    api.get<SystemLog[]>('/api/audit', { params: { limit, offset } }),
};

export default api;
