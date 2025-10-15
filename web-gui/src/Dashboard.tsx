import { useState, useEffect, useCallback } from 'react';
import { Activity, AlertTriangle } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { statsAPI, agentAPI, auditAPI } from './api';
import { useWebSocket } from './useWebSocket';
import type { Stats, Agent, Alert, SystemLog, TrafficData, WebSocketMessage } from './types';

export default function Dashboard() {
  const [stats, setStats] = useState<Stats>({
    total_agents: 0,
    active_agents: 0,
    total_messages: 0,
    sent_messages: 0,
    received_messages: 0,
    pending_messages: 0,
    average_response_time: 1.2,
  });
  const [agents, setAgents] = useState<Agent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [logs, setLogs] = useState<SystemLog[]>([]);
  const [trafficData, setTrafficData] = useState<TrafficData[]>([]);
  const userId = localStorage.getItem('userId');

  const loadData = useCallback(async () => {
    try {
      const [statsRes, agentsRes, logsRes] = await Promise.all([
        statsAPI.get(),
        agentAPI.list(),
        auditAPI.list(50, 0),
      ]);

      setStats({
        ...statsRes.data,
        pending_messages: statsRes.data.pending_messages || 0,
        average_response_time: statsRes.data.average_response_time || 1.2,
      });

      const enhancedAgents: Agent[] = agentsRes.data.map((agent: Agent) => ({
        ...agent,
        status: (agent.last_seen && new Date(agent.last_seen).getTime() > Date.now() - 300000
          ? 'online'
          : agent.last_seen
          ? 'idle'
          : 'offline') as 'online' | 'offline' | 'idle',
        current_connection: agent.last_seen ? 'CHAT-2623-QAIK-1B-001' : 'None',
        last_activity: agent.last_seen ? formatTimeAgo(agent.last_seen) : '18s',
      }));

      setAgents(enhancedAgents);

      const mappedLogs: SystemLog[] = logsRes.data.map((log: any) => ({
        id: log.id || Math.random().toString(),
        timestamp: log.created_at || new Date().toISOString(),
        level: log.severity || 'info',
        message: log.message || JSON.stringify(log.event_data || {}),
      }));
      setLogs(mappedLogs);

      generateMockAlerts();
      generateTrafficData();
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    }
  }, []);

  const handleWebSocketMessage = useCallback((message: WebSocketMessage) => {
    switch (message.type) {
      case 'agent_update':
        loadData();
        break;
      case 'message_received':
        loadData();
        addAlert('INFO', 'New message received');
        break;
      case 'stats_update':
        setStats(message.data as Stats);
        break;
      case 'alert':
        const alertData = message.data as Alert;
        addAlert(alertData.level, alertData.message);
        break;
      case 'log':
        const logData = message.data as SystemLog;
        setLogs(prev => [logData, ...prev].slice(0, 50));
        break;
    }
  }, [loadData]);

  useWebSocket({
    userId,
    onMessage: handleWebSocketMessage,
  });

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      loadData();
      updateTrafficData();
    }, 5000);

    return () => clearInterval(interval);
  }, [loadData]);

  const generateMockAlerts = () => {
    const mockAlerts: Alert[] = [
      {
        id: '1',
        level: 'WARNING',
        message: 'ASNT-015 experienced a connection drop',
        timestamp: new Date(Date.now() - 180000).toISOString(),
        agent_id: 'ASNT-015',
      },
    ];
    setAlerts(mockAlerts);
  };

  const addAlert = (level: Alert['level'], message: string) => {
    const newAlert: Alert = {
      id: Math.random().toString(),
      level,
      message,
      timestamp: new Date().toISOString(),
    };
    setAlerts(prev => [newAlert, ...prev].slice(0, 10));
  };

  const generateTrafficData = () => {
    const now = Date.now();
    const data: TrafficData[] = [];
    for (let i = 23; i >= 0; i--) {
      data.push({
        timestamp: now - i * 3600000,
        incoming: Math.floor(Math.random() * 500 + 200),
        outgoing: Math.floor(Math.random() * 400 + 150),
      });
    }
    setTrafficData(data);
  };

  const updateTrafficData = () => {
    setTrafficData(prev => {
      const newData = [...prev.slice(1)];
      newData.push({
        timestamp: Date.now(),
        incoming: Math.floor(Math.random() * 500 + 200),
        outgoing: Math.floor(Math.random() * 400 + 150),
      });
      return newData;
    });
  };

  const formatTimeAgo = (timestamp: string) => {
    const seconds = Math.floor((Date.now() - new Date(timestamp).getTime()) / 1000);
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ago`;
  };

  const communicationHealth = Math.round((stats.active_agents / Math.max(stats.total_agents, 1)) * 100);

  return (
    <div className="min-h-screen bg-slate-900 text-gray-100 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <h2 className="text-lg font-semibold mb-4 text-gray-200">System Overview</h2>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <div className="text-gray-400 text-sm mb-1">Active</div>
                <div className="text-3xl font-bold text-white">{stats.total_messages}</div>
                <div className="text-gray-400 text-xs mt-1">Pending Messages</div>
              </div>
              <div>
                <div className="text-gray-400 text-sm mb-1">Active Agents</div>
                <div className="text-3xl font-bold text-white">{stats.active_agents}</div>
                <div className="text-gray-400 text-xs mt-1">{stats.average_response_time}s</div>
              </div>
              <div>
                <div className="text-gray-400 text-sm mb-1">Messages</div>
                <div className="text-3xl font-bold text-white">{stats.average_response_time}s</div>
                <div className="text-gray-400 text-xs mt-1">Average Response Time</div>
              </div>
            </div>
          </div>

          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <h2 className="text-lg font-semibold mb-4 text-gray-200">Communication Health</h2>
            <div className="flex items-center gap-6">
              <div className="relative w-24 h-24">
                <svg className="w-24 h-24 transform -rotate-90">
                  <circle
                    cx="48"
                    cy="48"
                    r="40"
                    stroke="currentColor"
                    strokeWidth="8"
                    fill="none"
                    className="text-slate-700"
                  />
                  <circle
                    cx="48"
                    cy="48"
                    r="40"
                    stroke="currentColor"
                    strokeWidth="8"
                    fill="none"
                    strokeDasharray={`${2 * Math.PI * 40}`}
                    strokeDashoffset={`${2 * Math.PI * 40 * (1 - communicationHealth / 100)}`}
                    className="text-cyan-400"
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-2xl font-bold text-white">{communicationHealth}%</span>
                </div>
              </div>
              <div className="flex items-center justify-center w-10 h-10 bg-green-500 rounded-full">
                <Activity className="w-6 h-6 text-white" />
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-gray-200">Message Traffic (Last 24h)</h2>
              <div className="flex gap-4 text-sm">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-cyan-400 rounded-full"></div>
                  <span className="text-gray-400">Incoming</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-gray-400 rounded-full"></div>
                  <span className="text-gray-400">Outgoing</span>
                </div>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={trafficData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis
                  dataKey="timestamp"
                  tickFormatter={(ts) => new Date(ts).getHours() + ':00'}
                  stroke="#64748b"
                />
                <YAxis stroke="#64748b" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '0.5rem',
                  }}
                />
                <Line type="monotone" dataKey="incoming" stroke="#22d3ee" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="outgoing" stroke="#94a3b8" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>

          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <h2 className="text-lg font-semibold mb-4 text-gray-200">Recent Alerts</h2>
            <div className="space-y-3">
              {alerts.length === 0 ? (
                <p className="text-gray-400 text-sm">No recent alerts</p>
              ) : (
                alerts.slice(0, 5).map((alert) => (
                  <div key={alert.id} className="flex items-start gap-3">
                    <AlertTriangle className={`w-5 h-5 flex-shrink-0 ${
                      alert.level === 'WARNING' ? 'text-yellow-500' :
                      alert.level === 'ERROR' ? 'text-red-500' :
                      'text-blue-500'
                    }`} />
                    <div className="flex-1">
                      <div className={`font-medium ${
                        alert.level === 'WARNING' ? 'text-yellow-500' :
                        alert.level === 'ERROR' ? 'text-red-500' :
                        'text-blue-500'
                      }`}>
                        [{alert.level}] {alert.message}
                      </div>
                      <div className="text-xs text-gray-400 mt-1">
                        ({formatTimeAgo(alert.timestamp)})
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <h2 className="text-lg font-semibold mb-4 text-gray-200">Agent Status</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="text-left py-2 text-gray-400 font-medium">Agent ID</th>
                    <th className="text-left py-2 text-gray-400 font-medium">Status</th>
                    <th className="text-left py-2 text-gray-400 font-medium">Current Connection</th>
                    <th className="text-left py-2 text-gray-400 font-medium">Last Activity</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.slice(0, 4).map((agent) => (
                    <tr key={agent.id} className="border-b border-slate-700">
                      <td className="py-3 text-gray-200">{agent.agent_id}</td>
                      <td className="py-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs ${
                          agent.status === 'online' ? 'bg-green-500/20 text-green-400' :
                          agent.status === 'idle' ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-gray-500/20 text-gray-400'
                        }`}>
                          <div className={`w-1.5 h-1.5 rounded-full ${
                            agent.status === 'online' ? 'bg-green-400' :
                            agent.status === 'idle' ? 'bg-yellow-400' :
                            'bg-gray-400'
                          }`} />
                          {agent.status}
                        </span>
                      </td>
                      <td className="py-3 text-gray-300">{agent.current_connection}</td>
                      <td className="py-3 text-gray-400">{agent.last_activity}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
            <h2 className="text-lg font-semibold mb-4 text-gray-200">System Logs</h2>
            <div className="space-y-2 max-h-64 overflow-y-auto font-mono text-xs">
              {logs.slice(0, 10).map((log) => (
                <div key={log.id} className="text-gray-300">
                  <span className="text-gray-500">[{new Date(log.timestamp).toLocaleTimeString()}]</span>{' '}
                  <span className={
                    log.level === 'error' ? 'text-red-400' :
                    log.level === 'warning' ? 'text-yellow-400' :
                    'text-cyan-400'
                  }>{log.level}:</span>{' '}
                  {log.message}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
