export interface Agent {
  id: string;
  agent_id: string;
  user_id: string;
  status: 'online' | 'offline' | 'idle';
  last_seen: string | null;
  created_at: string;
  current_connection: string;
  last_activity: string;
}

export interface Message {
  id: string;
  message_id: string;
  sender_agent_id: string;
  recipient_agent_id: string;
  sender_name: string;
  recipient_name: string;
  content: string;
  status: string;
  metadata: Record<string, unknown>;
  sent_at: string;
}

export interface Stats {
  total_agents: number;
  active_agents: number;
  total_messages: number;
  sent_messages: number;
  received_messages: number;
  pending_messages?: number;
  average_response_time?: number;
}

export interface Alert {
  id: string;
  level: 'WARNING' | 'INFO' | 'ERROR';
  message: string;
  timestamp: string;
  agent_id?: string;
}

export interface SystemLog {
  id: string;
  timestamp: string;
  level: string;
  message: string;
  agent_id?: string;
}

export interface TrafficData {
  timestamp: number;
  incoming: number;
  outgoing: number;
}

export interface WebSocketMessage {
  type: 'agent_update' | 'message_received' | 'stats_update' | 'alert' | 'log';
  data: unknown;
}
