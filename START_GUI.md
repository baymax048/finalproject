# Starting the Real-Time Web GUI

## Quick Start

1. **Start Backend Services:**
   ```bash
   docker-compose up -d
   python web_backend.py
   ```

2. **Start Frontend:**
   ```bash
   cd web-gui
   npm install  # Only needed first time
   npm run dev
   ```

3. **Access the Application:**
   - Open browser to: http://localhost:5173
   - Register a new account or login
   - View real-time dashboard updates

## Real-Time Features

The dashboard includes the following live-updating components:

- **System Overview**: Active agents, pending messages, response times
- **Communication Health**: Live health percentage with visual indicator
- **Message Traffic Chart**: 24-hour traffic visualization with auto-updates
- **Agent Status Table**: Real-time agent status (online/offline/idle)
- **Recent Alerts**: Live alert notifications
- **System Logs**: Streaming log viewer

All components update automatically via WebSocket connection without page refresh.

## Architecture

- **Frontend**: React + TypeScript + Vite + Tailwind CSS
- **Real-time**: WebSocket connection for live data updates
- **Backend**: FastAPI with WebSocket support
- **Database**: MongoDB for persistence

## Development

Run development server with hot reload:
```bash
cd web-gui
npm run dev
```

Build for production:
```bash
cd web-gui
npm run build
```
