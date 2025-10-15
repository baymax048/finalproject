# Secure Agent Communication - Web GUI

A modern web interface for managing secure agent-to-agent communication with real-time monitoring, message tracking, and audit logging.

## Features

### Core Functionality
- **User Authentication**: Secure JWT-based authentication with registration and login
- **Agent Management**: Create and manage secure communication agents
- **Message Tracking**: View sent and received encrypted messages
- **Dashboard**: Real-time stats and activity overview
- **Audit Logging**: Complete security event tracking and monitoring

### Security Features
- RSA + AES hybrid encryption for messages
- JWT token-based authentication
- Password hashing with bcrypt
- Row-level security policies
- Comprehensive audit trails

### User Interface
- Modern, responsive design
- Real-time updates with WebSocket support
- Intuitive navigation and user experience
- Dark mode compatible
- Mobile-friendly interface

## Technology Stack

### Frontend
- **React 18**: Modern UI library
- **TypeScript**: Type-safe development
- **Vite**: Fast build tool and dev server
- **Tailwind CSS**: Utility-first styling
- **React Router**: Client-side routing
- **Axios**: HTTP client
- **Lucide React**: Icon library
- **date-fns**: Date formatting

### Backend
- **FastAPI**: Modern Python web framework
- **MongoDB**: Document database for user and agent data
- **JWT**: JSON Web Tokens for authentication
- **bcrypt**: Password hashing
- **WebSockets**: Real-time communication

## Installation

### Prerequisites
- Python 3.11+
- Node.js 18+
- Docker and Docker Compose
- MongoDB
- RabbitMQ

### Backend Setup

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start infrastructure services:**
   ```bash
   docker-compose up -d
   ```

3. **Start the web backend:**
   ```bash
   python web_backend.py
   ```
   The API will be available at `http://localhost:8001`

4. **Start the policy service (for agent operations):**
   ```bash
   python policy_service.py
   ```
   The policy service will be available at `http://localhost:8000`

### Frontend Setup

1. **Navigate to the web GUI directory:**
   ```bash
   cd web-gui
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```

   Edit `.env` to set your API URL:
   ```
   VITE_API_URL=http://localhost:8001
   ```

4. **Start the development server:**
   ```bash
   npm run dev
   ```
   The web app will be available at `http://localhost:5173`

5. **Build for production:**
   ```bash
   npm run build
   ```

## Usage

### First Time Setup

1. **Access the web interface** at `http://localhost:5173`

2. **Register a new account:**
   - Click "Register here" on the login page
   - Enter your full name, email, and password
   - Password must be at least 8 characters

3. **Dashboard Overview:**
   - After login, you'll see the dashboard with stats
   - View active agents and recent messages

### Managing Agents

1. **Create a New Agent:**
   - Navigate to "Agents" in the sidebar
   - Click "Add Agent"
   - Enter agent ID (letters, numbers, hyphens, underscores only)
   - Provide the public key fingerprint
   - Click "Create Agent"

2. **View Agent Details:**
   - See all your registered agents
   - View capabilities, status, and key fingerprints
   - Monitor last seen timestamps

### Viewing Messages

1. **Message List:**
   - Navigate to "Messages"
   - Filter by: All, Sent, or Received
   - Click on messages to expand details

2. **Message Details:**
   - View sender and recipient
   - See message content and metadata
   - Check delivery status and timestamps

### Monitoring Audit Logs

1. **Access Audit Logs:**
   - Navigate to "Audit Logs"
   - View security events and activity

2. **Filter Events:**
   - Filter by severity: All, Info, Warning, Error
   - View event details and timestamps

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/me` - Get current user

### Agents
- `GET /api/agents` - List user's agents
- `POST /api/agents` - Create new agent
- `GET /api/agents/{agent_id}` - Get agent details

### Messages
- `GET /api/messages` - List messages (with pagination)

### Stats & Monitoring
- `GET /api/stats` - Get user statistics
- `GET /api/audit` - Get audit logs
- `GET /health` - Health check

### WebSocket
- `WS /ws/{user_id}` - Real-time updates

## Security Considerations

### Authentication
- Passwords are hashed with bcrypt
- JWT tokens expire after 60 minutes
- Refresh tokens valid for 7 days
- Secure HTTP-only cookies recommended for production

### Authorization
- User can only access their own agents and messages
- Role-based access control (admin, agent_operator, viewer)
- Token revocation supported

### Data Protection
- All messages encrypted end-to-end
- AES-256-GCM for message encryption
- RSA-4096 for key exchange
- Message integrity verification with SHA-256

### Best Practices
1. Use HTTPS in production
2. Enable CORS restrictions
3. Implement rate limiting
4. Regular security audits
5. Keep dependencies updated

## Development

### Project Structure
```
web-gui/
├── src/
│   ├── api.ts                 # API client
│   ├── types.ts               # TypeScript types
│   ├── AuthContext.tsx        # Authentication context
│   ├── App.tsx                # Main app component
│   ├── components/
│   │   └── Layout.tsx         # Layout with navigation
│   └── pages/
│       ├── Login.tsx          # Login page
│       ├── Register.tsx       # Registration page
│       ├── Dashboard.tsx      # Dashboard page
│       ├── Agents.tsx         # Agent management
│       ├── Messages.tsx       # Message viewer
│       └── Audit.tsx          # Audit log viewer
├── package.json
├── vite.config.ts
├── tailwind.config.js
└── tsconfig.json

backend/
└── web_backend.py             # FastAPI backend
```

### Adding Features

1. **New API Endpoint:**
   - Add endpoint in `web_backend.py`
   - Update API client in `api.ts`
   - Add TypeScript types in `types.ts`

2. **New Page:**
   - Create component in `src/pages/`
   - Add route in `App.tsx`
   - Add navigation item in `Layout.tsx`

3. **Styling:**
   - Use Tailwind CSS utility classes
   - Follow existing component patterns
   - Maintain responsive design

## Troubleshooting

### Backend Issues

**MongoDB Connection Failed:**
```bash
# Check MongoDB is running
docker-compose ps

# Restart MongoDB
docker-compose restart mongo
```

**Port Already in Use:**
```bash
# Kill process on port 8001
lsof -ti:8001 | xargs kill -9
```

### Frontend Issues

**Dependencies Install Failed:**
```bash
# Clear npm cache
npm cache clean --force

# Remove node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

**Build Errors:**
```bash
# Check Node version (18+ required)
node --version

# Update dependencies
npm update
```

### Common Errors

**401 Unauthorized:**
- Token expired - login again
- Invalid credentials - check email/password

**503 Service Unavailable:**
- Database connection failed
- Check MongoDB is running

**CORS Errors:**
- Update CORS settings in `web_backend.py`
- Check API_URL in frontend `.env`

## Performance

### Optimization Tips
1. Enable production build for frontend
2. Use connection pooling for MongoDB
3. Implement caching for frequently accessed data
4. Compress API responses
5. Use CDN for static assets in production

### Monitoring
- Health check endpoint: `/health`
- Monitor MongoDB performance
- Track API response times
- Monitor WebSocket connections

## Deployment

### Production Checklist
- [ ] Change JWT secret key
- [ ] Enable HTTPS
- [ ] Configure CORS properly
- [ ] Set up reverse proxy (nginx)
- [ ] Enable rate limiting
- [ ] Configure logging
- [ ] Set up monitoring
- [ ] Regular backups
- [ ] Security audit

### Docker Deployment
```bash
# Build frontend
cd web-gui
npm run build

# The dist/ folder contains production build
# Serve with nginx or other web server
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Support

For issues and questions:
- Check the troubleshooting section
- Review existing issues
- Create a new issue with details

---

**Secure Agent Communication Framework v1.0**
