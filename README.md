# TapoCheck - Secure Chat Application with WebSockets

Improved version of the TapoCheck chat application with security enhancements, code quality improvements, and real-time WebSocket communication.

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env and set your SECRET_KEY
```

3. Generate a secure secret key:
```python
python -c "import secrets; print(secrets.token_hex(32))"
```

4. Run the application:
```bash
python tapocheck/app.py
```

## Security Improvements

### Fixed Issues:
- ✅ Hardcoded secret key moved to environment variables
- ✅ CSRF protection added via Flask-WTF
- ✅ Rate limiting for authentication endpoints only
- ✅ XSS protection via HTML sanitization (bleach)
- ✅ Improved file upload validation (size, type checks)
- ✅ Session security enhancements (timeout, secure cookies)
- ✅ Debug mode configurable via environment
- ✅ Password complexity requirements (min 8 characters)
- ✅ Proper error handling with logging
- ✅ SQL injection prevention maintained
- ✅ Input sanitization throughout

### WebSocket Implementation:
- ✅ Real-time messaging via Flask-SocketIO
- ✅ No more polling (eliminated rate limiting issues)
- ✅ Room-based communication for groups and DMs
- ✅ Typing indicators via WebSocket events
- ✅ Automatic connection/disconnection handling
- ✅ Secure WebSocket with authentication check

### Code Quality Improvements:
- ✅ Proper imports at file start
- ✅ Type hints added to all functions
- ✅ DRY principle - helper functions for repeated logic
- ✅ Configuration separated into config.py
- ✅ Comprehensive error handling
- ✅ Logging system added
- ✅ Constants for magic numbers
- ✅ Database connection improvements
- ✅ Modular configuration (dev/prod)

## Configuration

### Environment Variables:
- `FLASK_ENV`: development/production (default: development)
- `FLASK_DEBUG`: True/False (default: False)
- `SECRET_KEY`: Application secret key (required in production)

### Config Settings (config.py):
- Maximum file size: 16MB
- Session lifetime: 24 hours
- Rate limiting: 200/day, 50/hour default
- Typing timeout: 4 seconds
- Login attempts: 5 per lockout period

## Running in Production

1. Set environment:
```bash
export FLASK_ENV=production
export FLASK_DEBUG=False
export SECRET_KEY=your-generated-secret-key
```

2. Use a production WSGI server:
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 tapocheck.app:app
```

3. Enable HTTPS (required for secure cookies)
4. Set up proper logging rotation
5. Consider Redis for typing status in multi-worker deployments

## Architecture Notes

### Database:
- SQLite databases: `users.db` and `chats.db`
- Connection pooling improved with timeout
- Transactions used for data integrity

### File Uploads:
- Location: `static/uploads/`
- Validated extensions and size limits
- Secure filename handling

### Security:
- CSRF tokens required for all POST requests
- Rate limiting on sensitive endpoints
- Session management with secure flags
- Input sanitization for XSS prevention

## Future Improvements

While technical issues are fixed, consider these functional enhancements:
- WebSocket support for real-time messaging
- Redis for distributed state management
- Database migrations system
- Unit and integration tests
- More comprehensive admin panel
- Search functionality
- Notification system
