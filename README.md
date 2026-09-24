# EduVerse Server

A robust ASP.NET Core backend for the EduVerse educational platform with MongoDB integration.

🌐 **Frontend Repository**: [eduverse.main](https://github.com/kentrussel-dev/eduverse.main)

This is the backend server component. For the React frontend application, please visit the frontend repository.

## Tech Stack

- **Framework**: ASP.NET Core 9.0
- **Database**: MongoDB
- **Authentication**: 
  - ASP.NET Core Identity
  - Google OAuth 2.0
  - JWT for API authentication
- **ORM**: MongoDB.Driver with AspNetCore.Identity.MongoDbCore
- **Email**: MailKit for email notifications

## Project Structure

```
EduVerse.Server/
├── Controllers/        # API Controllers
├── Data/              # Data access and models
├── Models/            # Request/Response models
└── Services/          # Business logic services
```

## Features

- 🔐 Advanced authentication with multiple providers
- 📧 Email verification system
- 🗄️ MongoDB integration with Identity
- 🔑 Google OAuth integration
- 🛡️ Secure cookie-based sessions
- 📝 Comprehensive API documentation

## Prerequisites

- .NET 9.0 SDK
- MongoDB 6.0+
- Google OAuth 2.0 credentials
- SMTP server for emails

## Getting Started

1. Clone the repository
2. Update appsettings.json with your configuration:
```json
{
  "MongoDB": {
    "ConnectionString": "mongodb://localhost:27017",
    "DatabaseName": "EduVerse"
  },
  "Authentication": {
    "Google": {
      "ClientId": "your_client_id",
      "ClientSecret": "your_client_secret"
    }
  }
}
```

3. Run the migrations:
```powershell
dotnet ef database update
```

4. Start the server:
```powershell
dotnet run
```

## Virtual World (Habbo-style rooms)

The server also runs a real-time virtual world: students and teachers walk around isometric rooms as avatars, chat, and hold classes.

- **Transport**: ASP.NET Core SignalR hub at `/hubs/world`
- **Auth**: the JWT returned by `/api/auth/login` and `/api/auth/me`, sent as the `access_token` query parameter
- **Code**: `Realtime/`
  - `WorldHub.cs`: hub methods clients call (join, move, say, raise hand, host tools)
  - `WorldState.cs`: live rooms, who is where, walking, chat rate limits, host permissions
  - `RoomTemplates.cs`: built-in rooms (Main Hall, Quiet Library, Classroom 101) and layouts
  - `Pathfinder.cs`: A* pathfinding on the tile grid
  - `ChatFilter.cs`: masks bad words (English and Filipino) and hides links, emails and phone numbers
  - `RoomStore.cs`: saves user-created rooms and chat reports to MongoDB (`Rooms`, `ChatReports`)

### Rules

- The server decides where everyone is. Clients only send "walk to tile (x, y)".
- Only teachers can create classrooms. Classrooms and private rooms aren't listed; others join with the 6-character room code.
- Hosts (a room's owner, or any teacher in the built-in Classroom 101) can mute, remove, turn on quiet mode, clear chat and write on the whiteboard.
- Names are shown as first name + last initial ("Juan D.").
- Chat: max 200 characters, 5 messages per 6 seconds. There are no private messages.
- One avatar per account: joining from a second window removes the first.

### Running without MongoDB

Set `Realtime:Store` to `InMemory` to keep rooms in memory (login still needs MongoDB):

```bash
dotnet user-secrets set "Realtime:Store" "InMemory"
```

### Tests

```bash
dotnet test tests/EduVerse.Server.Tests
```

## API Documentation

### Authentication Endpoints

- POST `/api/auth/register` - Register new user
- POST `/api/auth/login` - Email/password login (returns a JWT in `token`)
- GET `/api/auth/google/login` - Initiate Google OAuth
- GET `/api/auth/google/callback` - Google OAuth callback
- POST `/api/auth/logout` - Logout user

### Protected Routes

All protected routes require authentication via:
- Valid session cookie
- JWT Bearer token
- Valid OAuth token

## Development

### Environment Setup

1. Install .NET 9.0 SDK
2. Install MongoDB
3. Configure Google OAuth credentials
4. Set up email service

### Security Configuration

- CORS is configured for frontend integration
- Secure cookie settings
- HTTPS in production
- OAuth state validation
- XSS protection

### Secrets Management

The project uses ASP.NET Core User Secrets for local development and environment variables for production. Sensitive data should never be committed to the repository.

1. **Local Development**:
   - Right-click the project in Visual Studio and select "Manage User Secrets"
   - Or use the command line: `dotnet user-secrets init`
   - Required secrets to set up:

   ```bash
   # MongoDB Connection
   dotnet user-secrets set "ConnectionStrings:MongoDB" "mongodb://localhost:27017"

   # JWT Authentication
   dotnet user-secrets set "Jwt:Key" "your-256-bit-secret-key"

   # Google OAuth
   dotnet user-secrets set "Authentication:Google:ClientId" "your-google-client-id"
   dotnet user-secrets set "Authentication:Google:ClientSecret" "your-google-client-secret"

   # SMTP Settings (Example using Mailtrap)
   dotnet user-secrets set "MailSettings:Host" "sandbox.smtp.mailtrap.io"
   dotnet user-secrets set "MailSettings:Port" "2525"
   dotnet user-secrets set "MailSettings:Username" "your-smtp-username"
   dotnet user-secrets set "MailSettings:Password" "your-smtp-password"
   ```

   You can verify your secrets are set correctly with:
   ```bash
   dotnet user-secrets list
   ```

2. **Production**:
   - Use environment variables with the same names
   - Example for Docker: Use Docker secrets or environment files
   - For Azure: Use Azure Key Vault or App Configuration
   - For AWS: Use AWS Secrets Manager

3. **Configuration Template**:
   - See `appsettings.template.json` for required configuration values
   - Copy to `appsettings.json` and update with non-sensitive values
   - Never commit sensitive data to `appsettings.json`

### Database Schema

The MongoDB schema is managed through the Identity framework with custom extensions for educational features.

## Deployment

1. Update environment variables
2. Configure production MongoDB instance
3. Enable HTTPS
4. Set secure cookie policies
5. Configure production logging

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details
