# EduVerse Server

A robust ASP.NET Core backend for the EduVerse educational platform with MongoDB integration.

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

## API Documentation

### Authentication Endpoints

- POST `/api/auth/register` - Register new user
- POST `/api/auth/login` - Email/password login
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
   - Set your secrets:
   ```bash
   dotnet user-secrets set "MongoDB:ConnectionString" "your-connection-string"
   dotnet user-secrets set "Jwt:Secret" "your-jwt-secret"
   dotnet user-secrets set "Authentication:Google:ClientId" "your-client-id"
   dotnet user-secrets set "Authentication:Google:ClientSecret" "your-client-secret"
   dotnet user-secrets set "MailSettings:Password" "your-smtp-password"
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
