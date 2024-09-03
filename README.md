# AngryBirds Authentication System

## Overview

This project implements a secure, token-based authentication system for an API. It provides a robust foundation for user registration, login, and access control using JSON Web Tokens (JWT) and refresh tokens.

## Key Features

- User registration with secure password hashing (BCrypt)
- JWT-based authentication
- Refresh token mechanism for extended sessions
- Protected API endpoints
- Modular design for easy integration and customization

## Components

1. **PasswordLib**: Handles secure password hashing using BCrypt.
2. **AuthenticationLib**: Core authentication logic including JWT services, user management, and token refresh mechanisms.
3. **AngryBirds.API**: Main application showcasing the integration of the authentication system.

## How It Works

1. Users register with a username and password.
2. Passwords are securely hashed using BCrypt before storage.
3. Upon login, users receive an access token (JWT) and a refresh token.
4. The access token is used to authenticate API requests.
5. When the access token expires, the refresh token can be used to obtain a new access token without re-authentication.
6. Protected endpoints require a valid access token for access.

## Getting Started

1. Implement the `IUserRepository` interface based on your chosen database technology.
2. Configure JWT settings in `appsettings.json`.
3. Run the application and use the `/register` endpoint to create a new user.
4. Use the `/login` endpoint to obtain tokens.
5. Access protected resources using the obtained access token.

## Security Considerations

- Store JWT secret keys securely and never expose them in public repositories.
- Implement additional security measures like rate limiting and HTTPS.
- Regularly rotate refresh tokens to enhance security.

## Customization

The modular design allows for easy customization and extension of the authentication system to meet specific project requirements.
