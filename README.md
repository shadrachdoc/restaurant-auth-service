# Restaurant Auth Service

Authentication and user management service for the Restaurant Management System.

## Features

- User registration and login
- JWT token authentication
- Password reset
- Role-based access control (RBAC)

## Quick Start

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the service
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

## CI/CD Pipeline

This repository uses GitHub Actions for automated deployment:

1. **On Push to `main` or `develop`**:
   - Runs tests
   - Builds Docker image
   - Pushes to Docker Hub with commit SHA tag

2. **On Push to `main` only**:
   - Updates the `restaurant-infrastructure` repo with new image tag
   - ArgoCD automatically deploys the new version

## Required GitHub Secrets

| Secret | Description |
|--------|-------------|
| `DOCKER_USERNAME` | Docker Hub username |
| `DOCKER_PASSWORD` | Docker Hub access token |
| `GH_PAT` | GitHub Personal Access Token (to push to infrastructure repo) |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `JWT_SECRET_KEY` | Secret key for JWT tokens |
| `JWT_ALGORITHM` | JWT algorithm (default: HS256) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiry time |
