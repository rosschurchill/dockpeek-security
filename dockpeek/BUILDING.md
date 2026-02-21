# Building DockPeek

This guide explains how to build and run DockPeek from source.

## Prerequisites

- Docker and Docker Compose
- Node.js and npm (for Tailwind CSS compilation)
- Git

## Getting the Source Code

### Clone the repository

```bash
git clone https://github.com/dockpeek/dockpeek.git
cd dockpeek
```

### Choose a branch

**Stable version (recommended):**
```bash
git checkout main
```

**Development version (latest features):**
```bash
git checkout develop
```

## Install Dependencies

Install Node.js dependencies for Tailwind CSS:

```bash
npm install
```

## Building CSS

Compile the Tailwind CSS:

```bash
npm run build:css
```

**Note:** The `tailwindcss.css` file is automatically generated. Do not edit it manually - make your changes in `styles.css` instead, then rebuild.

## Building and Running with Docker Compose

1. Navigate to the `deploy` directory:
   ```bash
   cd deploy
   ```

2. Build and start the container:
   ```bash
   docker-compose up -d --build
   ```

3. Access DockPeek at `http://localhost:3420`

## Configuration

Edit the `docker-compose.yml` file to customize:

- `SECRET_KEY` - Application secret key (change in production!)
- `USERNAME` / `PASSWORD` - Login credentials (default: admin/admin)
- `DISABLE_AUTH` - Set to `true` to disable authentication
- `DOCKER_HOST_NAME` - Display name for the Docker host
- `LOG_LEVEL` - Logging verbosity (DEBUG, INFO, WARNING, ERROR)
- Port mapping - Change `3420:8000` to use a different port

## Development

For development with auto-reload:

```bash
docker-compose up
```

To rebuild after changes:

```bash
docker-compose up -d --build
```

## Updating

To update to the latest version:

```bash
git pull origin main  # or 'develop' for development branch
npm install  # update dependencies if needed
npm run build:css
cd deploy
docker-compose up -d --build
```

