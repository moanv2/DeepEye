# DeepEye

Real-time attack surface monitoring tool. DeepEye scans a target domain to discover subdomains, probe host liveness, resolve ASN information, and crawl endpoints for sensitive paths.

## Current Stage

DeepEye is in **early development (v0.1.0)**. Core scanning functionality is working but runs synchronously within the HTTP request cycle — background task offloading via Celery is planned but not yet implemented.

### What works

- Full domain scan pipeline: subdomain discovery, HTTP probing, ASN lookup, and endpoint crawling
- Subdomain enumeration via [subfinder](https://github.com/projectdiscovery/subfinder)
- Liveness probing and IP resolution via [httpx](https://github.com/projectdiscovery/httpx)
- ASN information lookup via [asnmap](https://github.com/projectdiscovery/asnmap)
- Endpoint crawling with JavaScript rendering via [katana](https://github.com/projectdiscovery/katana)
- Sensitive path detection (~20 patterns: `/admin`, `/.env`, `/.git`, `/swagger`, etc.)
- Dashboard with scan history and per-scan detail views (subdomains, endpoints, sensitive findings)
- PostgreSQL persistence for all scan data

### What's in progress

- Background scan execution via Celery + Redis (infrastructure is provisioned, workers not yet implemented)
- WebSocket-based real-time scan progress updates
- Proper error handling and logging throughout the pipeline

## Tech Stack

| Layer          | Technology                                      |
|----------------|------------------------------------------------|
| Backend        | Python 3.13, FastAPI 0.109, SQLAlchemy 2.0     |
| Frontend       | React 19, TypeScript 5.9, Vite 7, Tailwind CSS 4 |
| Database       | PostgreSQL 15                                   |
| Cache/Queue    | Redis (provisioned, not yet used)               |
| Scanning Tools | ProjectDiscovery suite (subfinder, httpx, asnmap, katana) via Docker |
| Infrastructure | Docker Compose                                  |

## Prerequisites

- [Python 3.13+](https://www.python.org/downloads/)
- [Node.js 18+](https://nodejs.org/) and npm
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (required for both infrastructure and scanning tools)
- A [ProjectDiscovery Cloud Platform](https://cloud.projectdiscovery.io/) API key

## Setup

### 1. Clone the repository

```bash
git clone <repository-url>
cd DeepEye
```

### 2. Start infrastructure services

PostgreSQL and Redis run via Docker Compose:

```bash
docker-compose up -d
```

This starts:
- **PostgreSQL 15** on `localhost:5432` (user: `deepeye`, password: `localdev`, database: `deepeye`)
- **Redis** on `localhost:6379`

### 3. Pull the scanning tool Docker images

DeepEye invokes ProjectDiscovery tools as Docker containers. Pull them ahead of time:

```bash
docker pull projectdiscovery/subfinder
docker pull projectdiscovery/httpx
docker pull projectdiscovery/asnmap
docker pull projectdiscovery/katana
```

### 4. Set up the backend

```bash
cd backend
pip install -r requirements.txt
```

Create a `backend/.env` file:

```env
PDCP_API_KEY=<your-projectdiscovery-api-key>
DATABASE_URL=postgresql://deepeye:localdev@localhost:5432/deepeye
REDIS_URL=redis://localhost:6379
```

Database tables are created automatically on first startup.

### 5. Set up the frontend

```bash
cd frontend
npm install
```

## Running

Open two terminals from the project root:

**Terminal 1 — Backend** (runs on `http://localhost:8000`):

```bash
cd backend
uvicorn app.main:app --reload
```

**Terminal 2 — Frontend** (runs on `http://localhost:5173`):

```bash
cd frontend
npm run dev
```

Open `http://localhost:5173` in your browser. The frontend proxies `/api` requests to the backend automatically.

## API Endpoints

| Method | Path                            | Description                    |
|--------|---------------------------------|--------------------------------|
| POST   | `/api/scan`                     | Start a full domain scan       |
| GET    | `/api/scans`                    | List all scans with stats      |
| GET    | `/api/scan/{scan_id}/subdomains`| List subdomains for a scan     |
| GET    | `/api/scan/{scan_id}/endpoints` | List endpoints for a scan      |
| GET    | `/api/scan/{scan_id}/sensitive` | List sensitive endpoints only  |
| GET    | `/health`                       | Health check                   |

## Project Structure

```
DeepEye/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app, CORS, router mounting
│   │   ├── api/
│   │   │   └── routes.py        # All API routes and scan pipeline logic
│   │   ├── models/
│   │   │   ├── database.py      # SQLAlchemy engine and session factory
│   │   │   └── scan.py          # ORM models (Scan, Subdomain, Endpoint)
│   │   ├── services/            # Service modules (subfinder wrapper, unused)
│   │   └── workers/             # Reserved for Celery background tasks
│   ├── requirements.txt
│   └── .env                     # Local environment variables (not committed)
├── frontend/
│   ├── src/
│   │   ├── api/client.ts        # Axios API client
│   │   ├── types/index.ts       # TypeScript interfaces
│   │   ├── pages/               # Dashboard, ScanDetail
│   │   └── components/          # ScanForm, ScanList, SubdomainTable, etc.
│   ├── package.json
│   └── vite.config.ts
├── docker-compose.yml           # PostgreSQL + Redis
└── requirements.txt             # All project dependencies
```

## License

This project is for authorized security testing and educational purposes only. Always obtain proper authorization before scanning any domain you do not own.
