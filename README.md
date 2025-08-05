DataVault Enterprise
Quantum-ready distributed file-storage with Zero-Trust, BFT consensus, post-quantum crypto, dynamic sharding and a real-time security dashboard

1 Project overview
DataVault Enterprise is a teaching / demo stack that shows how modern security concepts can be layered on top of a flat-file, peer-to-peer storage system.

Main components

Layer	What it does
Enterprise nodes (main.go)	Each node stores encrypted files, talks to its peers over TCP and exposes a Web-API (default ports 8080-8082).
Dashboard-API (dashboard/server.go)	A lightweight aggregator that fans-out to all nodes, merges their JSON responses and exposes five REST endpoints on port 3000 for the UI.
Next.js dashboard (datavault-dashboard/)	React + TypeScript front-end that polls the Dashboard-API and animates a Security Command Center page.
2 Prerequisites
Tool	Version	Notes
Go	1.22+	builds the backend & dashboard-API
Node	18+	runs the Next.js dashboard
make	any	convenience targets (make dev, make build)
Linux, macOS and WSL are tested; Windows users can use PowerShell or WSL.

3 Clone & build
bash
git clone https://github.com/your-org/datavault-enterprise.git
cd datavault-enterprise
Install JavaScript deps

bash
cd datavault-dashboard
npm install        # or pnpm install
cd ..
Run everything in development mode

bash
make dev
make dev does the following in parallel:

Spins up three storage nodes

Starts the Dashboard-API on :3000

Launches the Next.js dev server on :3001

Open the UI

http://localhost:3001/dashboard/security

You should see live metrics flowing in a few seconds.

4 Manual start (no make)
4.1 Run the storage cluster
bash
# Terminal 1
go run ./cmd/datavault-node -listen :9000 -api 8080

# Terminal 2
go run ./cmd/datavault-node -listen :9001 -api 8081

# Terminal 3
go run ./cmd/datavault-node -listen :9002 -api 8082
Each command initializes a node, enables all enterprise modules and serves its REST API on localhost:<apiPort>.

4.2 Run the Dashboard-API
bash
export DATAVAULT_NODES="http://localhost:8080,http://localhost:8081,http://localhost:8082"
go run ./dashboard
Change DATAVAULT_NODES if you add or remove nodes.

4.3 Run the Next.js dashboard
bash
cd datavault-dashboard
npm run dev      # or pnpm dev
5 Key REST endpoints
Aggregator (port 3000)	What it returns
/api/security/metrics	Cluster-wide security KPI cards
/api/security/modules	Status of Zero-Trust, PQC, BFT, sharding…
/api/security/activity	Recent security events (blocked threats, key rotations)
/api/security/global-status	Threat count per region
/api/security/system-status	Overall health & user count
Each aggregator fans-out to the node endpoints below:

Node (port 808x)	Description
/api/health	ping
/api/advanced-zero-trust-status	real-time ZT data
/api/quantum-status	post-quantum crypto engine
/api/bft-status	Byzantine-fault-tolerant layer
/api/sharding-status	dynamic sharding engine
Try:

bash
curl localhost:8080/api/advanced-zero-trust-status | jq
curl localhost:3000/api/security/metrics | jq
6 Customisation
Change ports / node count – edit main.go or pass flags/env-vars when starting nodes.

Persistence folder – defaults to ./storage/shared; override via the -root flag.

Disable demo file – export DATAVAULT_NO_DEMO=true.

CORS – allowed origins are configured in corsWrapper() of the Web-API.

7 Production build
bash
make build
# dist/datavault-node, dist/dashboard-api, dist/dashboard-frontend/
Copy binaries to your servers, set DATAVAULT_NODES on the dashboard-API host and point the static Next.js build to that API.

8 Stopping everything
Hit Ctrl-C in each terminal or in the window running make dev.
Nodes persist their flat-file data in ./storage/shared; remove it if you want a clean slate.

9 Troubleshooting
Symptom	Fix
Dashboard shows “Loading …”	Check browser console → network tab. Likely CORS or Dashboard-API not running.
curl :3000/api/security/* returns only API-info	Your Dashboard-API binary is outdated – rebuild with the live handlers shown in dashboard/server.go.
Ports already in use	Kill other instances (lsof -i:3000, lsof -i:3001, etc.) or edit port flags.
Slow metrics	Increase http.Client{Timeout: …} in the Dashboard-API or reduce node list.
10 License
MIT — see LICENSE for details.
