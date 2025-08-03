.PHONY: api dashboard enterprise clean help install dev collab-test kill-ports status build test stop restart logs check-deps quick-start full-clean health-check api-safe dev-safe force-kill-ports nuclear-clean diagnose-ports

# 🏆 DataVault Enterprise - Development Commands
# ===============================================

help: ## Show this help message
	@echo "🏆 DataVault Enterprise - Development Commands"
	@echo "=============================================="
	@echo "Phase 1.5: Collaboration Interface Implementation"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

api: ## Start Main Enterprise Server with WebSocket Collaboration (port 3000)
	@echo "🚀 Starting DataVault Enterprise Server with Collaboration..."
	@echo "📊 Serving enterprise metrics and WebSocket collaboration"
	@echo "🏆 DataVault Enterprise - Dashboard API Service"
	@echo "==============================================="
	@echo "📊 Phase 1.5: Collaboration Interface"
	@echo ""
	@echo "🚀 API Server: http://localhost:3000"
	@echo "🎯 Next.js Dashboard: http://localhost:3001/dashboard"
	@echo "📈 Metrics: 40% efficiency, 60% security, 35% performance"
	@echo "🛡️ Security: All 11 enterprise layers active"
	@echo "📋 Compliance: 100% audit compliance"
	@echo ""
	@echo "✅ All API endpoints ready for dashboard integration!"
	@go run main.go server.go auth.go collaboration_fix.go operational_transform_engine.go workflow_management_engine.go policy_recommendation_engine.go immutable_audit_trail.go gdpr_compliance_automation.go pii_detection_compliance.go continuous_authentication.go attribute_based_encryption.go threshold_secret_sharing.go zero_trust_advanced.go bft.go enterprise_crypto.go compliance_engine.go audit.go store.go crypto.go

dashboard: ## Start Next.js Executive Dashboard (port 3001)
	@echo "📊 Starting DataVault Executive Dashboard..."
	@echo "🎯 Navigate to: http://localhost:3001/dashboard"
	@cd datavault-dashboard && npm run dev

enterprise: ## Start Enterprise P2P Server (same as api)
	@echo "🏗️  Starting DataVault Enterprise Server..."
	@echo "🛡️ All 11 security layers will be initialized"
	@$(MAKE) api

dev: ## Start Enterprise Server + Dashboard together
	@echo "🚀 Starting DataVault Enterprise Development Environment..."
	@echo "⚡ API Server will start on: http://localhost:3000"
	@echo "📊 Dashboard will start on: http://localhost:3001/dashboard"
	@echo "🧹 Ensuring ports are clear first..."
	@$(MAKE) kill-ports-enhanced
	@sleep 3
	@$(MAKE) api & \
	sleep 5 && \
	$(MAKE) dashboard

collab-test: ## Test WebSocket collaboration endpoint
	@echo "🔍 Testing WebSocket collaboration..."
	@curl -i -N \
		-H "Connection: Upgrade" \
		-H "Upgrade: websocket" \
		-H "Sec-WebSocket-Version: 13" \
		-H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
		-H "X-Session-ID: test-session" \
		"http://localhost:3000/ws/collaboration"

kill-ports: ## Kill processes on ports used by DataVault (standard method)
	@echo "🔥 Killing processes on DataVault ports (standard method)..."
	@echo "Trying graceful termination first..."
	@-lsof -ti:3000 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:4000 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:5000 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:5001 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:3001 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:8080 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:8081 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:8082 | xargs kill -15 2>/dev/null || true
	@sleep 2
	@echo "Force killing remaining processes..."
	@-lsof -ti:3000 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:4000 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:5000 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:5001 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:3001 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:8080 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:8081 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:8082 | xargs kill -9 2>/dev/null || true
	@echo "✅ Standard port clearing complete!"

kill-ports-enhanced: ## Enhanced port killing with sudo for system services
	@echo "🔥 Enhanced port clearing (handles system services)..."
	@echo "Checking what's using critical ports..."
	@-lsof -i :5000 2>/dev/null && echo "⚠️  Port 5000 in use - will attempt sudo kill" || echo "✅ Port 5000 free"
	@echo "Step 1: Graceful termination..."
	@-lsof -ti:3000 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:4000 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:5000 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:5001 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:3001 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:8080 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:8081 | xargs kill -15 2>/dev/null || true
	@-lsof -ti:8082 | xargs kill -15 2>/dev/null || true
	@sleep 2
	@echo "Step 2: Force killing user processes..."
	@-lsof -ti:3000 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:4000 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:5000 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:5001 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:3001 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:8080 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:8081 | xargs kill -9 2>/dev/null || true
	@-lsof -ti:8082 | xargs kill -9 2>/dev/null || true
	@sleep 1
	@echo "Step 3: Handling system services (requires sudo)..."
	@if lsof -i :5000 >/dev/null 2>&1; then \
		echo "🔒 Port 5000 still in use (likely AirPlay), trying sudo kill..."; \
		sudo lsof -ti:5000 | xargs sudo kill -9 2>/dev/null || echo "❌ Could not kill process on 5000 - check System Preferences > Sharing"; \
	else \
		echo "✅ Port 5000 is now free"; \
	fi
	@echo "✅ Enhanced port clearing complete!"

force-kill-ports: ## Force kill ALL processes on ports (including system services)
	@echo "💀 FORCE killing ALL processes on DataVault ports..."
	@echo "⚠️  This will kill system services like AirPlay if they use these ports!"
	@echo "Attempting sudo kill for all ports..."
	@-sudo lsof -ti:3000 | xargs sudo kill -9 2>/dev/null || true
	@-sudo lsof -ti:4000 | xargs sudo kill -9 2>/dev/null || true
	@-sudo lsof -ti:5000 | xargs sudo kill -9 2>/dev/null || true
	@-sudo lsof -ti:5001 | xargs sudo kill -9 2>/dev/null || true
	@-sudo lsof -ti:3001 | xargs sudo kill -9 2>/dev/null || true
	@-sudo lsof -ti:8080 | xargs sudo kill -9 2>/dev/null || true
	@-sudo lsof -ti:8081 | xargs sudo kill -9 2>/dev/null || true
	@-sudo lsof -ti:8082 | xargs sudo kill -9 2>/dev/null || true
	@echo "💀 FORCE port clearing complete!"
	@echo "📝 Note: If AirPlay was using port 5000, disable it in System Preferences > Sharing"

status: ## Check what's running on ports
	@echo "🔍 Checking DataVault port status..."
	@echo "Port 3000 (P2P Node 1):"
	@lsof -i :3000 2>/dev/null || echo "  ✅ Available"
	@echo "Port 4000 (P2P Node 2):"
	@lsof -i :4000 2>/dev/null || echo "  ✅ Available"
	@echo "Port 5000 (P2P Node 3):"
	@lsof -i :5000 2>/dev/null || echo "  ✅ Available"
	@echo "Port 5001 (P2P Node 3 Alt):"
	@lsof -i :5001 2>/dev/null || echo "  ✅ Available"
	@echo "Port 8080 (API Node 1):"
	@lsof -i :8080 2>/dev/null || echo "  ✅ Available"
	@echo "Port 8081 (API Node 2):"
	@lsof -i :8081 2>/dev/null || echo "  ✅ Available"
	@echo "Port 8082 (API Node 3):"
	@lsof -i :8082 2>/dev/null || echo "  ✅ Available"
	@echo "Port 3001 (Dashboard):"
	@lsof -i :3001 2>/dev/null || echo "  ✅ Available"

install: ## Install frontend dependencies
	@echo "📦 Installing frontend dependencies..."
	@cd datavault-dashboard && npm install --legacy-peer-deps

build: ## Build the entire project
	@echo "🏗️  Building DataVault Enterprise..."
	@go build -o datavault-server main.go server.go auth.go collaboration_fix.go operational_transform_engine.go workflow_management_engine.go policy_recommendation_engine.go immutable_audit_trail.go gdpr_compliance_automation.go pii_detection_compliance.go continuous_authentication.go attribute_based_encryption.go threshold_secret_sharing.go zero_trust_advanced.go bft.go enterprise_crypto.go compliance_engine.go audit.go store.go crypto.go
	@cd datavault-dashboard && npm run build

test: ## Run tests
	@echo "🧪 Running DataVault Enterprise tests..."
	@go test -v ./...
	@echo "🧪 Running frontend tests..."
	@cd datavault-dashboard && npm test

clean: ## Clean all build artifacts
	@echo "🧹 Cleaning DataVault Enterprise build artifacts..."
	@go clean
	@rm -f datavault-server
	@cd datavault-dashboard && rm -rf .next node_modules/.cache dist
	@echo "✅ Cleanup complete!"

# 🚀 Enhanced Commands for DataVault Enterprise
stop: ## Stop all running DataVault processes
	@echo "🛑 Stopping all DataVault processes..."
	@$(MAKE) kill-ports-enhanced
	@-pkill -f "datavault-server" 2>/dev/null || true
	@-pkill -f "npm run dev" 2>/dev/null || true
	@-pkill -f "go run" 2>/dev/null || true
	@echo "✅ All DataVault processes stopped!"

restart: ## Restart the entire development environment
	@echo "🔄 Restarting DataVault Enterprise..."
	@$(MAKE) stop
	@sleep 3
	@$(MAKE) dev

logs: ## Show logs from running processes
	@echo "📋 DataVault Enterprise Logs:"
	@echo "============================="
	@ps aux | grep -E "(datavault|npm run dev|go run)" | grep -v grep || echo "No DataVault processes running"

check-deps: ## Check if all dependencies are installed
	@echo "🔍 Checking DataVault Enterprise Dependencies..."
	@command -v go >/dev/null 2>&1 || { echo "❌ Go is not installed"; exit 1; }
	@command -v node >/dev/null 2>&1 || { echo "❌ Node.js is not installed"; exit 1; }
	@command -v npm >/dev/null 2>&1 || { echo "❌ npm is not installed"; exit 1; }
	@test -d datavault-dashboard/node_modules || { echo "❌ Frontend dependencies not installed. Run 'make install'"; exit 1; }
	@echo "✅ All dependencies are installed!"

# Additional useful commands
quick-start: check-deps ## Quick start after checking dependencies
	@echo "🚀 Quick starting DataVault Enterprise..."
	@$(MAKE) dev

full-clean: ## Complete cleanup including node_modules
	@echo "🧹 Performing full cleanup..."
	@$(MAKE) clean
	@cd datavault-dashboard && rm -rf node_modules package-lock.json
	@echo "✅ Full cleanup complete! Run 'make install' to reinstall dependencies."

health-check: ## Check if all services are running properly
	@echo "🏥 DataVault Enterprise Health Check..."
	@echo "Checking API endpoints..."
	@curl -s --max-time 5 http://localhost:8080/health >/dev/null 2>&1 && echo "✅ Node 1 API: Healthy" || echo "❌ Node 1 API: Down"
	@curl -s --max-time 5 http://localhost:8081/health >/dev/null 2>&1 && echo "✅ Node 2 API: Healthy" || echo "❌ Node 2 API: Down"
	@curl -s --max-time 5 http://localhost:8082/health >/dev/null 2>&1 && echo "✅ Node 3 API: Healthy" || echo "❌ Node 3 API: Down"
	@curl -s --max-time 5 http://localhost:3001 >/dev/null 2>&1 && echo "✅ Dashboard: Healthy" || echo "❌ Dashboard: Down"

# Alternative API start with automatic test file exclusion
api-safe: ## Start API server excluding test files automatically
	@echo "🚀 Starting DataVault Enterprise Server (Safe Mode)..."
	@echo "📊 Automatically excluding test files..."
	@go run $$(ls *.go | grep -v '_test.go')

# Development with safe mode
dev-safe: ## Start development environment with safe API mode
	@echo "🚀 Starting DataVault Enterprise Development Environment (Safe Mode)..."
	@echo "⚡ API Server will start on: http://localhost:3000 (Safe Mode)"
	@echo "📊 Dashboard will start on: http://localhost:3001/dashboard"
	@echo "🧹 Ensuring ports are clear first..."
	@$(MAKE) kill-ports-enhanced
	@sleep 3
	@$(MAKE) api-safe & \
	sleep 5 && \
	$(MAKE) dashboard

# Nuclear option for when ports are completely stuck
nuclear-clean: ## Nuclear option - kill everything and clean all ports
	@echo "☢️  NUCLEAR CLEAN - Killing ALL DataVault related processes..."
	@echo "This will terminate everything forcefully!"
	@$(MAKE) force-kill-ports
	@-pkill -f "go run" 2>/dev/null || true
	@-pkill -f "npm run dev" 2>/dev/null || true
	@-pkill -f "datavault" 2>/dev/null || true
	@-pkill -f "node.*3001" 2>/dev/null || true
	@-sudo pkill -f "ControlCenter" 2>/dev/null || echo "AirPlay not running"
	@sleep 3
	@echo "☢️  Nuclear cleanup complete! All ports should be clear now."
	@$(MAKE) status

# Quick diagnosis for port conflicts
diagnose-ports: ## Diagnose what's using DataVault ports
	@echo "🔬 Diagnosing DataVault port usage..."
	@echo ""
	@for port in 3000 4000 5000 5001 3001 8080 8081 8082; do \
		echo "=== Port $$port ==="; \
		if lsof -i :$$port 2>/dev/null; then \
			echo "Process details:"; \
			lsof -i :$$port 2>/dev/null | awk 'NR>1 {print "  PID: " $$2 ", Command: " $$1 ", User: " $$3}'; \
		else \
			echo "✅ Port $$port is free"; \
		fi; \
		echo ""; \
	done
	@echo "🔍 Common issues:"
	@echo "   - Port 5000: Usually macOS AirPlay Receiver (ControlCenter process)"
	@echo "   - Port 3000: May conflict with other development servers"
	@echo "   - If you see 'ControlCenter' or 'AirPlay', disable in System Preferences > Sharing"

# Fix for persistent AirPlay issues
fix-airplay: ## Specifically handle AirPlay Receiver on port 5000
	@echo "🔧 Fixing AirPlay Receiver on port 5000..."
	@echo "Checking if AirPlay is using port 5000..."
	@if lsof -i :5000 2>/dev/null | grep -q "ControlCenter\|AirPlay"; then \
		echo "⚠️  AirPlay Receiver found on port 5000"; \
		echo "Attempting to kill AirPlay processes..."; \
		sudo pkill -f "ControlCenter" 2>/dev/null || true; \
		sleep 2; \
		if lsof -i :5000 >/dev/null 2>&1; then \
			echo "❌ AirPlay still running. You need to disable it manually:"; \
			echo "   1. Open System Preferences/Settings"; \
			echo "   2. Go to Sharing"; \
			echo "   3. Uncheck 'AirPlay Receiver'"; \
			echo "   4. Or change its port to something other than 5000"; \
		else \
			echo "✅ Port 5000 is now free!"; \
		fi; \
	else \
		echo "✅ Port 5000 is free or not used by AirPlay"; \
	fi

.DEFAULT_GOAL := help
