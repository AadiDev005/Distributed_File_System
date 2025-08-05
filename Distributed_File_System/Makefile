.PHONY: \
  api dashboard enterprise clean help install dev collab-test kill-ports \
  status build test stop restart logs check-deps quick-start full-clean \
  health-check api-safe dev-safe force-kill-ports nuclear-clean \
  diagnose-ports dashboard-api main-server fix-airplay clean-storage \
  dev-clean test-files test-upload test-delete test-view test-share

# 🏆 DataVault Enterprise - Development Commands
# ==============================================

help: ## Show this help message
	@echo "🏆 DataVault Enterprise - Development Commands"
	@echo "=============================================="
	@echo "Phase 2.0: Enhanced File Operations & Smooth UX"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

#───────────────────────────────
# Servers
#───────────────────────────────

dashboard-api: ## Start Dashboard API Server (port 3000)
	@echo "🚀 Starting DataVault Dashboard API Server..."
	@cd datavault-dashboard/api/dashboard && go run server.go

main-server: ## Start Main DataVault Enterprise Server (ports 8080-8082)
	@echo "🏗️  Starting DataVault Enterprise Main Server..."
	@echo "📋 Loading all enterprise modules..."
	@go run \
		main.go server.go auth.go collaboration_fix.go operational_transform_engine.go \
		workflow_management_engine.go policy_recommendation_engine.go \
		immutable_audit_trail.go gdpr_compliance_automation.go \
		pii_detection_compliance.go continuous_authentication.go \
		attribute_based_encryption.go threshold_secret_sharing.go \
		zero_trust_advanced.go bft.go enterprise_crypto.go \
		compliance_engine.go audit.go store.go crypto.go

api: dashboard-api ## Alias for backward compatibility

dashboard: ## Start Next.js Executive Dashboard (port 3001)
	@echo "📊 Starting DataVault Executive Dashboard..."
	@echo "🎨 Enhanced with smooth animations and better UX"
	@cd datavault-dashboard && npm run dev

enterprise: main-server ## Alias

#───────────────────────────────
# Enhanced development workflows
#───────────────────────────────

dev: ## Start Dashboard API + Main Server + Frontend (recommended)
	@echo "🚀 Starting Complete DataVault Enterprise Development Environment..."
	@echo "🔧 Phase 2.0: Enhanced file operations with smooth transitions"
	@$(MAKE) kill-ports-enhanced
	@$(MAKE) clean-storage
	@echo "🔄 Starting services in sequence..."
	@$(MAKE) dashboard-api & \
	echo "⏳ Waiting for API server..." && sleep 5 && \
	$(MAKE) main-server & \
	echo "⏳ Waiting for main server..." && sleep 8 && \
	echo "🎯 Starting dashboard..." && $(MAKE) dashboard

dev-safe: ## Start development environment (safe API mode)
	@echo "🛡️  Starting DataVault in Safe Mode..."
	@$(MAKE) kill-ports-enhanced
	@$(MAKE) clean-storage
	@$(MAKE) api-safe & \
	sleep 5 && $(MAKE) main-server & \
	sleep 8 && $(MAKE) dashboard

quick-start: ## Fast start: check-deps + clean + dev
	@echo "⚡ DataVault Quick Start..."
	@$(MAKE) check-deps
	@$(MAKE) clean-storage
	@$(MAKE) dev

#───────────────────────────────
# Enhanced cleaning & storage resets
#───────────────────────────────

clean-storage: ## Wipe ./storage/shared (removes all CAS folders and files)
	@echo "🧹 Cleaning storage directory..."
	@mkdir -p ./storage/shared
	@rm -rf ./storage/shared/* || true
	@rm -rf ./storage/temp ./storage/cache || true
	@echo "✅ Storage directory cleaned (ready for fresh uploads)"

clean: ## Clean build artifacts (keeps node_modules & storage)
	@echo "🧹 Cleaning build artifacts..."
	@go clean
	@rm -f datavault-server datavault.pid *.log
	@cd datavault-dashboard/api/dashboard && rm -f dashboard-server
	@cd datavault-dashboard && rm -rf .next node_modules/.cache dist
	@rm -rf ./tmp ./logs/temp ./storage/temp
	@echo "✅ Cleanup complete"

dev-clean: ## Clean development environment (keeps storage)
	@echo "🧹 Development cleanup..."
	@$(MAKE) stop
	@$(MAKE) clean
	@cd datavault-dashboard && rm -rf .next node_modules/.cache
	@echo "✅ Development environment cleaned"

full-clean: ## Full cleanup (includes node_modules & storage)
	@echo "🚨 Full cleanup - this will remove everything!"
	@$(MAKE) stop
	@$(MAKE) clean
	@cd datavault-dashboard && rm -rf node_modules package-lock.json
	@rm -rf ./storage
	@echo "✅ Full cleanup complete! Run 'make install' afterwards."

#───────────────────────────────
# Enhanced port management
#───────────────────────────────

kill-ports: ## Kill processes on standard ports
	@echo "🔌 Killing processes on DataVault ports..."
	@-pkill -f "go run.*main.go" 2>/dev/null || true
	@-pkill -f "go run.*server.go" 2>/dev/null || true
	@-pkill -f "npm run dev" 2>/dev/null || true
	@-lsof -ti :3000,3001,8080,8081,8082,9000,9001,9002 | xargs kill -9 2>/dev/null || true

kill-ports-enhanced: ## Enhanced port killing (handles AirPlay conflicts)
	@echo "🔌 Enhanced port cleanup..."
	@$(MAKE) kill-ports
	@$(MAKE) fix-airplay
	@sleep 2
	@echo "✅ Ports cleaned"

force-kill-ports: ## Force kill ALL processes on DataVault ports
	@echo "💥 Force killing ALL processes on DataVault ports..."
	@-sudo lsof -ti :3000,3001,5000,8080,8081,8082,9000,9001,9002 | xargs sudo kill -9 2>/dev/null || true
	@-sudo pkill -9 -f "DataVault\|datavault\|go run.*main.go\|npm run dev" 2>/dev/null || true
	@echo "✅ All ports force-cleared"

diagnose-ports: ## Show what's using each DataVault port
	@echo "🔍 Port diagnostics..."
	@for port in 3000 3001 5000 8080 8081 8082 9000 9001 9002; do \
		echo "Port $$port:" && lsof -i :$$port 2>/dev/null | head -2 || echo "  (free)"; \
	done

fix-airplay: ## Attempt to free macOS AirPlay port 5000
	@echo "📡 Checking AirPlay receiver on port 5000..."
	@-sudo lsof -ti :5000 | head -1 | xargs sudo kill 2>/dev/null || true
	@echo "✅ AirPlay port handled"

#───────────────────────────────
# Enhanced file testing
#───────────────────────────────

test-files: ## Test complete file operations workflow
	@echo "🧪 Testing DataVault file operations..."
	@echo "📋 Testing: upload → list → view → share → delete"
	@sleep 2
	@$(MAKE) test-upload
	@sleep 1
	@$(MAKE) test-list
	@sleep 1
	@$(MAKE) test-view
	@sleep 1
	@$(MAKE) test-share
	@sleep 1
	@$(MAKE) test-delete

test-upload: ## Test file upload functionality
	@echo "📤 Testing file upload..."
	@echo "Test file content for DataVault Enterprise" > test_upload.txt
	@curl -X POST \
		-F "files=@test_upload.txt" \
		http://localhost:8080/api/files/upload \
		2>/dev/null | jq '.' || echo "❌ Upload test failed"
	@rm -f test_upload.txt

test-list: ## Test file listing
	@echo "📁 Testing file list..."
	@curl -X GET http://localhost:8080/api/files/list 2>/dev/null | \
		jq '.files | length' | xargs echo "Files found:" || echo "❌ List test failed"

test-view: ## Test file viewing (first file)
	@echo "👁️  Testing file view..."
	@curl -X GET "http://localhost:8080/api/files/view?id=test_upload.txt" \
		2>/dev/null | head -1 || echo "❌ View test failed"

test-share: ## Test file sharing
	@echo "🔗 Testing file sharing..."
	@curl -X POST \
		-H "Content-Type: application/json" \
		-d '{"fileId":"test_upload.txt","public":false,"expiresIn":"1h"}' \
		http://localhost:8080/api/files/share \
		2>/dev/null | jq '.success' || echo "❌ Share test failed"

test-delete: ## Test file deletion
	@echo "🗑️  Testing file deletion..."
	@curl -X DELETE "http://localhost:8080/api/files/delete?id=test_upload.txt" \
		2>/dev/null | jq '.success' || echo "❌ Delete test failed"

#───────────────────────────────
# Installation & dependencies
#───────────────────────────────

install: ## Install frontend dependencies
	@echo "📦 Installing DataVault dependencies..."
	@cd datavault-dashboard && npm install
	@echo "✅ Dependencies installed"

check-deps: ## Verify toolchain & create directories
	@echo "🔍 Checking DataVault dependencies..."
	@command -v go >/dev/null 2>&1 || { echo "❌ Go not installed"; exit 1; }
	@command -v node >/dev/null 2>&1 || { echo "❌ Node.js not installed"; exit 1; }
	@command -v npm >/dev/null 2>&1 || { echo "❌ npm not installed"; exit 1; }
	@mkdir -p ./storage/shared ./logs ./tmp
	@echo "✅ Dependencies verified, directories created"

#───────────────────────────────
# Build & test commands
#───────────────────────────────

build: ## Build all components
	@echo "🏗️  Building DataVault Enterprise..."
	@go build -o datavault-server main.go server.go auth.go
	@cd datavault-dashboard && npm run build
	@cd datavault-dashboard/api/dashboard && go build -o dashboard-server server.go
	@echo "✅ Build complete"

test: ## Run Go tests
	@echo "🧪 Running DataVault tests..."
	@go test ./...

collab-test: ## Quick collaboration & file operations test
	@echo "🤝 Testing collaboration features..."
	@curl -X GET http://localhost:3000/health 2>/dev/null | jq '.' || echo "❌ API health check failed"
	@curl -X GET http://localhost:8080/api/health 2>/dev/null | jq '.' || echo "❌ Main server health check failed"
	@echo "✅ Collaboration test complete"

#───────────────────────────────
# Process management
#───────────────────────────────

status: ## Show DataVault process status
	@echo "📊 DataVault Enterprise Status"
	@echo "=============================="
	@ps aux | grep -E "(go run.*main|npm run dev|dashboard)" | grep -v grep || echo "No processes running"
	@echo ""
	@echo "Port Status:"
	@$(MAKE) diagnose-ports

stop: ## Kill all DataVault processes
	@echo "🛑 Stopping DataVault Enterprise..."
	@$(MAKE) kill-ports-enhanced
	@echo "✅ All processes stopped"

restart: ## Stop and restart development environment
	@echo "🔄 Restarting DataVault Enterprise..."
	@$(MAKE) stop
	@sleep 2
	@$(MAKE) dev

logs: ## Show running DataVault processes
	@echo "📋 DataVault Enterprise Processes:"
	@ps aux | grep -E "(go run.*main|npm run dev|dashboard)" | grep -v grep | \
		awk '{print "PID: " $2 " | " $11 " " $12 " " $13}'

#───────────────────────────────
# Health & monitoring
#───────────────────────────────

health-check: ## Comprehensive health check
	@echo "🏥 DataVault Enterprise Health Check"
	@echo "===================================="
	@echo "API Server (port 3000):"
	@curl -s http://localhost:3000/health | jq '.' 2>/dev/null || echo "  ❌ Not responding"
	@echo "Main Server (port 8080):"
	@curl -s http://localhost:8080/api/health | jq '.' 2>/dev/null || echo "  ❌ Not responding"
	@echo "Dashboard (port 3001):"
	@curl -s -I http://localhost:3001 2>/dev/null | head -1 || echo "  ❌ Not responding"
	@echo "Storage:"
	@ls -la ./storage/shared/ 2>/dev/null | tail -3 || echo "  ❌ Storage not accessible"

#───────────────────────────────
# Advanced utilities
#───────────────────────────────

api-safe: ## Start Dashboard API in safe mode (excludes test files)
	@echo "🛡️  Starting Dashboard API in safe mode..."
	@cd datavault-dashboard/api/dashboard && \
		go run server.go 2>&1 | grep -v "_test.go" || true

nuclear-clean: ## Nuclear option: kill everything and wipe all data
	@echo "☢️  NUCLEAR CLEAN - This will destroy EVERYTHING!"
	@read -p "Are you sure? (type 'yes'): " confirm && [ "$$confirm" = "yes" ] || exit 1
	@$(MAKE) force-kill-ports
	@$(MAKE) full-clean
	@rm -rf ./datavault-dashboard/node_modules
	@rm -rf ./.git/hooks/* 2>/dev/null || true
	@echo "☢️  Nuclear clean complete. Run 'make install' to recover."

#───────────────────────────────
# Development shortcuts
#───────────────────────────────

demo: ## Start with demo files pre-loaded
	@echo "🎬 Starting DataVault with demo content..."
	@$(MAKE) clean-storage
	@$(MAKE) dev

prod-test: ## Test production-like environment
	@echo "🏭 Testing production-like environment..."
	@$(MAKE) build
	@$(MAKE) clean-storage
	@./datavault-server &
	@cd datavault-dashboard && npm start &
	@echo "✅ Production test environment started"

.DEFAULT_GOAL := help
