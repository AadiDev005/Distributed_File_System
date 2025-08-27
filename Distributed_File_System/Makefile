.PHONY: \
  api dashboard enterprise clean help install dev collab-test kill-ports \
  status build test stop restart logs check-deps quick-start full-clean \
  health-check api-safe dev-safe force-kill-ports nuclear-clean \
  diagnose-ports dashboard-api main-server fix-airplay clean-storage \
  dev-clean test-files test-upload test-delete test-view test-share \
  install-cors deps workflow-test enterprise-test bft-test quantum-test \
  compliance-test pii-test gdpr-test security-test prod-deploy \
  benchmark load-test integration-test e2e-test collaboration-test

# 🏆 DataVault Enterprise v1.5 - Complete Development Commands
# ============================================================

help: ## Show this help message
	@echo "🏆 DataVault Enterprise v1.5 - Complete Development Commands"
	@echo "========================================================="
	@echo "✅ Phase 2.0: Enhanced File Operations & Enterprise Security"
	@echo "🚀 All 58+ API endpoints operational with workflow management"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

#───────────────────────────────
# Dependencies & Installation
#───────────────────────────────

install-cors: ## Install CORS dependency for Go backend
	@echo "🔧 Installing CORS dependency..."
	@go get github.com/rs/cors
	@go mod tidy
	@echo "✅ CORS dependency installed"

deps: install-cors ## Install all dependencies (Go + Node.js)
	@echo "📦 Installing all DataVault Enterprise dependencies..."
	@$(MAKE) install-cors
	@cd datavault-dashboard && npm install
	@echo "✅ All dependencies installed"

install: deps ## Install frontend dependencies (includes CORS)

#───────────────────────────────
# Core Servers
#───────────────────────────────

dashboard-api: ## Start Dashboard API Server (port 3000)
	@echo "🚀 Starting DataVault Dashboard API Server..."
	@cd datavault-dashboard/api/dashboard && go run server.go

main-server: ## Start Main DataVault Enterprise Server (ports 8080-8082) with all features
	@echo "🏗️  Starting DataVault Enterprise Main Server with full security stack..."
	@echo "📋 Loading: BFT + Quantum + Zero-Trust + Workflows + Collaboration..."
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
	@echo "🎨 Enhanced with real-time monitoring and workflow management"
	@cd datavault-dashboard && npm run dev

enterprise: main-server ## Alias for enterprise server

#───────────────────────────────
# Enhanced Development Workflows
#───────────────────────────────

dev: ## Start Complete DataVault Enterprise Stack (recommended)
	@echo "🚀 Starting Complete DataVault Enterprise Development Environment..."
	@echo "🔧 v1.5: Full enterprise security + workflow management"
	@$(MAKE) check-deps
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
	@echo "⚡ DataVault Enterprise Quick Start..."
	@$(MAKE) deps
	@$(MAKE) clean-storage
	@$(MAKE) dev

#───────────────────────────────
# Enterprise Feature Testing
#───────────────────────────────

workflow-test: ## Test complete workflow management system
	@echo "📋 Testing DataVault Workflow Management System..."
	@echo "🔍 Testing workflow status..."
	@curl -s http://localhost:8080/api/workflow/status | jq '.' || echo "❌ Workflow status failed"
	@echo "📝 Testing workflow templates..."
	@curl -s http://localhost:8080/api/workflow/templates | jq '.templates | length' | xargs echo "Templates found:"
	@echo "🚀 Testing workflow start..."
	@curl -s -X POST -H "Content-Type: application/json" \
		-d '{"workflow_id":"template_001","user_id":"test","variables":{"test":true}}' \
		http://localhost:8080/api/workflow/start | jq '.success' || echo "❌ Workflow start failed"

enterprise-test: ## Test all enterprise security features
	@echo "🔒 Testing DataVault Enterprise Security Features..."
	@echo "1. BFT Consensus:"
	@curl -s http://localhost:8080/api/bft-status | jq '.status' || echo "❌ BFT failed"
	@echo "2. Post-Quantum Cryptography:"
	@curl -s http://localhost:8080/api/quantum-status | jq '.data.quantum_resistant' || echo "❌ Quantum failed"
	@echo "3. Dynamic Sharding:"
	@curl -s http://localhost:8080/api/sharding-status | jq '.data.active_shards' || echo "❌ Sharding failed"
	@echo "4. Zero-Trust Gateway:"
	@curl -s http://localhost:8080/api/zero-trust/status | jq '.data.zero_trust_enabled' || echo "❌ Zero-Trust failed"

compliance-test: ## Test compliance and audit features
	@echo "📋 Testing DataVault Compliance System..."
	@echo "1. GDPR Compliance:"
	@curl -s http://localhost:8080/api/compliance/gdpr | jq '.data.complianceScore' || echo "❌ GDPR failed"
	@echo "2. PII Detection:"
	@curl -s http://localhost:8080/api/compliance/pii-scan | jq '.data.detection_accuracy' || echo "❌ PII failed"
	@echo "3. Audit Trail:"
	@curl -s http://localhost:8080/api/compliance/audit-trail | jq '.data.integrity' || echo "❌ Audit failed"

collaboration-test: ## Test real-time collaboration features
	@echo "🤝 Testing DataVault Collaboration System..."
	@curl -s http://localhost:8080/api/collaboration/health | jq '.status' || echo "❌ Collaboration health failed"
	@curl -s http://localhost:8080/api/collaboration/documents | jq '.success' || echo "❌ Documents failed"

security-test: ## Comprehensive security feature testing
	@echo "🛡️  Comprehensive Security Test Suite..."
	@$(MAKE) enterprise-test
	@$(MAKE) compliance-test
	@echo "5. Policy Recommendations:"
	@curl -s http://localhost:8080/api/policy/recommendations | jq '.data.summary.totalRecommendations' || echo "❌ Policy failed"
	@echo "6. Blockchain Audit:"
	@curl -s http://localhost:8080/api/audit/blockchain | jq '.data.chainStats.totalBlocks' || echo "❌ Blockchain failed"

#───────────────────────────────
# Enhanced File Testing
#───────────────────────────────

test-files: ## Test complete file operations workflow with enterprise features
	@echo "🧪 Testing DataVault Enterprise File Operations..."
	@echo "📋 Testing: upload → list → view → share → delete → workflow"
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
	@$(MAKE) workflow-test

test-upload: ## Test file upload functionality
	@echo "📤 Testing enterprise file upload..."
	@echo "DataVault Enterprise v1.5 Test File with BFT+Quantum+ZeroTrust" > test_enterprise.txt
	@curl -s -X POST \
		-F "files=@test_enterprise.txt" \
		http://localhost:8080/api/files/upload \
		2>/dev/null | jq '.security_applied' || echo "❌ Upload test failed"
	@rm -f test_enterprise.txt

test-list: ## Test file listing
	@echo "📁 Testing enterprise file list..."
	@curl -s http://localhost:8080/api/files/list 2>/dev/null | \
		jq '.files | length' | xargs echo "Files found:" || echo "❌ List test failed"

test-view: ## Test file viewing (first file)
	@echo "👁️  Testing enterprise file view..."
	@curl -s "http://localhost:8080/api/files/view?id=test_enterprise.txt" \
		2>/dev/null | head -1 || echo "❌ View test failed"

test-share: ## Test file sharing with enterprise security
	@echo "🔗 Testing enterprise file sharing..."
	@curl -s -X POST \
		-H "Content-Type: application/json" \
		-d '{"fileId":"test_enterprise.txt","public":false,"expiresIn":"1h"}' \
		http://localhost:8080/api/files/share \
		2>/dev/null | jq '.success' || echo "❌ Share test failed"

test-delete: ## Test file deletion
	@echo "🗑️  Testing enterprise file deletion..."
	@curl -s -X DELETE "http://localhost:8080/api/files/delete?id=test_enterprise.txt" \
		2>/dev/null | jq '.success' || echo "❌ Delete test failed"

#───────────────────────────────
# Performance & Load Testing
#───────────────────────────────

benchmark: ## Run performance benchmarks
	@echo "⚡ Running DataVault Enterprise Benchmarks..."
	@echo "🔍 Testing API response times..."
	@time curl -s http://localhost:8080/api/health > /dev/null
	@echo "🔍 Testing enterprise features response times..."
	@time curl -s http://localhost:8080/api/bft-status > /dev/null
	@time curl -s http://localhost:8080/api/quantum-status > /dev/null

load-test: ## Basic load testing (requires Apache Bench)
	@echo "🏋️  Running basic load test..."
	@echo "Testing 100 concurrent requests..."
	@ab -n 100 -c 10 http://localhost:8080/api/health || echo "❌ Install apache2-utils for load testing"

integration-test: ## Complete integration test suite
	@echo "🔗 Running DataVault Enterprise Integration Tests..."
	@$(MAKE) security-test
	@$(MAKE) workflow-test
	@$(MAKE) collaboration-test
	@$(MAKE) test-files

#───────────────────────────────
# Enhanced Cleaning & Storage
#───────────────────────────────

clean-storage: ## Wipe storage and reset enterprise data
	@echo "🧹 Cleaning DataVault Enterprise storage..."
	@mkdir -p ./storage/shared ./logs ./tmp
	@rm -rf ./storage/shared/* || true
	@rm -rf ./storage/temp ./storage/cache ./logs/temp || true
	@echo "✅ Enterprise storage cleaned (ready for fresh data)"

clean: ## Clean build artifacts (keeps node_modules & storage)
	@echo "🧹 Cleaning DataVault Enterprise build artifacts..."
	@go clean
	@rm -f datavault-server datavault-enterprise datavault.pid *.log
	@cd datavault-dashboard/api/dashboard && rm -f dashboard-server
	@cd datavault-dashboard && rm -rf .next node_modules/.cache dist
	@rm -rf ./tmp ./logs/temp ./storage/temp
	@echo "✅ Enterprise cleanup complete"

#───────────────────────────────
# Enhanced Port Management
#───────────────────────────────

kill-ports-enhanced: ## Enhanced port killing with enterprise process cleanup
	@echo "🔌 Enhanced DataVault Enterprise port cleanup..."
	@-pkill -f "go run.*main.go" 2>/dev/null || true
	@-pkill -f "go run.*server.go" 2>/dev/null || true
	@-pkill -f "npm run dev" 2>/dev/null || true
	@-pkill -f "datavault-enterprise" 2>/dev/null || true
	@-lsof -ti :3000,3001,8080,8081,8082,9000,9001,9002 | xargs kill -9 2>/dev/null || true
	@$(MAKE) fix-airplay
	@sleep 2
	@echo "✅ Enterprise ports cleaned"

kill-ports: kill-ports-enhanced ## Alias for enhanced port killing

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
# Installation & Dependencies
#───────────────────────────────

check-deps: ## Verify toolchain & create directories
	@echo "🔍 Checking DataVault Enterprise dependencies..."
	@command -v go >/dev/null 2>&1 || { echo "❌ Go not installed"; exit 1; }
	@command -v node >/dev/null 2>&1 || { echo "❌ Node.js not installed"; exit 1; }
	@command -v npm >/dev/null 2>&1 || { echo "❌ npm not installed"; exit 1; }
	@mkdir -p ./storage/shared ./logs ./tmp
	@echo "✅ Enterprise dependencies verified, directories created"
	@$(MAKE) install-cors

#───────────────────────────────
# Build & Test Commands
#───────────────────────────────

build: ## Build all components with full enterprise features
	@echo "🏗️  Building DataVault Enterprise v1.5..."
	@$(MAKE) install-cors
	@go build -ldflags "-s -w" -o datavault-enterprise \
		main.go server.go auth.go collaboration_fix.go workflow_management_engine.go
	@cd datavault-dashboard && npm run build
	@cd datavault-dashboard/api/dashboard && go build -o dashboard-server server.go
	@echo "✅ Enterprise build complete"

test: ## Run Go tests
	@echo "🧪 Running DataVault Enterprise tests..."
	@go test ./...

#───────────────────────────────
# Process Management
#───────────────────────────────

status: ## Show comprehensive DataVault process status
	@echo "📊 DataVault Enterprise v1.5 Status"
	@echo "=================================="
	@ps aux | grep -E "(go run.*main|npm run dev|dashboard)" | grep -v grep || echo "No processes running"
	@echo ""
	@echo "Port Status:"
	@$(MAKE) diagnose-ports

stop: ## Kill all DataVault processes
	@echo "🛑 Stopping DataVault Enterprise..."
	@$(MAKE) kill-ports-enhanced
	@echo "✅ All enterprise processes stopped"

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
# Health & Monitoring
#───────────────────────────────

health-check: ## Comprehensive enterprise health check
	@echo "🏥 DataVault Enterprise v1.5 Health Check"
	@echo "========================================"
	@echo "API Server (port 3000):"
	@curl -s http://localhost:3000/health | jq '.status' 2>/dev/null || echo "  ❌ Not responding"
	@echo "Main Server (port 8080):"
	@curl -s http://localhost:8080/api/health | jq '.status' 2>/dev/null || echo "  ❌ Not responding"
	@echo "Dashboard (port 3001):"
	@curl -s -I http://localhost:3001 2>/dev/null | head -1 || echo "  ❌ Not responding"
	@echo "Enterprise Features:"
	@curl -s http://localhost:8080/api/bft-status | jq '.status' 2>/dev/null | xargs echo "  BFT:" || echo "  BFT: ❌"
	@curl -s http://localhost:8080/api/quantum-status | jq '.status' 2>/dev/null | xargs echo "  Quantum:" || echo "  Quantum: ❌"
	@curl -s http://localhost:8080/api/workflow/status | jq '.status' 2>/dev/null | xargs echo "  Workflow:" || echo "  Workflow: ❌"
	@echo "Storage:"
	@ls -la ./storage/shared/ 2>/dev/null | tail -3 || echo "  ❌ Storage not accessible"

#───────────────────────────────
# Utility Commands
#───────────────────────────────

demo: ## Start with enterprise demo content
	@echo "🎬 Starting DataVault Enterprise Demo..."
	@$(MAKE) clean-storage
	@$(MAKE) dev

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
	@rm -rf ./storage go.sum
	@echo "✅ Full cleanup complete! Run 'make install' afterwards."

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

force-kill-ports: ## Force kill ALL processes on DataVault ports
	@echo "💥 Force killing ALL processes on DataVault ports..."
	@-sudo lsof -ti :3000,3001,5000,8080,8081,8082,9000,9001,9002 | xargs sudo kill -9 2>/dev/null || true
	@-sudo pkill -9 -f "DataVault\|datavault\|go run.*main.go\|npm run dev" 2>/dev/null || true
	@echo "✅ All ports force-cleared"

.DEFAULT_GOAL := help
