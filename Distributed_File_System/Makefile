.PHONY: api dashboard enterprise clean help install dev

# 🏆 DataVault Enterprise - Development Commands
# ===============================================

help: ## Show this help message
	@echo "🏆 DataVault Enterprise - Development Commands"
	@echo "=============================================="
	@echo "Phase 1.4: Executive Dashboard Implementation"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

api: ## Start Dashboard API Server (port 3000)
	@echo "🚀 Starting DataVault Dashboard API Server..."
	@echo "📊 Serving enterprise metrics and security status"
	@cd services/dashboard-api && go run main.go

dashboard: ## Start Next.js Executive Dashboard (port 3001)
	@echo "📊 Starting DataVault Executive Dashboard..."
	@echo "🎯 Navigate to: http://localhost:3001/dashboard"
	@cd datavault-dashboard && npm run dev

enterprise: ## Start Enterprise P2P Server (your main.go)
	@echo "🏗️  Starting DataVault Enterprise Server..."
	@echo "🛡️ All 11 security layers will be initialized"
	@go run main.go

dev: ## Start API + Dashboard together
	@echo "🚀 Starting DataVault Enterprise Development Environment..."
	@echo "⚡ API Server will start on: http://localhost:3000"
	@echo "📊 Dashboard will start on: http://localhost:3001/dashboard"
	@make api &
	@sleep 3
	@make dashboard

kill-ports: ## Kill processes on ports 3000 and 3001
	@echo "🔥 Killing processes on ports 3000 and 3001..."
	@-sudo kill -9 $$(lsof -t -i:3000) 2>/dev/null || true
	@-sudo kill -9 $$(lsof -t -i:3001) 2>/dev/null || true
	@echo "✅ Ports cleared!"

status: ## Check what's running on ports
	@echo "🔍 Checking port status..."
	@echo "Port 3000:"
	@lsof -i :3000 || echo "  - Available"
	@echo "Port 3001:"
	@lsof -i :3001 || echo "  - Available"

clean: ## Clean all build artifacts
	@echo "🧹 Cleaning DataVault Enterprise build artifacts..."
	@go clean
	@cd datavault-dashboard && rm -rf .next node_modules/.cache
	@echo "✅ Cleanup complete!"

.DEFAULT_GOAL := help
