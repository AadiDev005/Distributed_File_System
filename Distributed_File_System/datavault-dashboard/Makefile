.PHONY: dashboard-api enterprise-server frontend clean help

# DataVault Enterprise Development Commands

help: ## Show this help message
	@echo "🏆 DataVault Enterprise - Development Commands"
	@echo "=============================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

dashboard-api: ## Start the Dashboard API server (port 3000)
	@echo "🚀 Starting DataVault Dashboard API Server..."
	@cd api/dashboard && go run server.go

enterprise-server: ## Start the main Enterprise server
	@echo "🏗️  Starting DataVault Enterprise Server..."
	@go run main.go

frontend: ## Start the Next.js frontend (port 3001)
	@echo "📊 Starting DataVault Executive Dashboard..."
	@cd datavault-dashboard && npm run dev

dev: ## Start both API server and frontend
	@echo "🚀 Starting DataVault Enterprise Development Environment..."
	@make dashboard-api &
	@sleep 2
	@make frontend

clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	@go clean
	@cd datavault-dashboard && npm run build

install: ## Install frontend dependencies
	@echo "📦 Installing frontend dependencies..."
	@cd datavault-dashboard && npm install

build: ## Build the entire project
	@echo "🏗️  Building DataVault Enterprise..."
	@go build .
	@cd datavault-dashboard && npm run build

test: ## Run tests
	@echo "🧪 Running tests..."
	@go test ./...
	@cd datavault-dashboard && npm test

.DEFAULT_GOAL := help
