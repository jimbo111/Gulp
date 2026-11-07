# Gulp — single entry point for build/test/dev (see docs/02-build-and-dev-setup.md §3).
# macOS targets need Xcode; *-core, lint, vulnlab and beacon also work on Linux.

KIT       := Packages/GulpKit
BEACON    := Beacon
SCHEME    := Gulp
DD        := .build/xcode
CONFIG    := Debug
DEST      := platform=macOS

.DEFAULT_GOAL := help

.PHONY: help bootstrap generate build run test test-core perf lint format vulnlab beacon release clean

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n",$$1,$$2}'

bootstrap: ## Install brew tools and resolve SwiftPM packages
	@command -v brew >/dev/null && brew bundle || echo "note: Homebrew not found (expected off macOS); skipping brew bundle"
	swift package --package-path $(KIT) resolve
	swift package --package-path $(BEACON) resolve

generate: ## Generate Gulp.xcodeproj from project.yml (macOS)
	xcodegen generate

build: generate ## Build the macOS app (Debug)
	xcodebuild -project Gulp.xcodeproj -scheme $(SCHEME) -configuration $(CONFIG) -destination '$(DEST)' -derivedDataPath $(DD) build

run: build ## Build and launch Gulp.app
	open "$(DD)/Build/Products/$(CONFIG)/Gulp.app"

test-core: ## swift test for GulpKit (works on Linux)
	swift test --package-path $(KIT) --parallel

test: test-core ## Core tests + app/UI tests (macOS)
	xcodebuild -project Gulp.xcodeproj -scheme $(SCHEME) -configuration $(CONFIG) -destination '$(DEST)' -derivedDataPath $(DD) test

perf: ## Performance budget tests (doc 06 §5; slow, excluded from `test`)
	swift test --package-path $(KIT) --filter PerformanceTests

lint: ## Check formatting (strict)
	swift format lint --strict --recursive App Packages Beacon UITests

format: ## Apply formatting in place
	swift format --in-place --recursive App Packages Beacon UITests

vulnlab: ## Run the local vulnerable test server on :8088 (127.0.0.1 only)
	swift run --package-path $(KIT) gulp-vulnlab --port 8088

beacon: ## Run the OAST Beacon server locally (dev mode)
	swift run --package-path $(BEACON) gulp-beacon --dev

release: ## Archive, sign, notarize and package (macOS; needs signing secrets)
	Scripts/release.sh

clean: ## Remove build products and the generated Xcode project
	rm -rf .build Gulp.xcodeproj $(KIT)/.build $(BEACON)/.build
