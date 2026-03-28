build:
	@echo "Compiling injectdb (dev)..."
	uv run maturin develop

release:
	@echo "Compiling injectdb (release)..."
	uv run maturin build --release

test:
	@echo "Running Python tests..."
	uv run pytest

update:
	@echo "Updating dependencies..."
	cargo update

clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf target/ dist/ *.egg-info