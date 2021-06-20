debug:
	@if [ ! -d "target/debug" ]; then \
		mkdir --parents target/debug; \
	else \
		rm target/debug/*; \
	fi

	@echo "[INFO] Building dropper [DEBUG]"
	@cd src/dropper && \
	cargo build  &&\
	mv target/debug/dropper ../../target/debug/dropper

	@echo "[INFO] Building payload [DEBUG]"
	@cd src/payload && \
	cargo build --target x86_64-pc-windows-gnu && \
	mv target/x86_64-pc-windows-gnu/debug/payload.exe ../../target/debug/payload

	@echo "[INFO] Debug build complete"

release:
	@if [ ! -d "target/release" ]; then \
		mkdir --parents target/release; \
	else \
		rm target/release/*; \
	fi
	
	@echo "[INFO] Building dropper [RELEASE]"
	@cd src/dropper && \
	cargo build --release && \
	mv target/release/dropper ../../target/release/dropper

	@echo "[INFO] Building payload [RELEASE]"
	@cd src/payload && \
	cargo build --target x86_64-pc-windows-gnu --release && \
	mv target/x86_64-pc-windows-gnu/release/payload.exe ../../target/release/payload
	
	@echo "[INFO] Release build complete"

clean:
	@cd src/dropper && cargo clean
	@cd src/payload && cargo clean
	@rm -rf target
	@echo "[INFO] Clean complete"