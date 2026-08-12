# Qanat build: `make NATIVE=1` enables on-device ARM tuning.

NAME      := qanat
# One source of truth: the header defines it, the build reads it.
VERSION   := $(shell sed -n 's/^#define QN_VERSION "\(.*\)"$$/\1/p' include/qanat/qanat.h)

ifeq ($(origin CC), default)
  CC := clang
endif
CC        ?= clang
PREFIX    ?= /data/data/com.termux/files/usr
BUILD     ?= build

UNAME_M   := $(shell uname -m 2>/dev/null || echo unknown)

# Target arch, not host: the CI cross-builds aarch64 from x86.
TARGET_ARCH := $(shell $(CC) -dumpmachine 2>/dev/null | cut -d- -f1)

CRYPTO_SRC := \
	src/crypto/arm64/cpufeat.c \
	src/crypto/sha2.c \
	src/crypto/kdf.c \
	src/crypto/chacha.c \
	src/crypto/poly1305.c \
	src/crypto/aesgcm.c \
	src/crypto/aead.c \
	src/crypto/x25519.c \
	src/crypto/p256.c \
	src/crypto/mlkem.c \
	src/crypto/rand.c \
	src/crypto/md5.c

TLS_CAPABILITY_SRC := src/net/tls_capability.c

# Hand-written crypto-extension paths; dispatched at runtime on HWCAP.
ifeq ($(TARGET_ARCH),aarch64)
CRYPTO_SRC += \
	src/crypto/arm64/aes_ce.S \
	src/crypto/arm64/ghash_ce.S \
	src/crypto/arm64/sha256_ce.S \
	src/crypto/arm64/sha512_ce.S \
	src/crypto/arm64/chacha_neon.S \
	src/crypto/arm64/poly1305.S
SHA2_ACCEL_SRC := \
	src/crypto/arm64/sha256_ce.S \
	src/crypto/arm64/sha512_ce.S
endif

SRC := \
	src/main.c \
	src/export.c \
	$(CRYPTO_SRC) \
	src/core/arena.c \
	src/core/bandit.c \
	src/core/cidr.c \
	src/core/cpuinfo.c \
	src/core/netinfo.c \
	src/core/outcome.c \
	src/core/perm.c \
	src/core/ranges.c \
	src/core/ring.c \
	src/core/scan_plan.c \
	src/core/sprt.c \
	src/core/stats.c \
	src/core/store.c \
	src/core/timewheel.c \
	src/core/topk.c \
	src/core/util.c \
	src/data/cf_prefixes.c \
	src/data/services.c \
	src/net/engine.c \
	src/net/http1.c \
	src/net/probe_http.c \
	src/net/http2.c \
	src/net/observation.c \
	src/net/profile.c \
	src/net/request_gate.c \
	src/net/probe_tls.c \
	$(TLS_CAPABILITY_SRC) \
	src/net/tls_hello.c \
	src/net/tls13.c \
	src/net/tls12.c \
	src/net/tls_cert.c \
	src/net/tls_fp.c \
	src/net/tunnel_link.c \
	src/net/tunnel_config.c \
	src/net/socks5.c \
	src/net/tunnel_runtime.c \
	src/net/xray_install.c \
	src/net/verify.c \
	src/task/task_cf.c \
	src/task/task_discover.c \
	src/task/task_ports.c \
	src/ui/menu.c \
	src/ui/app.c \
	src/ui/input.c \
	src/ui/scan_editor.c \
	src/ui/screen.c \
	src/ui/term.c \
	src/ui/widgets.c

OBJ := $(patsubst %.S,$(BUILD)/%.o,$(patsubst %.c,$(BUILD)/%.o,$(SRC)))
DEP := $(OBJ:.o=.d)

WARN := -Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-prototypes \
        -Wpointer-arith -Wcast-align -Wwrite-strings -Wredundant-decls \
        -Wno-unused-parameter

BASE := -std=c11 -D_GNU_SOURCE -Iinclude -pthread -MMD -MP
OPT  := -O3 -fno-plt -fomit-frame-pointer -ffunction-sections -fdata-sections
LDFL := -pthread -Wl,--gc-sections

# ARM64 is primary; scalar paths keep development builds portable.
ifeq ($(UNAME_M),aarch64)
  ARCH := -march=armv8-a
  ifeq ($(NATIVE),1)
    ARCH := -mcpu=native
  endif
endif
ifeq ($(UNAME_M),arm64)
  ARCH := -march=armv8-a
endif

# BTI and PAC. The assembly emits matching notes, and the linker needs every
# object marked or it drops the feature for the whole binary.
BP_PROBE = $(shell d=$$(mktemp -d 2>/dev/null || echo /tmp/qn-bp-$$$$) && \
	mkdir -p $$d && printf 'int main(void){return 0;}\n' > $$d/p.c && \
	$(CC) $(1) -c -o $$d/p.o $$d/p.c >/dev/null 2>&1 && echo yes || echo no; \
	rm -rf $$d)

ifeq ($(TARGET_ARCH),aarch64)
  ifeq ($(call BP_PROBE,-mbranch-protection=standard),yes)
    ARCH += -mbranch-protection=standard
  endif
endif

# LTO joins the probe state machine with the event loop. Accepting the flag is
# not the same as being able to link: the plugin can be missing. Probe both.
LTO ?= auto

LTO_PROBE = $(shell d=$$(mktemp -d 2>/dev/null || echo /tmp/qn-lto-$$$$) && \
	mkdir -p $$d && printf 'int main(void){return 0;}\n' > $$d/p.c && \
	$(CC) $(ARCH) $(1) -o $$d/p $$d/p.c >/dev/null 2>&1 && echo yes || echo no; \
	rm -rf $$d)

ifeq ($(LTO),auto)
  ifeq ($(call LTO_PROBE,-flto=thin),yes)
    LTO_MODE  := thin
    LTO_FLAGS := -flto=thin
  else ifeq ($(call LTO_PROBE,-flto),yes)
    LTO_MODE  := full
    LTO_FLAGS := -flto
  else
    LTO_MODE  := off
    LTO_FLAGS :=
  endif
else ifeq ($(LTO),thin)
  ifeq ($(call LTO_PROBE,-flto=thin),yes)
    LTO_MODE  := thin
    LTO_FLAGS := -flto=thin
  else
    $(error LTO=thin: $(CC) cannot compile and link with -flto=thin; use LTO=auto)
  endif
else ifeq ($(LTO),full)
  ifeq ($(call LTO_PROBE,-flto),yes)
    LTO_MODE  := full
    LTO_FLAGS := -flto
  else
    $(error LTO=full: $(CC) cannot compile and link with -flto; use LTO=auto)
  endif
else ifeq ($(LTO),off)
  LTO_MODE  := off
  LTO_FLAGS :=
else ifeq ($(LTO),)
  LTO_MODE  := off
  LTO_FLAGS :=
else
  $(error LTO must be auto, thin, full, or off; got "$(LTO)")
endif

CFLAGS  ?= $(BASE) $(WARN) $(OPT) $(ARCH) $(LTO_FLAGS) -DNDEBUG
LDFLAGS ?= $(LDFL) $(OPT) $(LTO_FLAGS) $(ARCH)

# Objects carry no record of how they were built, so a flag change alone used to
# leave stale output in place. Every compile depends on this signature instead.
CC_VERSION := $(shell $(CC) --version 2>/dev/null | head -1)
CONFIG_SIG := cc=$(CC)|ver=$(CC_VERSION)|target=$(shell $(CC) -dumpmachine 2>/dev/null)|\
arch=$(TARGET_ARCH)|host=$(UNAME_M)|native=$(NATIVE)|lto=$(LTO_MODE)|ver=$(VERSION)|\
cflags=$(CFLAGS)|ldflags=$(LDFLAGS)
CONFIG_STAMP := $(BUILD)/.build-config

# 16 hex digits is enough to name a configuration in output and in bug reports.
BUILD_FINGERPRINT := $(shell printf '%s' '$(CONFIG_SIG)' | \
	{ sha256sum 2>/dev/null || cksum; } | cut -c1-16)
BUILD_DEFS := -DQN_BUILD_FINGERPRINT='"$(BUILD_FINGERPRINT)"'
ALL_CFLAGS := $(CFLAGS) $(BUILD_DEFS)

BIN := $(BUILD)/$(NAME)

TEST_BIN := $(BUILD)/test_core
TEST_SRC := \
	tests/test_core.c \
	src/crypto/sha2.c \
	src/crypto/rand.c \
	src/crypto/arm64/cpufeat.c \
	$(SHA2_ACCEL_SRC) \
	src/core/arena.c \
	src/core/cidr.c \
	src/core/perm.c \
	src/core/ranges.c \
	src/core/ring.c \
	src/core/stats.c \
	src/core/util.c \
	src/data/cf_prefixes.c \
	src/data/services.c \
	src/net/http1.c \
	src/net/http2.c \
	src/net/observation.c \
	src/net/profile.c \
	src/net/request_gate.c \
	src/net/probe_http.c \
	src/net/probe_tls.c \
	$(TLS_CAPABILITY_SRC) \
	src/net/tls_hello.c \
	src/task/task_ports.c

CRYPTO_TEST_BIN := $(BUILD)/test_crypto
CRYPTO_TEST_SRC := \
	tests/test_crypto.c \
	$(CRYPTO_SRC) \
	src/core/perm.c \
	src/core/util.c

CRYPTO_ABI_TEST_BIN := $(BUILD)/test_crypto_abi
CRYPTO_ABI_TEST_SRC := \
	tests/test_crypto_abi.c \
	tests/arm64/abi_probe.S \
	$(CRYPTO_SRC) \
	src/core/perm.c \
	src/core/util.c

CRYPTO_DIFF_TEST_BIN := $(BUILD)/test_crypto_diff
CRYPTO_DIFF_TEST_SRC := \
	tests/test_crypto_diff.c \
	$(CRYPTO_SRC) \
	src/core/perm.c \
	src/core/util.c

CRYPTO_BENCH_BIN := $(BUILD)/bench_crypto
CRYPTO_BENCH_SRC := \
	tests/bench_crypto.c \
	$(CRYPTO_SRC) \
	src/core/perm.c \
	src/core/util.c

TLS_VERIFY_BENCH_BIN := $(BUILD)/bench_tls_verify
TLS_VERIFY_BENCH_SRC := \
	tests/bench_tls_verify.c \
	src/net/verify.c \
	src/net/socks5.c \
	src/net/http1.c \
	src/net/http2.c \
	src/net/observation.c \
	src/net/profile.c \
	src/net/request_gate.c \
	src/net/probe_http.c \
	$(TLS_CAPABILITY_SRC) \
	src/net/tls13.c \
	src/net/tls12.c \
	src/net/tls_hello.c \
	src/net/tls_fp.c \
	src/net/tls_cert.c \
	$(CRYPTO_SRC) \
	src/core/perm.c \
	src/core/util.c

TLS_TEST_BIN := $(BUILD)/test_tls
TLS_TEST_SRC := \
	tests/test_tls.c \
	src/net/http2.c \
	src/net/probe_http.c \
	src/net/probe_tls.c \
	src/net/profile.c \
	$(TLS_CAPABILITY_SRC) \
	src/net/tls_hello.c \
	src/net/tls13.c \
	src/net/tls12.c \
	src/net/tls_cert.c \
	src/net/tls_fp.c \
	$(CRYPTO_SRC) \
	src/core/perm.c \
	src/core/util.c

BROWSER_HELLO_TEST_BIN := $(BUILD)/test_browser_hello
BROWSER_HELLO_TEST_SRC := \
	tests/test_browser_hello.c \
	$(TLS_CAPABILITY_SRC) \
	src/net/tls_hello.c \
	src/crypto/md5.c \
	src/crypto/sha2.c \
	src/crypto/rand.c \
	src/core/util.c

PROP_TEST_BIN := $(BUILD)/test_props
PROP_TEST_SRC := \
	tests/test_props.c \
	src/core/arena.c \
	src/core/bandit.c \
	src/core/perm.c \
	src/core/ring.c \
	src/core/sprt.c \
	src/core/stats.c \
	src/core/store.c \
	src/core/timewheel.c \
	src/core/topk.c \
	src/core/util.c

ENGINE_TEST_BIN := $(BUILD)/test_engine
ENGINE_TEST_SRC := \
	tests/test_engine.c \
	src/core/arena.c \
	src/core/cpuinfo.c \
	src/core/outcome.c \
	src/core/perm.c \
	src/core/ring.c \
	src/core/timewheel.c \
	src/core/util.c \
	src/net/engine.c \
	src/net/probe_tls.c \
	$(TLS_CAPABILITY_SRC) \
	src/net/tls_hello.c \
	src/net/tls_fp.c \
	$(CRYPTO_SRC)

ENGINE_FAULT_TEST_BIN := $(BUILD)/test_engine_faults
ENGINE_FAULT_TEST_SRC := tests/test_engine_faults.c $(filter-out tests/test_engine.c,$(ENGINE_TEST_SRC))

VERIFY_TEST_BIN := $(BUILD)/test_verify
VERIFY_TEST_SRC := \
	tests/test_verify.c \
	tests/netsim.c \
	src/net/verify.c \
	src/net/socks5.c \
	src/net/http1.c \
	src/net/http2.c \
	src/net/observation.c \
	src/net/profile.c \
	src/net/request_gate.c \
	src/net/probe_http.c \
	$(TLS_CAPABILITY_SRC) \
	src/net/tls13.c \
	src/net/tls12.c \
	src/net/tls_hello.c \
	src/net/tls_fp.c \
	src/net/tls_cert.c \
	$(CRYPTO_SRC) \
	src/core/perm.c \
	src/core/util.c

VERIFY_FAULT_TEST_BIN := $(BUILD)/test_verify_faults
VERIFY_FAULT_TEST_SRC := \
	tests/test_verify_faults.c \
	src/net/verify.c \
	src/net/socks5.c \
	src/net/http1.c \
	src/net/http2.c \
	src/net/observation.c \
	src/net/profile.c \
	src/net/request_gate.c \
	src/net/probe_http.c \
	$(TLS_CAPABILITY_SRC) \
	src/net/tls13.c \
	src/net/tls12.c \
	src/net/tls_hello.c \
	src/net/tls_fp.c \
	src/net/tls_cert.c \
	$(CRYPTO_SRC) \
	src/core/perm.c \
	src/core/util.c

EXPORT_TEST_BIN := $(BUILD)/test_export
EXPORT_TEST_SRC := \
	tests/test_export.c \
	src/export.c \
	src/net/tunnel_link.c \
	src/net/tunnel_config.c \
	src/net/observation.c \
	src/core/outcome.c \
	src/core/scan_plan.c \
	src/core/util.c \
	src/data/services.c

TASK_TEST_BIN := $(BUILD)/test_task_cf
TASK_TEST_SRC := \
	tests/test_task_cf.c \
	src/core/arena.c \
	src/core/bandit.c \
	src/core/cidr.c \
	src/core/cpuinfo.c \
	src/core/netinfo.c \
	src/core/outcome.c \
	src/core/perm.c \
	src/core/ranges.c \
	src/core/ring.c \
	src/core/scan_plan.c \
	src/core/sprt.c \
	src/core/stats.c \
	src/core/store.c \
	src/core/timewheel.c \
	src/core/topk.c \
	src/core/util.c \
	src/data/cf_prefixes.c \
	src/net/engine.c \
	src/net/http1.c \
	src/net/http2.c \
	src/net/observation.c \
	src/net/profile.c \
	src/net/request_gate.c \
	src/net/probe_http.c \
	src/net/probe_tls.c \
	$(TLS_CAPABILITY_SRC) \
	src/net/tls12.c \
	src/net/tls13.c \
	src/net/tls_cert.c \
	src/net/tls_fp.c \
	src/net/tls_hello.c \
	src/net/verify.c \
	src/net/socks5.c \
	src/net/tunnel_link.c \
	src/net/tunnel_config.c \
	src/net/tunnel_runtime.c \
	$(CRYPTO_SRC) \
	src/task/task_cf.c

OUTBUF_TEST_BIN := $(BUILD)/test_outbuf
OUTBUF_TEST_SRC := tests/test_outbuf.c src/net/request_gate.c src/core/util.c

SCREEN_TEST_BIN := $(BUILD)/test_screen
SCREEN_TEST_SRC := tests/test_screen.c src/ui/screen.c src/core/util.c

INPUT_TEST_BIN := $(BUILD)/test_input
INPUT_TEST_SRC := tests/test_input.c src/ui/input.c src/core/util.c

DISCOVER_TEST_BIN := $(BUILD)/test_discover
DISCOVER_TEST_SRC := \
	tests/test_discover.c \
	src/core/arena.c \
	src/core/cidr.c \
	src/core/netinfo.c \
	src/core/perm.c \
	src/core/util.c \
	src/crypto/arm64/cpufeat.c \
	src/crypto/rand.c \
	src/crypto/sha2.c \
	$(SHA2_ACCEL_SRC) \
	src/net/probe_http.c \
	src/net/http1.c \
	src/data/services.c

SCAN_PLAN_TEST_BIN := $(BUILD)/test_scan_plan
SCAN_PLAN_TEST_SRC := tests/test_scan_plan.c src/core/scan_plan.c

SCAN_EDITOR_TEST_BIN := $(BUILD)/test_scan_editor
SCAN_EDITOR_TEST_SRC := tests/test_scan_editor.c src/ui/scan_editor.c src/core/scan_plan.c

TUNNEL_TEST_BIN := $(BUILD)/test_tunnel
TUNNEL_TEST_SRC := \
	tests/test_tunnel.c \
	tests/fake_socks.c \
	src/net/tunnel_link.c \
	src/net/tunnel_config.c \
	src/net/socks5.c \
	src/core/util.c

TUNNEL_RUNTIME_TEST_BIN := $(BUILD)/test_tunnel_runtime
TUNNEL_RUNTIME_TEST_SRC := \
	tests/test_tunnel_runtime.c \
	src/net/tunnel_runtime.c \
	src/net/tunnel_link.c \
	src/net/tunnel_config.c \
	src/net/socks5.c \
	src/net/verify.c \
	src/net/http1.c \
	src/net/http2.c \
	src/net/observation.c \
	src/net/profile.c \
	src/net/request_gate.c \
	src/net/probe_http.c \
	$(TLS_CAPABILITY_SRC) \
	src/net/tls13.c \
	src/net/tls12.c \
	src/net/tls_hello.c \
	src/net/tls_fp.c \
	src/net/tls_cert.c \
	$(CRYPTO_SRC) \
	src/core/perm.c \
	src/core/util.c

OFFLINE_TEST_BINS := $(TEST_BIN) $(CRYPTO_TEST_BIN) $(TLS_TEST_BIN) \
                     $(BROWSER_HELLO_TEST_BIN) \
                     $(PROP_TEST_BIN) $(ENGINE_FAULT_TEST_BIN) \
                     $(VERIFY_FAULT_TEST_BIN) $(EXPORT_TEST_BIN) \
                     $(TASK_TEST_BIN) $(OUTBUF_TEST_BIN) $(SCREEN_TEST_BIN) \
			     $(DISCOVER_TEST_BIN) $(SCAN_PLAN_TEST_BIN) \
			     $(SCAN_EDITOR_TEST_BIN) $(INPUT_TEST_BIN) $(TUNNEL_TEST_BIN) \
			     $(TUNNEL_RUNTIME_TEST_BIN)

TEST_BINS := $(OFFLINE_TEST_BINS) $(ENGINE_TEST_BIN) $(VERIFY_TEST_BIN)

ifeq ($(TARGET_ARCH),aarch64)
OFFLINE_TEST_BINS += $(CRYPTO_ABI_TEST_BIN) $(CRYPTO_DIFF_TEST_BIN)
TEST_BINS += $(CRYPTO_ABI_TEST_BIN) $(CRYPTO_DIFF_TEST_BIN)
endif

.PHONY: all debug sanitize-test sanitize-offline-test tsan tsan-test \
        tsan-offline-test strict strict-test strict-offline-test analyze test \
        test-build offline-test offline-test-build bench-crypto \
        bench-tls-verify menu-test install-docs-test tls-test fuzz fuzz-smoke \
        tunnel-local-test check clean install \
        uninstall run fmt config-fingerprint force

all: $(BIN)

# Rewritten only when the configuration really changed, so it is not a rebuild
# trigger in itself.
$(CONFIG_STAMP): force
	@mkdir -p $(dir $@)
	@test "$$(cat $@ 2>/dev/null)" = "$(CONFIG_SIG)" || \
		{ printf '%s' "$(CONFIG_SIG)" > $@; echo "  config $(BUILD_FINGERPRINT) ($(CC), lto=$(LTO_MODE), $(TARGET_ARCH))"; }

force:

config-fingerprint:
	@echo "$(BUILD_FINGERPRINT)"
	@echo "$(CONFIG_SIG)"

$(OBJ): $(CONFIG_STAMP)
$(TEST_BINS) $(CRYPTO_BENCH_BIN) $(TLS_VERIFY_BENCH_BIN): $(CONFIG_STAMP)

$(BIN): $(OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)
	@echo "  built $@ ($(TARGET_ARCH), lto=$(LTO_MODE), config $(BUILD_FINGERPRINT))"

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

$(BUILD)/%.o: %.S
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -c $< -o $@

debug:
	@$(MAKE) --no-print-directory BUILD=build-debug \
		CFLAGS="$(BASE) $(WARN) -O0 -g3 -fno-omit-frame-pointer -fsanitize=address,undefined" \
		LDFLAGS="-pthread -fsanitize=address,undefined"

sanitize-test:
	@$(MAKE) --no-print-directory BUILD=build-sanitize \
		CFLAGS="$(BASE) $(WARN) -O1 -g3 -fno-omit-frame-pointer -fsanitize=address,undefined" \
		LDFLAGS="-pthread -fsanitize=address,undefined" test

sanitize-offline-test:
	@$(MAKE) --no-print-directory BUILD=build-sanitize-offline \
		CFLAGS="$(BASE) $(WARN) -O1 -g3 -fno-omit-frame-pointer -fsanitize=address,undefined" \
		LDFLAGS="-pthread -fsanitize=address,undefined" offline-test

tsan-test:
	@$(MAKE) --no-print-directory BUILD=build-tsan \
		CFLAGS="$(BASE) $(WARN) -O1 -g3 -fno-omit-frame-pointer -fsanitize=thread" \
		LDFLAGS="-pthread -fsanitize=thread" test

tsan-offline-test:
	@$(MAKE) --no-print-directory BUILD=build-tsan-offline \
		CFLAGS="$(BASE) $(WARN) -O1 -g3 -fno-omit-frame-pointer -fsanitize=thread" \
		LDFLAGS="-pthread -fsanitize=thread" offline-test

tsan:
	@$(MAKE) --no-print-directory BUILD=build-tsan-app \
		CFLAGS="$(BASE) $(WARN) -O1 -g3 -fno-omit-frame-pointer -fsanitize=thread" \
		LDFLAGS="-pthread -fsanitize=thread"

strict:
	@$(MAKE) --no-print-directory BUILD=build-strict \
		CFLAGS="$(BASE) $(WARN) -Werror -Wconversion -Wsign-conversion $(OPT) $(ARCH) -DNDEBUG" \
		LDFLAGS="$(LDFL) $(OPT) $(ARCH)"

# -Wrestrict is GCC-only; under -Werror Clang rejects the unknown option itself.
WRESTRICT := $(if $(filter yes,$(call BP_PROBE,-Wrestrict -Werror)),-Wrestrict,)

# `strict` covers the application only; the suites need the same gate.
strict-test:
	@$(MAKE) --no-print-directory BUILD=build-strict-test LTO= \
		CFLAGS="$(BASE) $(WARN) -Werror -Wconversion -Wsign-conversion $(WRESTRICT) $(ARCH) -O2 -DNDEBUG" \
		LDFLAGS="$(LDFL) $(ARCH) -O2" test

strict-offline-test:
	@$(MAKE) --no-print-directory BUILD=build-strict-offline LTO= \
		CFLAGS="$(BASE) $(WARN) -Werror -Wconversion -Wsign-conversion $(WRESTRICT) $(ARCH) -O2 -DNDEBUG" \
		LDFLAGS="$(LDFL) $(ARCH) -O2" offline-test

# GCC's path-sensitive analyzer catches ownership and descriptor bugs that
# runtime sanitizers only see when a test happens to execute the same path.
analyze:
	@$(MAKE) --no-print-directory BUILD=build-analyzer-o0 \
		CFLAGS="$(BASE) $(WARN) -Werror -O0 -g -fanalyzer -DQN_STATIC_ANALYZER=1 -DNDEBUG" \
		LDFLAGS="$(LDFL)"

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do echo "  run $$t"; $$t || exit 1; done

# This allowlist never opens a real network socket; transport failures use fake hooks.
offline-test: $(OFFLINE_TEST_BINS)
	@for t in $(OFFLINE_TEST_BINS); do echo "  run $$t"; $$t || exit 1; done

# Cross-build every suite without executing target binaries on the build host.
test-build: $(TEST_BINS)

offline-test-build: $(OFFLINE_TEST_BINS)

bench-crypto: $(CRYPTO_BENCH_BIN)
	$(CRYPTO_BENCH_BIN)

bench-tls-verify: $(TLS_VERIFY_BENCH_BIN)
	$(TLS_VERIFY_BENCH_BIN) $(BENCH_TLS_ARGS)

install-docs-test:
	@sh scripts/check_install_docs.sh

menu-test: strict install-docs-test
	@python3 tests/test_menu_pty.py build-strict/qanat

$(TEST_BIN): $(TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -DQN_CIDR_TESTING -Isrc/net $(TEST_SRC) -o $@ $(LDFLAGS)

$(CRYPTO_TEST_BIN): $(CRYPTO_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) $(CRYPTO_TEST_SRC) -o $@ $(LDFLAGS)

$(CRYPTO_ABI_TEST_BIN): $(CRYPTO_ABI_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -Isrc/crypto $(CRYPTO_ABI_TEST_SRC) -o $@ $(LDFLAGS)

$(CRYPTO_DIFF_TEST_BIN): $(CRYPTO_DIFF_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -DQN_CRYPTO_TESTING -Isrc/crypto $(CRYPTO_DIFF_TEST_SRC) -o $@ $(LDFLAGS)

$(CRYPTO_BENCH_BIN): $(CRYPTO_BENCH_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -DQN_CRYPTO_TESTING -DQN_BENCH_TEST_HOOKS -Isrc/crypto \
		$(CRYPTO_BENCH_SRC) -o $@ $(LDFLAGS)

$(TLS_VERIFY_BENCH_BIN): $(TLS_VERIFY_BENCH_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) $(TLS_VERIFY_BENCH_SRC) -o $@ $(LDFLAGS)

$(TLS_TEST_BIN): $(TLS_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -Isrc/net $(TLS_TEST_SRC) -o $@ $(LDFLAGS)

$(BROWSER_HELLO_TEST_BIN): $(BROWSER_HELLO_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) $(BROWSER_HELLO_TEST_SRC) -o $@ $(LDFLAGS)

$(PROP_TEST_BIN): $(PROP_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) $(PROP_TEST_SRC) -o $@ $(LDFLAGS)

$(ENGINE_TEST_BIN): $(ENGINE_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) $(ENGINE_TEST_SRC) -o $@ $(LDFLAGS)

$(ENGINE_FAULT_TEST_BIN): $(ENGINE_FAULT_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -DQN_ENGINE_TESTING $(ENGINE_FAULT_TEST_SRC) -o $@ $(LDFLAGS)

$(VERIFY_TEST_BIN): $(VERIFY_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -Itests $(VERIFY_TEST_SRC) -o $@ $(LDFLAGS)

$(VERIFY_FAULT_TEST_BIN): $(VERIFY_FAULT_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -DQN_VERIFY_TESTING $(VERIFY_FAULT_TEST_SRC) -o $@ $(LDFLAGS)

$(EXPORT_TEST_BIN): $(EXPORT_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -DQN_EXPORT_TESTING $(EXPORT_TEST_SRC) -o $@ $(LDFLAGS)

$(TASK_TEST_BIN): $(TASK_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -DQN_TASK_CF_TESTING $(TASK_TEST_SRC) -o $@ $(LDFLAGS)

$(OUTBUF_TEST_BIN): $(OUTBUF_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -Isrc/net $(OUTBUF_TEST_SRC) -o $@ $(LDFLAGS)

$(SCREEN_TEST_BIN): $(SCREEN_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) $(SCREEN_TEST_SRC) -o $@ $(LDFLAGS)

$(INPUT_TEST_BIN): $(INPUT_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) $(INPUT_TEST_SRC) -o $@ $(LDFLAGS)

$(DISCOVER_TEST_BIN): $(DISCOVER_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -Isrc/task -Isrc/core $(DISCOVER_TEST_SRC) -o $@ $(LDFLAGS)

$(SCAN_PLAN_TEST_BIN): $(SCAN_PLAN_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) $(SCAN_PLAN_TEST_SRC) -o $@ $(LDFLAGS)

$(SCAN_EDITOR_TEST_BIN): $(SCAN_EDITOR_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) $(SCAN_EDITOR_TEST_SRC) -o $@ $(LDFLAGS)

$(TUNNEL_TEST_BIN): $(TUNNEL_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) $(TUNNEL_TEST_SRC) -o $@ $(LDFLAGS)

$(TUNNEL_RUNTIME_TEST_BIN): $(TUNNEL_RUNTIME_TEST_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(ALL_CFLAGS) -DQN_TUNNEL_TESTING $(TUNNEL_RUNTIME_TEST_SRC) \
		-o $@ $(LDFLAGS)

tls-test:
	@sh scripts/test_tls_local.sh

tunnel-local-test: $(TUNNEL_RUNTIME_TEST_BIN)
	@sh scripts/test_tunnel_local.sh $(TUNNEL_RUNTIME_TEST_BIN)

FUZZ_TARGETS := fuzz_http fuzz_http1 fuzz_http2 fuzz_tls_classify fuzz_cidr \
	fuzz_tls_session fuzz_tunnel_link
FUZZ_LIB := \
	$(CRYPTO_SRC) \
	src/core/arena.c src/core/cidr.c src/core/perm.c src/core/util.c \
	src/net/probe_http.c src/net/probe_tls.c src/net/http1.c src/net/http2.c \
	src/net/profile.c \
	src/net/tunnel_link.c \
	$(TLS_CAPABILITY_SRC) \
	src/net/tls13.c src/net/tls12.c src/net/tls_hello.c src/net/tls_fp.c src/net/tls_cert.c

# libFuzzer needs clang; `fuzz-smoke` replays the same harnesses under any cc.
fuzz:
	@mkdir -p build-fuzz
	@for t in $(FUZZ_TARGETS); do \
		echo "  build $$t"; \
		$(CC) $(BASE) $(WARN) -O1 -g -fsanitize=fuzzer,address,undefined \
			-Ifuzz fuzz/$$t.c $(FUZZ_LIB) -o build-fuzz/$$t || exit 1; \
	done

fuzz-smoke:
	@mkdir -p build-fuzz
	@for t in $(FUZZ_TARGETS); do \
		$(CC) $(BASE) $(WARN) -O1 -g -fsanitize=address,undefined \
			-DQN_FUZZ_STANDALONE -Ifuzz fuzz/$$t.c $(FUZZ_LIB) \
			-o build-fuzz/$$t-smoke || exit 1; \
		./build-fuzz/$$t-smoke || exit 1; \
	done

check: strict test menu-test tls-test

clean:
	rm -rf build build-debug build-strict build-test build-sanitize build-tlstest build-tlsasan build-fuzz build-tsan build-tsan-app build-analyzer-o0

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(NAME)
	@echo "  installed $(DESTDIR)$(PREFIX)/bin/$(NAME)"

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(NAME)

run: $(BIN)
	$(BIN) --net

fmt:
	@command -v clang-format >/dev/null && clang-format -i $(SRC) tests/test_core.c include/qanat/*.h || \
		echo "clang-format not installed"

-include $(DEP)
