# Shared helpers for tests/phase*.sh. Source at the top of any phase script.

# Re-exec under scripts/with-nix-libs so numpy/pandas C-extensions inside
# engine/.venv find libstdc++ + zlib on NixOS. No-op on other platforms.
# Idempotent (guarded by WAFLAB_WITH_NIX_LIBS, which the wrapper sets).
waflab_nix_reexec() {
  if [[ -z "${WAFLAB_WITH_NIX_LIBS:-}" ]] && command -v nix-build >/dev/null 2>&1; then
    local script="$1"; shift
    local repo_root
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    exec "$repo_root/scripts/with-nix-libs" bash "$script" "$@"
  fi
}
