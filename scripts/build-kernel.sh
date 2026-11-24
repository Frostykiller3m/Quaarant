#!/usr/bin/env bash
# Build qt's Firecracker guest kernel, reproducibly.
#
#   scripts/build-kernel.sh            -> bin/kernel/vmlinux-<version>-qt (+ .config, .sha256)
#   sudo install -m 0644 bin/kernel/vmlinux-*-qt /usr/local/lib/quarantine/vmlinux
#
# Pinned: the kernel version and the tarball's sha256 (from kernel.org's signed
# sha256sums.asc), the config (kernel/guest-<arch>.config merged on `make tinyconfig`), and
# all build metadata (timestamp, user, host, build number). With the same compiler, two runs
# produce the same vmlinux; the script prints its sha256.
set -euo pipefail

VERSION=6.18.65
SHA256=c92606f956f09dc50b5a0e2af9e86763fce27ada1647de97f8d1ac8cfc95801d
EPOCH=1795046400 # 2026-11-17T00:00:00Z: fixed build timestamp

ARCH=${ARCH:-x86_64}
REPO=$(cd "$(dirname "$0")/.." && pwd)
FRAGMENT=$REPO/kernel/guest-$ARCH.config
OUT=${OUT:-$REPO/bin/kernel}
CACHE=${CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/qt-kernel}
JOBS=${JOBS:-$(nproc)}

[ -f "$FRAGMENT" ] || { echo "no config fragment for $ARCH: $FRAGMENT" >&2; exit 1; }
mkdir -p "$CACHE" "$OUT"

tarball=$CACHE/linux-$VERSION.tar.xz
if ! { [ -f "$tarball" ] && echo "$SHA256  $tarball" | sha256sum -c --quiet; }; then
	echo "downloading linux-$VERSION"
	curl -fsSL "https://cdn.kernel.org/pub/linux/kernel/v${VERSION%%.*}.x/linux-$VERSION.tar.xz" -o "$tarball.tmp"
	echo "$SHA256  $tarball.tmp" | sha256sum -c --quiet
	mv "$tarball.tmp" "$tarball"
fi

src=$CACHE/linux-$VERSION-$ARCH
rm -rf "$src"
mkdir -p "$src"
tar -xJf "$tarball" -C "$src" --strip-components=1
cd "$src"

export ARCH KBUILD_BUILD_TIMESTAMP="$(date -u -d "@$EPOCH")" KBUILD_BUILD_USER=qt KBUILD_BUILD_HOST=quarantine \
	KBUILD_BUILD_VERSION=1 SOURCE_DATE_EPOCH=$EPOCH LC_ALL=C TZ=UTC
make -s tinyconfig
scripts/kconfig/merge_config.sh -m -O . .config "$FRAGMENT" >/dev/null
make -s olddefconfig

# Every option in the fragment must have survived Kconfig's dependency resolution.
missing=0
while IFS= read -r line; do
	case "$line" in
	CONFIG_*=*)
		grep -qxF "$line" .config || { echo "config: wanted $line, got: $(grep -E "^(# )?${line%%=*}[= ]" .config || echo unset)" >&2; missing=1; }
		;;
	"# CONFIG_"*" is not set")
		opt=${line#\# }; opt=${opt%% *}
		if grep -qE "^$opt=" .config; then echo "config: wanted $opt unset, got $(grep -E "^$opt=" .config)" >&2; missing=1; fi
		;;
	esac
done <"$FRAGMENT"
[ "$missing" = 0 ] || { echo "kernel config fragment not satisfied" >&2; exit 1; }

echo "building vmlinux ($VERSION, $ARCH, $JOBS jobs)"
make -s -j"$JOBS" vmlinux
release=$(make -s kernelrelease)
cp vmlinux "$OUT/vmlinux-$release"
cp .config "$OUT/vmlinux-$release.config"
(cd "$OUT" && sha256sum "vmlinux-$release" | tee "vmlinux-$release.sha256")
echo "kernel: $OUT/vmlinux-$release ($(du -h "$OUT/vmlinux-$release" | cut -f1)); gcc: $(gcc -dumpfullversion)"
