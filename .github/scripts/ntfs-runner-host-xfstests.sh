#!/bin/bash

set -u

: "${GITHUB_WORKSPACE:?}"
: "${TEST_CASE:?}"
: "${RUNNER_KERNEL:?}"
: "${MKNTFS:?}"
: "${NTFS_PROGS:?}"
: "${XFSTESTS:?}"

RESULT_DIR="$GITHUB_WORKSPACE/ci-results"
TEST_IMAGE="$RESULT_DIR/runner-test.img"
SCRATCH_IMAGE="$RESULT_DIR/runner-scratch.img"
TEST_MNT=/mnt/ntfs-runner-test
SCRATCH_MNT=/mnt/ntfs-runner-scratch
TEST_DEV=
SCRATCH_DEV=

cleanup()
{
	set +e
	sudo umount "$TEST_MNT" "$SCRATCH_MNT" 2>/dev/null
	[ -z "$TEST_DEV" ] || sudo losetup -d "$TEST_DEV"
	[ -z "$SCRATCH_DEV" ] || sudo losetup -d "$SCRATCH_DEV"
	sudo rmmod ntfs 2>/dev/null
}
trap cleanup EXIT

mkdir -p "$RESULT_DIR" "$TEST_MNT" "$SCRATCH_MNT"
truncate -s 16G "$TEST_IMAGE" "$SCRATCH_IMAGE"

sudo modprobe loop
sudo insmod "$GITHUB_WORKSPACE/ntfs.ko"

TEST_DEV=$(sudo losetup --find --show --sector-size 4096 "$TEST_IMAGE")
SCRATCH_DEV=$(sudo losetup --find --show --sector-size 4096 "$SCRATCH_IMAGE")

{
	printf 'kernel_release=%s\n' "$RUNNER_KERNEL"
	for dev in "$TEST_DEV" "$SCRATCH_DEV"; do
		logical=$(sudo blockdev --getss "$dev")
		physical=$(sudo blockdev --getpbsz "$dev")
		printf '%s logical=%s physical=%s\n' "$dev" "$logical" "$physical"
		[ "$logical" = 4096 ] && [ "$physical" = 4096 ]
	done
} | tee "$RESULT_DIR/runner-device-geometry.txt"

for dev in "$TEST_DEV" "$SCRATCH_DEV"; do
	"$MKNTFS" -F -Q -s 4096 -c 4096 -r 1024 "$dev" \
		> "$RESULT_DIR/mkntfs-$(basename "$dev").log" 2>&1
done

python3 - "$TEST_DEV" "$RESULT_DIR/runner-boot-geometry.txt" <<'PY'
import struct
import sys

device, output = sys.argv[1:]
with open(device, "rb", buffering=0) as stream:
    boot = stream.read(4096)
sector = struct.unpack_from("<H", boot, 11)[0]
cluster = sector * boot[13]
encoding = struct.unpack_from("<b", boot, 64)[0]
record = 1 << -encoding if encoding < 0 else cluster * encoding
with open(output, "w", encoding="ascii") as stream:
    stream.write(f"bytes_per_sector={sector}\n")
    stream.write(f"cluster_size={cluster}\n")
    stream.write(f"mft_record_size={record}\n")
if (sector, cluster, record) != (4096, 4096, 1024):
    raise SystemExit("unexpected NTFS geometry")
PY

rm -rf "$XFSTESTS/results"
cat > "$XFSTESTS/local.config" <<EOF
export TEST_DEV=$TEST_DEV
export TEST_DIR=$TEST_MNT
export SCRATCH_DEV=$SCRATCH_DEV
export SCRATCH_MNT=$SCRATCH_MNT
export FSTYP=ntfs
export MKFS_OPTIONS="-F -Q -s 4096 -c 4096 -r 1024"
export MOUNT_OPTIONS="-i -osymlink=native,native_symlink=rel"
export KEEP_DMESG=yes
EOF

set +e
(
	cd "$XFSTESTS"
	mapfile -t tests < "$RESULT_DIR/tests.list"
	./check --exact-order "${tests[@]}"
) > "$RESULT_DIR/xfstests.log" 2>&1
test_rc=$?
set -e

if [ -d "$XFSTESTS/results" ]; then
	cp -a "$XFSTESTS/results/." "$RESULT_DIR/xfstests/"
fi

{
	printf 'test_rc=%s\n' "$test_rc"
	if [ "$test_rc" -ne 0 ] ||
		find "$RESULT_DIR/xfstests" -type f -name '*.out.bad' |
			grep -q .; then
		echo NTFS_XFSTESTS_FAIL
		echo 'failed_cases:'
		find "$RESULT_DIR/xfstests" -type f -name '*.out.bad' \
			-printf '%f\n' | sed 's/\.out\.bad$//' | sort -u
	else
		echo NTFS_XFSTESTS_PASS
	fi
} | tee "$RESULT_DIR/status"

exit "$test_rc"
