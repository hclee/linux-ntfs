#!/bin/bash
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RESULTS_DIR=${RESULTS_DIR:-"$ROOT_DIR/ntfs-4kn-results"}
TEST_CASE=${TEST_CASE:-}
TESTS_FILE=${TESTS_FILE:-"$ROOT_DIR/.github/xfstests/ntfs-geometry-full.list"}
XFSTESTS_DIR=${XFSTESTS_DIR:-"$ROOT_DIR/exfat-testsuites/xfstests-exfat"}
TEST_IMAGE=${TEST_IMAGE:-"$ROOT_DIR/ntfs-4kn-test.img"}
SCRATCH_IMAGE=${SCRATCH_IMAGE:-"$ROOT_DIR/ntfs-4kn-scratch.img"}
TEST_MNT=${TEST_MNT:-/mnt/ntfs-4kn-test}
SCRATCH_MNT=${SCRATCH_MNT:-/mnt/ntfs-4kn-scratch}

TEST_DEV=
SCRATCH_DEV=
overall_status=0

mkdir -p "$RESULTS_DIR"

classify_failure()
{
	local class=$1

	printf '%s\n' "$class" > "$RESULTS_DIR/classification.txt"
	if (( overall_status < 1 )); then
		overall_status=1
	fi
}

cleanup()
{
	set +e
	sudo dmesg --color=never > "$RESULTS_DIR/dmesg-after.log" 2>&1
	sudo chmod -R a+rX "$RESULTS_DIR" "$XFSTESTS_DIR/results" 2>/dev/null
	sudo umount "$TEST_MNT" 2>/dev/null
	sudo umount "$SCRATCH_MNT" 2>/dev/null
	if [[ -n "$TEST_DEV" ]]; then
		sudo losetup --detach "$TEST_DEV" 2>/dev/null
	fi
	if [[ -n "$SCRATCH_DEV" ]]; then
		sudo losetup --detach "$SCRATCH_DEV" 2>/dev/null
	fi
	sudo rmdir "$TEST_MNT" "$SCRATCH_MNT" 2>/dev/null
	rm -f "$TEST_IMAGE" "$SCRATCH_IMAGE"
}
trap cleanup EXIT

sudo dmesg --color=never > "$RESULTS_DIR/dmesg-before.log" 2>&1 || true

if [[ ! -f "$TESTS_FILE" ]]; then
	echo "Missing xfstests list: $TESTS_FILE" >&2
	printf '%s\n' "SETUP_BLOCKED" > "$RESULTS_DIR/classification.txt"
	exit 2
fi

if [[ -z "$TEST_CASE" ]]; then
	echo "TEST_CASE is required; the full test profile is not supported" >&2
	printf '%s\n' "SETUP_BLOCKED" > "$RESULTS_DIR/classification.txt"
	exit 2
fi
if ! grep -Fxq "$TEST_CASE" "$TESTS_FILE"; then
	echo "Requested case is not in the full profile: $TEST_CASE" >&2
	printf '%s\n' "SETUP_BLOCKED" > "$RESULTS_DIR/classification.txt"
	exit 2
fi
printf '%s\n' "$TEST_CASE" > "$RESULTS_DIR/tests.list"

truncate -s 100G "$TEST_IMAGE" "$SCRATCH_IMAGE"
TEST_DEV=$(sudo losetup --find --show --sector-size 4096 "$TEST_IMAGE")
SCRATCH_DEV=$(sudo losetup --find --show --sector-size 4096 "$SCRATCH_IMAGE")

record_geometry()
{
	local label=$1
	local dev=$2
	local name
	local queue_dir
	local logical
	local physical

	name=$(basename "$dev")
	queue_dir="/sys/class/block/$name/queue"
	logical=$(sudo blockdev --getss "$dev")
	physical=$(sudo blockdev --getpbsz "$dev")
	{
		echo "label=$label"
		echo "device=$dev"
		echo "logical_block_size=$logical"
		echo "physical_block_size=$physical"
		echo "size_bytes=$(sudo blockdev --getsize64 "$dev")"
		echo "rotational=$(sudo cat "$queue_dir/rotational")"
		echo "sysfs_logical=$(sudo cat "$queue_dir/logical_block_size")"
		echo "sysfs_physical=$(sudo cat "$queue_dir/physical_block_size")"
	} | tee "$RESULTS_DIR/geometry-$label.txt"

	if [[ "$logical" != 4096 || "$physical" != 4096 ]]; then
		echo "Device $dev is not native 4Kn: $logical/$physical" >&2
		classify_failure SETUP_BLOCKED
		exit 2
	fi
}

record_geometry test "$TEST_DEV"
record_geometry scratch "$SCRATCH_DEV"

MKNTFS=${MKNTFS:-$(command -v mkntfs || true)}
if [[ -z "$MKNTFS" ]]; then
	echo "mkntfs was not installed" >&2
	printf '%s\n' "SETUP_BLOCKED" > "$RESULTS_DIR/classification.txt"
	exit 2
fi

if ! "$MKNTFS" --help | grep -q -- '--mft-record-size'; then
	echo "mkntfs lacks --mft-record-size support" >&2
	printf '%s\n' "SETUP_BLOCKED" > "$RESULTS_DIR/classification.txt"
	exit 2
fi

format_device()
{
	local label=$1
	local dev=$2
	local log="$RESULTS_DIR/mkntfs-$label.log"

	if ! sudo "$MKNTFS" -Q -s 4096 -c 4096 -r 1024 "$dev" > "$log" 2>&1; then
		cat "$log" >&2
		classify_failure SETUP_BLOCKED
		exit 2
	fi
	cat "$log"
}

format_device test "$TEST_DEV"
format_device scratch "$SCRATCH_DEV"

check_boot_geometry()
{
	local label=$1
	local dev=$2
	local output="$RESULTS_DIR/boot-$label.txt"

	if ! sudo python3 - "$dev" > "$output" <<'PY'
import struct
import sys

device = sys.argv[1]
with open(device, "rb", buffering=0) as stream:
    boot = stream.read(4096)

bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
sectors_per_cluster = boot[13]
mft_encoding = struct.unpack_from("<b", boot, 64)[0]
if mft_encoding < 0:
    mft_record_size = 1 << -mft_encoding
else:
    mft_record_size = bytes_per_sector * sectors_per_cluster * mft_encoding
cluster_size = bytes_per_sector * sectors_per_cluster

print(f"bytes_per_sector={bytes_per_sector}")
print(f"sectors_per_cluster={sectors_per_cluster}")
print(f"cluster_size={cluster_size}")
print(f"mft_record_size={mft_record_size}")

if (bytes_per_sector, cluster_size, mft_record_size) != (4096, 4096, 1024):
    raise SystemExit("unexpected NTFS 4kn-c4k-m1k boot geometry")
PY
	then
		cat "$output" >&2
		classify_failure SETUP_BLOCKED
		exit 2
	fi
	cat "$output"
}

check_boot_geometry test "$TEST_DEV"
check_boot_geometry scratch "$SCRATCH_DEV"

if [[ ! -d "$XFSTESTS_DIR" ]]; then
	mkdir -p "$(dirname "$XFSTESTS_DIR")"
	tar -xzf "$ROOT_DIR/exfat-testsuites/xfstests-exfat.tgz" \
		-C "$(dirname "$XFSTESTS_DIR")"
fi

cp "$XFSTESTS_DIR/local.config.ntfs" "$XFSTESTS_DIR/local.config"
cat >> "$XFSTESTS_DIR/local.config" <<EOF

export TEST_DEV=$TEST_DEV
export TEST_DIR=$TEST_MNT
export SCRATCH_DEV=$SCRATCH_DEV
export SCRATCH_MNT=$SCRATCH_MNT
export FSTYP=ntfs
export MKFS_OPTIONS="-q -s 4096 -c 4096 -r 1024"
export MOUNT_OPTIONS="-osymlink=native,native_symlink=rel"
EOF

sudo mkdir -p "$TEST_MNT" "$SCRATCH_MNT"
make -C "$XFSTESTS_DIR" -j"$(( $(nproc) + 1 ))" > "$RESULTS_DIR/xfstests-build.log" 2>&1

printf 'case,status,exit_code\n' > "$RESULTS_DIR/results.csv"
while IFS= read -r test_case; do
	[[ -z "$test_case" ]] && continue
	safe_case=${test_case//\//_}
	log="$RESULTS_DIR/${safe_case}.log"
	set +e
	(
		cd "$XFSTESTS_DIR"
		sudo ./check "$test_case"
	) > "$log" 2>&1
	rc=$?
	set -e
	cat "$log"

	result_name=${test_case#generic/}
	if [[ -f "$XFSTESTS_DIR/results/generic/$result_name.notrun" ]]; then
		status=NOTRUN
		overall_status=2
	elif grep -Eiq '9p|timed out|timeout' "$log"; then
		status=ENVIRONMENT
		overall_status=3
	elif (( rc != 0 )) || [[ -f "$XFSTESTS_DIR/results/generic/$result_name.out.bad" ]]; then
		status=FAIL
		if (( overall_status < 1 )); then
			overall_status=1
		fi
	else
		status=PASS
	fi
	printf '%s,%s,%s\n' "$test_case" "$status" "$rc" >> "$RESULTS_DIR/results.csv"
done < "$RESULTS_DIR/tests.list"

sudo chmod -R a+rX "$XFSTESTS_DIR/results" 2>/dev/null || true

if grep -Eiq 'BUG:|Oops:|kernel panic|KASAN:|UBSAN:|general protection fault|Call Trace:' \
	"$RESULTS_DIR/dmesg-after.log"; then
	printf '%s\n' "KERNEL_FAULT" > "$RESULTS_DIR/classification.txt"
	exit 4
fi

if (( overall_status == 0 )); then
	printf '%s\n' "PASS" > "$RESULTS_DIR/classification.txt"
elif (( overall_status == 2 )); then
	printf '%s\n' "NOTRUN_OR_SETUP" > "$RESULTS_DIR/classification.txt"
elif (( overall_status == 3 )); then
	printf '%s\n' "ENVIRONMENT" > "$RESULTS_DIR/classification.txt"
else
	printf '%s\n' "FAIL" > "$RESULTS_DIR/classification.txt"
fi

exit "$overall_status"
