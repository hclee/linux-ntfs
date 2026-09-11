#!/usr/bin/env bash
# Run NTFS geometry xfstests profiles on qemu vm01 or vm02.
#
# The test device is formatted at profile setup and after ordinary test
# failures; xfstests formats the scratch device as needed.

set -Eeuo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VM_NAME=vm02
QEMU_ROOT=${QEMU_ROOT:-"$HOME/qemu-linux"}
VM_MANAGER="$QEMU_ROOT/vm_manager.sh"
KERNEL_VERSION=
PROFILE=
RUN_ALL=0
RUN_PATCHSET=0
TEST_SET=short
TESTS_FILE=
REPEAT_COUNT=1
ALLOW_FORMAT=0
RESULTS_DIR=
DRY_RUN=0
VM_STARTED=0
CURRENT_SECTOR=
CURRENT_MFT_RECORD_SIZE=
CURRENT_LOGICAL_BLOCK_SIZE=
CURRENT_PHYSICAL_BLOCK_SIZE=
NINEP_RETRIES=0
XFSTESTS_IMAGE=
XFSTESTS_IMAGE_DEVICE=/dev/disk/by-id/virtio-ntfs-xfstests
MKNTFS_PATH=

SHORT_TESTS_FILE="$SCRIPT_DIR/ntfs-geometry-short.list"
FULL_TESTS_FILE="$SCRIPT_DIR/ntfs-geometry-full.list"
TEST_DEVICE=/dev/vdc
SCRATCH_DEVICE=/dev/vdd

declare -a TEST_CASES=()
declare -A SEEN_TEST_CASES=()

usage()
{
	cat <<'EOF'
Usage:
  ntfs-vm02-xfstests.sh --kernel VERSION --profile PROFILE [options]
  ntfs-vm02-xfstests.sh --kernel VERSION --patchset [options]
  ntfs-vm02-xfstests.sh --kernel VERSION --all [options]

Required:
  --kernel VERSION       Kernel version accepted by vm_manager.sh
  --profile PROFILE      One profile from --list-profiles
  --patchset              Run the focused native-4Kn MFT patchset profiles
  --all                  Run all 512e/native-4Kn cluster and MFT profiles

Options:
  --vm vm01|vm02         VM to use (default: vm02)
  --set short|full       Select the built-in test list (default: short)
  --tests-file FILE      Use FILE instead of the built-in test list
  --repeat COUNT         Repeat each selected test COUNT times in one VM session
  --allow-format         Recreate and format the selected VM /dev/vdc and /dev/vdd
  --mkntfs PATH          Guest mkntfs with -r support
                         (default: /mnt/host-share/ntfsprogs-test/bin/mkntfs)
  --xfstests-image PATH  Use PATH as the selected VM's xfstests-dev.git image
  --9p-retries COUNT     Retry a pure 9p timeout from the same test
                         (guest allows up to 300s (5 minutes) for a 9p stall to clear;
                          default: 0; 0 disables retries)
  --results-dir DIR      Directory for this run's manifests and CSV
  --qemu-root DIR        qemu-linux directory (default: ~/qemu-linux)
  --dry-run              Validate arguments and print the selected matrix
  --list-profiles        Print supported profiles and exit
  -h, --help             Show this help

Each profile validates its configured MFT record size. The current profiles use
explicit -m1k and -m4k variants. The names without an MFT suffix are retained
as compatibility aliases: 1KiB for 512e and 4KiB for native-4Kn.

WARNING: --allow-format destroys the filesystems on the selected VM /dev/vdc
and /dev/vdd. Do not run this command while those devices contain data that
must be preserved.

After an ordinary xfstest failure, /dev/vdc is reformatted with the active
profile and the next test continues. VM faults, timeout/environment failures,
and reset failures stop the profile.
EOF
}

log()
{
	printf '%s %s\n' "$(date '+%F %T')" "$*"
}

die()
{
	log "ERROR: $*" >&2
	exit 1
}

csv_quote()
{
	local value=${1//\"/\"\"}

	printf '"%s"' "$value"
}

append_result()
{
	local profile=$1
	local geometry=$2
	local cluster=$3
	local test_set=$4
	local test_case=$5
	local status=$6
	local run_dir=$7
	local message=$8

	{
		csv_quote "$profile"
		printf ','
		csv_quote "$geometry"
		printf ','
		csv_quote "$cluster"
		printf ','
		csv_quote "$CURRENT_MFT_RECORD_SIZE"
		printf ','
		csv_quote "$test_set"
		printf ','
		csv_quote "$test_case"
		printf ','
		csv_quote "$status"
		printf ','
		csv_quote "$run_dir"
		printf ','
		csv_quote "$message"
		printf '\n'
	} >> "$RESULTS_DIR/results.csv"
}

profile_values()
{
	local profile=$1
	local base
	local mft_record_size

	case "$profile" in
	*-m1k)
		base=${profile%-m1k}
		mft_record_size=1024
		;;
	*-m4k)
		base=${profile%-m4k}
		mft_record_size=4096
		;;
	512e-*)
		base=$profile
		mft_record_size=1024
		;;
	4kn-*)
		base=$profile
		mft_record_size=4096
		;;
	*) return 1 ;;
	esac

	case "$base" in
	512e-c512)  printf '512e 512 4096 512 512 %s\n' "$mft_record_size" ;;
	512e-c1k)   printf '512e 512 4096 512 1024 %s\n' "$mft_record_size" ;;
	512e-c2k)   printf '512e 512 4096 512 2048 %s\n' "$mft_record_size" ;;
	512e-c4k)   printf '512e 512 4096 512 4096 %s\n' "$mft_record_size" ;;
	512e-c8k)   printf '512e 512 4096 512 8192 %s\n' "$mft_record_size" ;;
	512e-c16k)  printf '512e 512 4096 512 16384 %s\n' "$mft_record_size" ;;
	512e-c32k)  printf '512e 512 4096 512 32768 %s\n' "$mft_record_size" ;;
	512e-c64k)  printf '512e 512 4096 512 65536 %s\n' "$mft_record_size" ;;
	4kn-c4k)    printf '4kn 4096 4096 4096 4096 %s\n' "$mft_record_size" ;;
	4kn-c8k)    printf '4kn 4096 4096 4096 8192 %s\n' "$mft_record_size" ;;
	4kn-c16k)   printf '4kn 4096 4096 4096 16384 %s\n' "$mft_record_size" ;;
	4kn-c32k)   printf '4kn 4096 4096 4096 32768 %s\n' "$mft_record_size" ;;
	4kn-c64k)   printf '4kn 4096 4096 4096 65536 %s\n' "$mft_record_size" ;;
	*) return 1 ;;
	esac
}

all_profiles()
{
	printf '%s\n' \
		512e-c512-m1k 512e-c512-m4k \
		512e-c1k-m1k 512e-c1k-m4k \
		512e-c2k-m1k 512e-c2k-m4k \
		512e-c4k-m1k 512e-c4k-m4k \
		512e-c8k-m1k 512e-c8k-m4k \
		512e-c16k-m1k 512e-c16k-m4k \
		512e-c32k-m1k 512e-c32k-m4k \
		512e-c64k-m1k 512e-c64k-m4k \
		4kn-c4k-m1k 4kn-c4k-m4k \
		4kn-c8k-m1k 4kn-c8k-m4k \
		4kn-c16k-m1k 4kn-c16k-m4k \
		4kn-c32k-m1k 4kn-c32k-m4k \
		4kn-c64k-m1k 4kn-c64k-m4k
}

patchset_profiles()
{
	printf '%s\n' \
		4kn-c4k-m1k \
		4kn-c4k-m4k \
		4kn-c8k-m1k \
		512e-c4k-m1k
}

parse_test_list()
{
	local line
	local list_file=$1

	[ -r "$list_file" ] || die "test list is not readable: $list_file"

	mapfile -t TEST_CASES < <(sed -e '/^[[:space:]]*#/d' \
		-e '/^[[:space:]]*$/d' "$list_file")
	[ "${#TEST_CASES[@]}" -gt 0 ] || die "test list is empty: $list_file"

	for line in "${TEST_CASES[@]}"; do
		[[ "$line" =~ ^generic/[0-9]{3}$ ]] ||
			die "invalid xfstest case in $list_file: $line"
		[ -z "${SEEN_TEST_CASES[$line]+x}" ] ||
			die "duplicate xfstest case in $list_file: $line"
		SEEN_TEST_CASES[$line]=1
	done
}

expand_test_cases()
{
	local test_case
	local repeat
	local -a selected_test_cases=("${TEST_CASES[@]}")

	TEST_CASES=()
	for test_case in "${selected_test_cases[@]}"; do
		for ((repeat = 0; repeat < REPEAT_COUNT; repeat++)); do
			TEST_CASES+=("$test_case")
		done
	done
}

vm_manager()
{
	"$VM_MANAGER" --vm "$VM_NAME" "$@"
}

ensure_vm_stopped()
{
	local status

	if vm_manager status >/dev/null 2>&1; then
		die "$VM_NAME is already reachable; stop it before using /dev/vdc and /dev/vdd"
	else
		status=$?
	fi
	[ "$status" -ne 2 ] ||
		die "$VM_NAME has a running process but is not reachable; stop it first"
}

set_launcher_environment()
{
	local logical=$1
	local physical=$2

	clear_launcher_environment
	case "$VM_NAME" in
	vm01)
		export NTFS_VM01_USE_VDC_VDD=1
		export NTFS_VM01_LOGICAL_BLOCK_SIZE=$logical
		export NTFS_VM01_PHYSICAL_BLOCK_SIZE=$physical
		if [ -n "$XFSTESTS_IMAGE" ]; then
			export NTFS_VM01_XFSTESTS_IMG=$XFSTESTS_IMAGE
			export NTFS_VM01_USE_XFSTESTS_IMAGE=1
		fi
		;;
	vm02)
		export NTFS_VM02_USE_VDC_VDD=1
		export NTFS_VM02_LOGICAL_BLOCK_SIZE=$logical
		export NTFS_VM02_PHYSICAL_BLOCK_SIZE=$physical
		if [ -n "$XFSTESTS_IMAGE" ]; then
			export NTFS_VM02_XFSTESTS_IMG=$XFSTESTS_IMAGE
			export NTFS_VM02_USE_XFSTESTS_IMAGE=1
		fi
		;;
	esac
}

clear_launcher_environment()
{
	unset NTFS_VM01_USE_VDC_VDD
	unset NTFS_VM01_LOGICAL_BLOCK_SIZE NTFS_VM01_PHYSICAL_BLOCK_SIZE
	unset NTFS_VM01_XFSTESTS_IMG NTFS_VM01_USE_XFSTESTS_IMAGE
	unset NTFS_VM02_USE_VDC_VDD
	unset NTFS_VM02_LOGICAL_BLOCK_SIZE NTFS_VM02_PHYSICAL_BLOCK_SIZE
	unset NTFS_VM02_XFSTESTS_IMG NTFS_VM02_USE_XFSTESTS_IMAGE
}

set_vm_defaults()
{
	case "$VM_NAME" in
	vm01)
		[ -n "$MKNTFS_PATH" ] ||
			MKNTFS_PATH=${NTFS_VM01_MKNTFS_PATH:-/sbin/mkntfs}
		[ -n "$XFSTESTS_IMAGE" ] ||
			XFSTESTS_IMAGE=${NTFS_VM01_XFSTESTS_IMG:-$QEMU_ROOT/vm01-xfstests-dev.img}
		;;
	vm02)
		[ -n "$MKNTFS_PATH" ] ||
			MKNTFS_PATH=${NTFS_VM02_MKNTFS_PATH:-/mnt/host-share/ntfsprogs-test/bin/mkntfs}
		[ -n "$XFSTESTS_IMAGE" ] ||
			XFSTESTS_IMAGE=${NTFS_VM02_XFSTESTS_IMG:-}
		;;
	esac
}

query_guest_devices()
{
	local logical=$1
	local physical=$2
	local output

	output=$(
		vm_manager run bash -s -- "$TEST_DEVICE" "$SCRATCH_DEVICE" \
			"$logical" "$physical" <<'EOF'
set -eu

test_path=$1
scratch_path=$2
expected_logical=$3
expected_physical=$4

check_device()
{
	local name=$1
	local path=$2
	local actual_logical
	local actual_physical
	local block_name
	local rotational

	actual_logical=$(blockdev --getss "$path")
	actual_physical=$(blockdev --getpbsz "$path")
	block_name=$(basename "$(readlink -f "$path")")
	rotational=$(cat "/sys/class/block/$block_name/queue/rotational")
	[ "$actual_logical" -eq "$expected_logical" ] ||
		{ echo "$name logical sector is $actual_logical" >&2; return 1; }
	[ "$actual_physical" -eq "$expected_physical" ] ||
		{ echo "$name physical sector is $actual_physical" >&2; return 1; }
	[ "$rotational" -eq 1 ] ||
		{ echo "$name is not reported as rotational" >&2; return 1; }
	printf '%s=%s logical=%s physical=%s rotational=%s\n' \
		"$name" "$path" "$actual_logical" "$actual_physical" "$rotational"
}

[ -b "$test_path" ] || {
	echo "missing test device: $test_path" >&2
	exit 1
}
[ -b "$scratch_path" ] || {
	echo "missing scratch device: $scratch_path" >&2
	exit 1
}
check_device test "$test_path"
check_device scratch "$scratch_path"
printf 'test_device=%s\n' "$test_path"
printf 'scratch_device=%s\n' "$scratch_path"
EOF
	)
	printf '%s\n' "$output"
}

verify_guest_xfstests_drive()
{
vm_manager run bash -s -- "$XFSTESTS_IMAGE_DEVICE" "$VM_NAME" <<'EOF'
set -eu

image_device=$1
vm_name=$2
case "$vm_name" in
vm01) scratch_serial=ntfs-scratch ;;
vm02) scratch_serial=ntfs-geometry-scratc ;;
*) echo "invalid VM id: $vm_name" >&2; exit 1 ;;
esac

[ -b "$image_device" ] || {
echo "missing xfstests image device: $image_device" >&2
exit 1
}
image_path=$(readlink -f "$image_device")
image_name=${image_path##*/}
case "$image_name" in
vda|vdb|vdc|vdd)
echo "xfstests image overlaps a required device: $image_name" >&2
exit 1
;;
esac
image_serial=$(lsblk -dn -o SERIAL "$image_path" | tr -d '[:space:]')
[ "$image_serial" = ntfs-xfstests ] || {
echo "unexpected xfstests image serial: $image_serial" >&2
exit 1
}
for mapping in \
"vda ntfs-boot" \
"vdb ntfs-helper" \
"vdc ntfs-geometry-test" \
"vdd $scratch_serial"; do
set -- $mapping
path=/dev/disk/by-id/virtio-$2
[ -e "$path" ] || {
	echo "missing stable device path: $path" >&2
	exit 1
}
actual=$(basename "$(readlink -f "$path")")
[ "$actual" = "$1" ] || {
	echo "$2 is $actual, expected $1" >&2
	exit 1
}
done
if [ "$vm_name" = vm02 ]; then
path=/dev/disk/by-id/virtio-ntfs-corpus
[ -e "$path" ] || {
	echo "missing stable device path: $path" >&2
	exit 1
}
fi
printf 'xfstests_image=%s serial=%s\n' "$image_path" "$image_serial"
lsblk -dn -o NAME,SERIAL,TYPE
EOF
}

prepare_guest_xfstests_image()
{
local source_dir

case "$VM_NAME" in
vm01) source_dir=/mnt/host-share/xfstests-dev-02.git ;;
vm02) source_dir=/mnt/host-share/xfstests-dev.git ;;
*) return 1 ;;
esac

vm_manager run bash -s -- "$XFSTESTS_IMAGE_DEVICE" "$source_dir" <<'EOF'
set -eu

device=$1
source=$2
mount_dir=/mnt/xfstests-dev-image-init
mounted=0

cleanup()
{
if [ "$mounted" -eq 1 ]; then
	sync
	umount "$mount_dir"
fi
}
trap cleanup EXIT

[ -b "$device" ] || {
echo "missing xfstests image device: $device" >&2
exit 1
}
[ -d "$source" ] || {
echo "missing source xfstests tree: $source" >&2
exit 1
}
mkdir -p "$mount_dir"
mount -t ext4 "$device" "$mount_dir"
mounted=1
find "$mount_dir" -mindepth 1 -maxdepth 1 ! -name lost+found \
	-exec rm -rf -- {} +
cp -a -- "$source"/. "$mount_dir"/
rm -rf -- "$mount_dir/results/ntfs"
mkdir -p -- "$mount_dir/results/ntfs"
[ -x "$mount_dir/check" ] || {
echo "xfstests image lacks check: $mount_dir/check" >&2
exit 1
}
[ -d "$mount_dir/tests" ] || {
echo "xfstests image lacks tests directory: $mount_dir/tests" >&2
exit 1
}
sync
EOF
}

write_guest_config()
{
	local sector=$1
	local cluster=$2
	local mft_record_size=$3

	vm_manager run bash -s -- "$TEST_DEVICE" "$SCRATCH_DEVICE" "$sector" \
		"$cluster" "$mft_record_size" <<'EOF'
set -eu

config=/root/xfstests-dev.git/local.config.ntfs
backup=/root/xfstests-dev.git/local.config.ntfs.ntfs-geometry-backup
test_dev=$1
scratch_dev=$2
sector=$3
cluster=$4
mft_record_size=$5

if [ -e "$backup" ]; then
	mv -f -- "$backup" "$config"
fi
if [ -e "$config" ]; then
	cp -a -- "$config" "$backup"
fi

cat > "$config" <<CONFIG
[ntfs]
FSTYP=ntfs
TEST_DEV=$test_dev
TEST_DIR=/mnt/test
SCRATCH_DEV=$scratch_dev
SCRATCH_MNT=/mnt/scratch
MKFS_OPTIONS="-Q -s $sector -c $cluster -r $mft_record_size"
CANON_DEVS=yes
CONFIG
EOF
}

format_guest_test_device()
{
	local sector=$1
	local cluster=$2
	local mft_record_size=$3
	local mkfs_ntfs=/usr/local/bin/mkfs.ntfs

	vm_manager run bash -s -- "$mkfs_ntfs" "$TEST_DEVICE" "$sector" \
		"$cluster" "$mft_record_size" <<'EOF'
set -eu

mkfs_ntfs=$1
device=$2
sector=$3
cluster=$4
mft_record_size=$5

[ -x "$mkfs_ntfs" ] || {
	echo "missing mkfs.ntfs: $mkfs_ntfs" >&2
	exit 1
}
[ -b "$device" ] || {
	echo "missing test device: $device" >&2
	exit 1
}
if findmnt -rn -S "$device" >/dev/null 2>&1; then
	echo "test device is mounted: $device" >&2
	exit 1
fi
"$mkfs_ntfs" -Q -s "$sector" -c "$cluster" -r "$mft_record_size" "$device"
EOF
}

install_guest_formatter()
{
local mkntfs=$1

vm_manager run bash -s -- "$mkntfs" <<'EOF'
set -eu

source=$1
link=/usr/local/bin/mkfs.ntfs
backup=/usr/local/bin/mkfs.ntfs.ntfs-geometry-backup

[ -x "$source" ] || {
echo "MFT-capable mkntfs is not executable: $source" >&2
exit 1
}
"$source" --help 2>&1 | grep -F -- '--mft-record-size' >/dev/null || {
echo "mkntfs does not support --mft-record-size: $source" >&2
exit 1
}

if [ -L "$link" ] && [ "$(readlink "$link")" = "$source" ]; then
exit 0
fi
if [ -e "$backup" ] || [ -L "$backup" ]; then
echo "stale mkfs.ntfs backup exists: $backup" >&2
exit 1
fi
if [ -e "$link" ] || [ -L "$link" ]; then
mv -- "$link" "$backup"
fi
ln -s -- "$source" "$link"
"$link" --help 2>&1 | grep -F -- '--mft-record-size' >/dev/null
EOF
}

restore_guest_config()
{
vm_manager run bash -s -- "$MKNTFS_PATH" <<'EOF' || true
set -u
config=/root/xfstests-dev.git/local.config.ntfs
backup=/root/xfstests-dev.git/local.config.ntfs.ntfs-geometry-backup
source=$1
link=/usr/local/bin/mkfs.ntfs
formatter_backup=/usr/local/bin/mkfs.ntfs.ntfs-geometry-backup

if [ -e "$backup" ]; then
	mv -f -- "$backup" "$config"
fi
if [ -L "$link" ] && [ "$(readlink "$link")" = "$source" ]; then
	rm -f -- "$link"
	if [ -e "$formatter_backup" ] || [ -L "$formatter_backup" ]; then
		mv -f -- "$formatter_backup" "$link"
	fi
fi
EOF
}

validate_guest_geometry()
{
	local expected_sector=$1
	local expected_cluster=$2
	local expected_mft=$3

	vm_manager run bash -s -- "$TEST_DEVICE" "$expected_sector" \
		"$expected_cluster" "$expected_mft" <<'EOF'
set -eu

device=$1
expected_sector=$2
expected_cluster=$3
expected_mft=$4

read_u8()
{
	od -An -v -t u1 -j "$2" -N 1 "$1" |
		awk '{ print $1; exit }'
}

read_le16()
{
	local bytes
	local b0
	local b1

	bytes=$(od -An -v -t u1 -j "$2" -N 2 "$1")
	read -r b0 b1 <<< "$bytes"
	printf '%s\n' $((b0 | (b1 << 8)))
}

bytes_per_sector=$(read_le16 "$device" 11)
sectors_per_cluster=$(read_u8 "$device" 13)
cluster_size=$((bytes_per_sector * sectors_per_cluster))
mft_encoding=$(read_u8 "$device" 64)
if [ "$mft_encoding" -ge 128 ]; then
	mft_record_size=$((1 << (256 - mft_encoding)))
else
	mft_record_size=$((mft_encoding * cluster_size))
fi

[ "$bytes_per_sector" -eq "$expected_sector" ] ||
	{ echo "guest NTFS sector is $bytes_per_sector" >&2; exit 1; }
[ "$cluster_size" -eq "$expected_cluster" ] ||
	{ echo "guest NTFS cluster is $cluster_size" >&2; exit 1; }
[ "$mft_record_size" -eq "$expected_mft" ] ||
	{ echo "guest NTFS MFT record is $mft_record_size" >&2; exit 1; }
printf 'guest_ntfs sector=%s cluster=%s mft=%s\n' \
	"$bytes_per_sector" "$cluster_size" "$mft_record_size"
EOF
}

reset_profile_filesystem()
{
	local sector=$1
	local cluster=$2
	local mft_record_size=$3
	local device_output
	local setup_output

	log "Resetting profile filesystem before the next test"
	if ! device_output=$(query_guest_devices "$CURRENT_LOGICAL_BLOCK_SIZE" \
		"$CURRENT_PHYSICAL_BLOCK_SIZE" 2>&1); then
		log "Guest device validation failed during profile reset: $device_output"
		return 1
	fi
	printf '%s\n' "$device_output"

	if ! setup_output=$(vm_manager run bash -s 2>&1 <<'EOF'
set -eu

for mount_dir in /mnt/test /mnt/scratch /mnt/ntfs-geometry-check; do
	if mountpoint -q "$mount_dir"; then
		umount "$mount_dir"
	fi
done
sync
EOF
	); then
		log "Guest mount cleanup failed during profile reset: $setup_output"
		return 1
	fi

	if ! setup_output=$(install_guest_formatter "$MKNTFS_PATH" 2>&1); then
		log "Guest formatter setup failed during profile reset: $setup_output"
		return 1
	fi
	if ! setup_output=$(write_guest_config "$sector" "$cluster" \
		"$mft_record_size" 2>&1); then
		log "Guest xfstests config setup failed during profile reset: $setup_output"
		return 1
	fi
	if ! setup_output=$(format_guest_test_device "$sector" "$cluster" \
		"$mft_record_size" 2>&1); then
		log "Test device reformat failed during profile reset: $setup_output"
		return 1
	fi
	if ! setup_output=$(validate_guest_geometry "$sector" "$cluster" \
		"$mft_record_size" 2>&1); then
		log "NTFS geometry validation failed during profile reset: $setup_output"
		return 1
	fi
	printf '%s\n' "$setup_output"
}

postcheck_guest_rw()
{
	vm_manager run bash -s -- "$TEST_DEVICE" <<'EOF'
set -eu

device=$1
mount_dir=/mnt/ntfs-geometry-check
check_file=$mount_dir/.ntfs-geometry-check
before=
after=

mkdir -p "$mount_dir"
if mountpoint -q "$mount_dir"; then
	umount "$mount_dir"
fi

mount -t ntfs "$device" "$mount_dir"
dd if=/dev/zero of="$check_file" bs=4096 count=32 conv=fsync status=none
before=$(sha256sum "$check_file" | awk '{ print $1 }')
sync
umount "$mount_dir"

mount -t ntfs "$device" "$mount_dir"
after=$(sha256sum "$check_file" | awk '{ print $1 }')
[ "$before" = "$after" ] ||
	{ echo "post-remount checksum mismatch" >&2; exit 1; }
rm -f -- "$check_file"
sync
umount "$mount_dir"
printf 'postcheck checksum=%s\n' "$after"
EOF
}

newest_run_dir()
{
	local log_file=$1
	local run_dir

	run_dir=$(awk '
		/xfstests run directory: / {
			sub(/^.*xfstests run directory: /, "")
			print
		}
		/artifacts: / {
			sub(/^.*artifacts: /, "")
			print
		}
	' "$log_file" |
		tail -n 1)
	if [ -n "$run_dir" ] && [ -d "$run_dir" ]; then
		printf '%s\n' "$run_dir"
	fi
}

run_test_case()
{
	local profile=$1
	local geometry=$2
	local cluster=$3
	local test_set=$4
	local test_case=$5
	local profile_dir="$RESULTS_DIR/$profile"
	local test_id=${test_case//\//_}
	local attempt=0
	local attempt_log
	local attempt_run_dir
	local run_dirs=
	local vm_status
	local validation
	local message
	local notrun_file
	local notrun_reason

	while :; do
		attempt_log="$profile_dir/${test_set}-${test_id}.attempt-${attempt}.vm-manager.log"
		log "Running $profile $test_set $test_case (attempt $((attempt + 1)))"
		set +e
		vm_manager run_xfstests ntfs "$test_case" 2>&1 |
			tee "$attempt_log"
		vm_status=${PIPESTATUS[0]}
		set -e

		attempt_run_dir=$(newest_run_dir "$attempt_log" || true)
		if [ -n "$attempt_run_dir" ]; then
			if [ -n "$run_dirs" ]; then
				run_dirs="$run_dirs;$attempt_run_dir"
			else
				run_dirs=$attempt_run_dir
			fi
		fi
		message="attempts=$((attempt + 1));9p_retries=$attempt;run_dirs=$run_dirs"

		case "$vm_status" in
		0)
			if [ -n "$attempt_run_dir" ]; then
				notrun_file="$attempt_run_dir/results/ntfs/$test_case.notrun"
				if [ -f "$notrun_file" ]; then
					if ! validation=$(validate_guest_geometry \
						"$CURRENT_SECTOR" "$cluster" \
						"$CURRENT_MFT_RECORD_SIZE" 2>&1); then
						append_result "$profile" "$geometry" "$cluster" \
							"$test_set" "$test_case" SETUP_BLOCKED \
							"$run_dirs" "$message;$validation"
						log "NTFS geometry validation failed after $test_case"
						return 2
					fi
					notrun_reason=$(tr '\n' ' ' < "$notrun_file" |
						sed 's/[[:space:]]*$//')
					append_result "$profile" "$geometry" "$cluster" \
						"$test_set" "$test_case" NOTRUN "$run_dirs" \
						"$message;$validation;reason=$notrun_reason"
					log "$test_case not run: $notrun_reason"
					return 0
				fi
			fi
			if validation=$(validate_guest_geometry "$CURRENT_SECTOR" "$cluster" \
				"$CURRENT_MFT_RECORD_SIZE" 2>&1); then
				append_result "$profile" "$geometry" "$cluster" "$test_set" \
					"$test_case" PASS "$run_dirs" "$message;$validation"
				return 0
			fi
			append_result "$profile" "$geometry" "$cluster" "$test_set" \
				"$test_case" SETUP_BLOCKED "$run_dirs" \
				"$message;$validation"
			log "NTFS geometry validation failed after $test_case"
			return 2
			;;
		1)
			if ! validation=$(validate_guest_geometry "$CURRENT_SECTOR" "$cluster" \
				"$CURRENT_MFT_RECORD_SIZE" 2>&1); then
				append_result "$profile" "$geometry" "$cluster" "$test_set" \
					"$test_case" SETUP_BLOCKED "$run_dirs" \
					"$message;$validation"
				log "NTFS geometry validation failed after $test_case"
				return 2
			fi
			append_result "$profile" "$geometry" "$cluster" "$test_set" \
				"$test_case" FAIL "$run_dirs" \
				"$message;xfstests exit status 1;$validation"
			return 1
			;;
		125)
			if [ "$attempt" -ge "$NINEP_RETRIES" ]; then
				append_result "$profile" "$geometry" "$cluster" "$test_set" \
					"$test_case" ENV_9P_TIMEOUT "$run_dirs" "$message"
				log "$test_case exhausted 9p retry limit ($NINEP_RETRIES)"
				return 4
			fi
			attempt=$((attempt + 1))
			if ! reset_profile_filesystem "$CURRENT_SECTOR" "$cluster" \
				"$CURRENT_MFT_RECORD_SIZE"; then
				append_result "$profile" "$geometry" "$cluster" "$test_set" \
					"$test_case" SETUP_BLOCKED "$run_dirs" \
					"$message;failed to reset after 9p timeout"
				return 2
			fi
			continue
			;;
		2|3|124)
			append_result "$profile" "$geometry" "$cluster" "$test_set" \
				"$test_case" VM_FAULT "$run_dirs" \
				"$message;vm_manager exit status $vm_status"
			return 3
			;;
		*)
			append_result "$profile" "$geometry" "$cluster" "$test_set" \
				"$test_case" FAIL "$run_dirs" \
				"$message;vm_manager exit status $vm_status"
			return 1
			;;
		esac
	done
}

run_profile()
{
	local profile=$1
	local geometry
	local logical
	local physical
	local sector
	local cluster
	local profile_dir="$RESULTS_DIR/$profile"
	local test_case
	local profile_status=0
	local test_status
	local device_output
	local setup_output
	local mft_record_size

	read -r geometry logical physical sector cluster mft_record_size < \
		<(profile_values "$profile")
	CURRENT_LOGICAL_BLOCK_SIZE=$logical
	CURRENT_PHYSICAL_BLOCK_SIZE=$physical
	CURRENT_SECTOR=$sector
	CURRENT_MFT_RECORD_SIZE=$mft_record_size
	mkdir -p "$profile_dir"
	{
		printf 'profile=%s\n' "$profile"
		printf 'geometry=%s\nlogical_block_size=%s\nphysical_block_size=%s\n' \
			"$geometry" "$logical" "$physical"
		printf 'ntfs_sector_size=%s\ncluster_size=%s\nmft_record_size=%s\n' \
			"$sector" "$cluster" "$mft_record_size"
		printf 'test_device=%s\nscratch_device=%s\n' \
			"$TEST_DEVICE" "$SCRATCH_DEVICE"
		printf 'mkntfs_path=%s\n' "$MKNTFS_PATH"
		printf '9p_retries=%s\n' "$NINEP_RETRIES"
		printf 'xfstests_image=%s\nxfstests_image_device=%s\n' \
			"${XFSTESTS_IMAGE:-none}" "$XFSTESTS_IMAGE_DEVICE"
		printf 'test_set=%s\ntests_file=%s\nstarted=%s\n' \
			"$TEST_SET" "$TESTS_FILE" "$(date --iso-8601=seconds)"
	} > "$profile_dir/manifest"

	if [ "$DRY_RUN" -eq 1 ]; then
		printf 'outcome=DRY_RUN\n' >> "$profile_dir/manifest"
		return 0
	fi

	ensure_vm_stopped
	set_launcher_environment "$logical" "$physical"
	if ! vm_manager start "$KERNEL_VERSION"; then
		append_result "$profile" "$geometry" "$cluster" "$TEST_SET" \
			start VM_FAULT "" "failed to start $VM_NAME"
		printf 'outcome=VM_FAULT\n' >> "$profile_dir/manifest"
		clear_launcher_environment
		return 3
	fi
	VM_STARTED=1

	if [ -n "$XFSTESTS_IMAGE" ]; then
		if ! setup_output=$(verify_guest_xfstests_drive 2>&1); then
			append_result "$profile" "$geometry" "$cluster" "$TEST_SET" \
				setup SETUP_BLOCKED "" "$setup_output"
			printf 'xfstests_image_drive=%s\noutcome=SETUP_BLOCKED\n' \
				"$setup_output" >> "$profile_dir/manifest"
			vm_manager stop || true
			VM_STARTED=0
			clear_launcher_environment
			return 2
		fi
		printf 'xfstests_image_drive=%s\n' "$setup_output" >> "$profile_dir/manifest"
	fi

	if ! device_output=$(query_guest_devices "$logical" "$physical" 2>&1); then
		append_result "$profile" "$geometry" "$cluster" "$TEST_SET" \
			setup SETUP_BLOCKED "" "$device_output"
		printf 'guest_devices=%s\noutcome=SETUP_BLOCKED\n' \
			"$device_output" >> "$profile_dir/manifest"
		restore_guest_config
		vm_manager stop || true
		VM_STARTED=0
		clear_launcher_environment
		return 2
	fi
	printf 'guest_devices=%s\n' "$device_output" >> "$profile_dir/manifest"

	if ! setup_output=$(install_guest_formatter "$MKNTFS_PATH" 2>&1); then
		append_result "$profile" "$geometry" "$cluster" "$TEST_SET" \
			setup SETUP_BLOCKED "" "$setup_output"
		printf 'setup=%s\noutcome=SETUP_BLOCKED\n' \
			"$setup_output" >> "$profile_dir/manifest"
		restore_guest_config
		vm_manager stop || true
		VM_STARTED=0
		clear_launcher_environment
		return 2
	fi

	if ! setup_output=$(write_guest_config "$sector" "$cluster" \
		"$mft_record_size" 2>&1); then
		append_result "$profile" "$geometry" "$cluster" "$TEST_SET" \
			setup SETUP_BLOCKED "" "$setup_output"
		printf 'setup=%s\noutcome=SETUP_BLOCKED\n' \
			"$setup_output" >> "$profile_dir/manifest"
		restore_guest_config
		vm_manager stop || true
		VM_STARTED=0
		clear_launcher_environment
		return 2
	fi

	if [ -n "$XFSTESTS_IMAGE" ]; then
		if ! setup_output=$(prepare_guest_xfstests_image 2>&1); then
			append_result "$profile" "$geometry" "$cluster" "$TEST_SET" \
				setup SETUP_BLOCKED "" "$setup_output"
			printf 'xfstests_image_prepare=%s\noutcome=SETUP_BLOCKED\n' \
				"$setup_output" >> "$profile_dir/manifest"
			restore_guest_config
			vm_manager stop || true
			VM_STARTED=0
			clear_launcher_environment
			return 2
		fi
		printf 'xfstests_image_prepare=%s\n' "$setup_output" >> "$profile_dir/manifest"
	fi

	if ! setup_output=$(format_guest_test_device "$sector" "$cluster" \
		"$mft_record_size" 2>&1); then
		append_result "$profile" "$geometry" "$cluster" "$TEST_SET" \
			setup SETUP_BLOCKED "" "$setup_output"
		printf 'setup=%s\noutcome=SETUP_BLOCKED\n' \
			"$setup_output" >> "$profile_dir/manifest"
		restore_guest_config
		vm_manager stop || true
		VM_STARTED=0
		clear_launcher_environment
		return 2
	fi

	if ! setup_output=$(validate_guest_geometry "$sector" "$cluster" \
		"$mft_record_size" 2>&1); then
		append_result "$profile" "$geometry" "$cluster" "$TEST_SET" \
			setup SETUP_BLOCKED "" "$setup_output"
		printf 'setup=%s\noutcome=SETUP_BLOCKED\n' \
			"$setup_output" >> "$profile_dir/manifest"
		restore_guest_config
		vm_manager stop || true
		VM_STARTED=0
		clear_launcher_environment
		return 2
	fi
	printf 'test_device_geometry=%s\n' "$setup_output" >> "$profile_dir/manifest"

	for test_case in "${TEST_CASES[@]}"; do
		test_status=0
		run_test_case "$profile" "$geometry" "$cluster" "$TEST_SET" \
			"$test_case" || test_status=$?
		if [ "$test_status" -eq 0 ]; then
			continue
		fi
		case "$test_status" in
		2) profile_status=2 ;;
		3) profile_status=3 ;;
		4) profile_status=4 ;;
		*)
			if [ "$profile_status" -eq 0 ]; then
				profile_status=1
			fi
			;;
		esac
		[ "$profile_status" -ge 2 ] && break
		if ! reset_profile_filesystem "$CURRENT_SECTOR" "$cluster" \
			"$CURRENT_MFT_RECORD_SIZE"; then
			printf 'profile_reset_failed_after=%s\n' "$test_case" \
				>> "$profile_dir/manifest"
			profile_status=2
			break
		fi
		printf 'profile_reset_after=%s\n' "$test_case" >> "$profile_dir/manifest"
	done

	if [ "$profile_status" -lt 2 ]; then
		if postcheck=$(postcheck_guest_rw 2>&1); then
			append_result "$profile" "$geometry" "$cluster" "$TEST_SET" \
				postcheck PASS "" "$postcheck"
		else
			append_result "$profile" "$geometry" "$cluster" "$TEST_SET" \
				postcheck FAIL "" "$postcheck"
			if [ "$profile_status" -eq 0 ]; then
				profile_status=1
			fi
		fi
	fi

	restore_guest_config
	vm_manager stop || true
	VM_STARTED=0
	clear_launcher_environment
	case "$profile_status" in
	0) printf 'outcome=PASS\n' >> "$profile_dir/manifest" ;;
	1) printf 'outcome=FAIL\n' >> "$profile_dir/manifest" ;;
	2) printf 'outcome=SETUP_BLOCKED\n' >> "$profile_dir/manifest" ;;
	3) printf 'outcome=VM_FAULT\n' >> "$profile_dir/manifest" ;;
	4) printf 'outcome=ENV_9P_TIMEOUT\n' >> "$profile_dir/manifest" ;;
	esac
	return "$profile_status"
}

cleanup()
{
	if [ "$VM_STARTED" -eq 1 ]; then
		vm_manager stop >/dev/null 2>&1 || true
		VM_STARTED=0
	fi
	clear_launcher_environment
}

print_profiles()
{
	printf '512e profiles (logical/physical=512/4096, NTFS sector=512):\n'
	all_profiles | awk '/^512e-/'
	printf 'native-4Kn profiles (logical/physical=4096/4096, NTFS sector=4096):\n'
	all_profiles | awk '/^4kn-/'
	printf 'focused native-4Kn MFT patchset profiles:\n'
	patchset_profiles
}

main()
{
	local arg
	local profile
	local result
	local overall_status=0
	local selected_profiles=()
	local -A profile_status=()
	local profile_selection

	while [ "$#" -gt 0 ]; do
		arg=$1
		case "$arg" in
		--vm)
			[ "$#" -ge 2 ] || die "--vm requires a value"
			VM_NAME=$2
			shift 2
			;;
		--kernel)
			[ "$#" -ge 2 ] || die "--kernel requires a value"
			KERNEL_VERSION=$2
			shift 2
			;;
		--profile)
			[ "$#" -ge 2 ] || die "--profile requires a value"
			[ "$RUN_ALL" -eq 0 ] && [ "$RUN_PATCHSET" -eq 0 ] ||
				die "--profile, --patchset, and --all are mutually exclusive"
			PROFILE=$2
			shift 2
			;;
		--all)
			[ -z "$PROFILE" ] && [ "$RUN_PATCHSET" -eq 0 ] ||
				die "--profile, --patchset, and --all are mutually exclusive"
			RUN_ALL=1
			shift
			;;
		--patchset)
			[ -z "$PROFILE" ] && [ "$RUN_ALL" -eq 0 ] ||
				die "--profile, --patchset, and --all are mutually exclusive"
			RUN_PATCHSET=1
			shift
			;;
		--set)
			[ "$#" -ge 2 ] || die "--set requires short or full"
			case "$2" in
			short|full) TEST_SET=$2 ;;
			*) die "invalid test set: $2" ;;
			esac
			shift 2
			;;
		--tests-file)
			[ "$#" -ge 2 ] || die "--tests-file requires a path"
			TESTS_FILE=$2
			TEST_SET=custom
			shift 2
			;;
		--repeat)
			[ "$#" -ge 2 ] || die "--repeat requires a positive integer"
			[[ "$2" =~ ^[1-9][0-9]*$ ]] ||
				die "--repeat requires a positive integer"
			REPEAT_COUNT=$2
			shift 2
			;;
		--allow-format)
			ALLOW_FORMAT=1
			shift
			;;
		--mkntfs)
			[ "$#" -ge 2 ] || die "--mkntfs requires a guest path"
			MKNTFS_PATH=$2
			shift 2
			;;
		--xfstests-image)
			[ "$#" -ge 2 ] || die "--xfstests-image requires a path"
			XFSTESTS_IMAGE=$2
			shift 2
			;;
		--9p-retries)
			[ "$#" -ge 2 ] || die "--9p-retries requires a non-negative integer"
			[[ "$2" =~ ^[0-9]+$ ]] ||
				die "--9p-retries requires a non-negative integer"
			NINEP_RETRIES=$2
			shift 2
			;;
		--results-dir)
			[ "$#" -ge 2 ] || die "--results-dir requires a path"
			RESULTS_DIR=$2
			shift 2
			;;
		--qemu-root)
			[ "$#" -ge 2 ] || die "--qemu-root requires a path"
			QEMU_ROOT=$2
			VM_MANAGER="$QEMU_ROOT/vm_manager.sh"
			shift 2
			;;
		--dry-run)
			DRY_RUN=1
			shift
			;;
		--list-profiles)
			print_profiles
			return 0
			;;
		-h|--help)
			usage
			return 0
			;;
		*) die "unknown option: $arg" ;;
		esac
	done

	case "$VM_NAME" in
	vm01|vm02) ;;
	*) die "invalid VM: $VM_NAME (use vm01 or vm02)" ;;
	esac
	set_vm_defaults
	[ -n "$KERNEL_VERSION" ] || die "--kernel is required"
	[[ "$KERNEL_VERSION" =~ ^[A-Za-z0-9._-]+$ ]] ||
		die "invalid kernel version: $KERNEL_VERSION"
	[ -n "$PROFILE" ] || [ "$RUN_ALL" -eq 1 ] || [ "$RUN_PATCHSET" -eq 1 ] ||
		die "specify --profile PROFILE, --patchset, or --all"
	[ -z "$PROFILE" ] || profile_values "$PROFILE" >/dev/null ||
		die "unknown profile: $PROFILE"
	[[ "$NINEP_RETRIES" =~ ^[0-9]+$ ]] ||
		die "9p retry count must be a non-negative integer"
	[[ "$REPEAT_COUNT" =~ ^[1-9][0-9]*$ ]] ||
		die "repeat count must be a positive integer"
	[ "$ALLOW_FORMAT" -eq 1 ] || [ "$DRY_RUN" -eq 1 ] ||
		die "a real run requires --allow-format because xfstests reformats both devices"
	if [ -n "$XFSTESTS_IMAGE" ]; then
		[ -f "$XFSTESTS_IMAGE" ] ||
			die "xfstests image is not a regular file: $XFSTESTS_IMAGE"
		image_size=$(stat -c %s "$XFSTESTS_IMAGE") ||
			die "cannot stat xfstests image: $XFSTESTS_IMAGE"
		[ "$image_size" -ge $((2 * 1024 * 1024 * 1024)) ] ||
			die "xfstests image must be at least 2 GiB: $XFSTESTS_IMAGE"
	fi
	VM_MANAGER="$QEMU_ROOT/vm_manager.sh"

	[ -x "$VM_MANAGER" ] || die "missing vm manager: $VM_MANAGER"
	case "$VM_NAME" in
	vm01)
		launcher="$QEMU_ROOT/run_vm_01.sh"
		launcher_hook=NTFS_VM01_USE_VDC_VDD
		;;
	vm02)
		launcher="$QEMU_ROOT/run_vm_02.sh"
		launcher_hook=NTFS_VM02_USE_VDC_VDD
		;;
	esac
	[ -x "$launcher" ] || die "missing VM launcher: $launcher"
	grep -q "$launcher_hook" "$launcher" ||
		die "$launcher lacks the geometry launcher hook: $launcher_hook"

	if [ -n "$TESTS_FILE" ]; then
		:
	elif [ "$TEST_SET" = short ]; then
		TESTS_FILE=$SHORT_TESTS_FILE
	else
		TESTS_FILE=$FULL_TESTS_FILE
	fi
	parse_test_list "$TESTS_FILE"
	expand_test_cases

	if [ -z "$RESULTS_DIR" ]; then
		RESULTS_DIR="$QEMU_ROOT/host-share-dir/agent-automation/ntfs-geometry-results/$(date '+%Y%m%d-%H%M%S')"
	fi
	mkdir -p "$RESULTS_DIR"
	printf 'profile,geometry,cluster_size,mft_record_size,test_set,test_case,status,run_dir,message\n' \
		> "$RESULTS_DIR/results.csv"
	printf 'kernel=%s\nvm=%s\nmft_record_size=profile-specific\ntests_file=%s\n' \
		"$KERNEL_VERSION" "$VM_NAME" "$TESTS_FILE" \
		> "$RESULTS_DIR/manifest"
	printf 'test_device=%s\nscratch_device=%s\nmkntfs_path=%s\n' \
		"$TEST_DEVICE" "$SCRATCH_DEVICE" "$MKNTFS_PATH" \
		>> "$RESULTS_DIR/manifest"
	printf '9p_retries=%s\n' "$NINEP_RETRIES" >> "$RESULTS_DIR/manifest"
	printf 'repeat_count=%s\n' "$REPEAT_COUNT" >> "$RESULTS_DIR/manifest"

	if [ "$RUN_ALL" -eq 1 ]; then
		mapfile -t selected_profiles < <(all_profiles)
		profile_selection=all
	elif [ "$RUN_PATCHSET" -eq 1 ]; then
		mapfile -t selected_profiles < <(patchset_profiles)
		profile_selection=patchset
	else
		selected_profiles=("$PROFILE")
		profile_selection=profile
	fi
	for profile in "${selected_profiles[@]}"; do
		profile_values "$profile" >/dev/null ||
			die "unknown profile: $profile"
	done

	printf 'kernel=%s vm=%s test_set=%s tests=%s results=%s\n' \
		"$KERNEL_VERSION" "$VM_NAME" "$TEST_SET" "${#TEST_CASES[@]}" \
		"$RESULTS_DIR"
	printf 'profile_selection=%s\n' "$profile_selection" >> "$RESULTS_DIR/manifest"
	for profile in "${selected_profiles[@]}"; do
		log "Starting profile $profile"
		set +e
		run_profile "$profile"
		result=$?
		set -e
		profile_status["$profile"]=$result
		if [ "$result" -ne 0 ]; then
			case "$result" in
			4) overall_status=4 ;;
			3)
				if [ "$overall_status" -lt 3 ]; then
					overall_status=3
				fi
				;;
			2)
				if [ "$overall_status" -lt 2 ]; then
					overall_status=2
				fi
				;;
			*)
				if [ "$overall_status" -eq 0 ]; then
					overall_status=1
				fi
				;;
			esac
		fi
	done

	printf '\nProfile summary:\n'
	for profile in "${selected_profiles[@]}"; do
		if [ "${profile_status[$profile]}" -eq 0 ]; then
			printf '%s: SUCCESS\n' "$profile"
		else
			printf '%s: FAIL\n' "$profile"
		fi
	done

	printf 'finished=%s\noutcome=%s\n' "$(date --iso-8601=seconds)" \
		"$overall_status" >> "$RESULTS_DIR/manifest"
	return "$overall_status"
}

trap cleanup EXIT INT TERM
main "$@"
