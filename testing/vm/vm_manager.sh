#!/usr/bin/env bash
# Manage the VM used by the OpenCode xfstests development loop.
set -u -o pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
AUTOMATION_DIR="$ROOT_DIR/host-share-dir/agent-automation"
RUNS_DIR="$AUTOMATION_DIR/runs"
VM_NAME=vm02
GUEST_PATH=/mnt/host-share/sbin:/mnt/host-share/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
GUEST_LD_LIBRARY_PATH=/mnt/host-share/lib
NTFS_9P_MOUNT_OPTIONS=${NTFS_9P_MOUNT_OPTIONS:-msize=512000,cache=loose}
NTFS_XFSTESTS_IMAGE_DEVICE=${NTFS_XFSTESTS_IMAGE_DEVICE:-/dev/disk/by-id/virtio-ntfs-xfstests}

configure_vm()
{
    case "$VM_NAME" in
        vm01)
            VM_SCRIPT=run_vm_01.sh
            VM_ID=vm01
            MONITOR_SOCKET="$ROOT_DIR/qemu-monitor-socket"
            SSH_PORT=8022
            ;;
        vm02)
            VM_SCRIPT=run_vm_02.sh
            VM_ID=vm02
            MONITOR_SOCKET="$ROOT_DIR/qemu-monitor-socket-02"
            SSH_PORT=9022
            ;;
        *)
            die "invalid VM: $VM_NAME (use vm01 or vm02)"
            ;;
    esac

    PID_FILE="$AUTOMATION_DIR/$VM_NAME.pid"
    KERNEL_FILE="$AUTOMATION_DIR/$VM_NAME.kernel"
    CONSOLE_LOG="$AUTOMATION_DIR/$VM_NAME.console.log"
    OPERATION_LOCK_FILE="$AUTOMATION_DIR/$VM_NAME.lock"
    VM_LOCK_FILE="$AUTOMATION_DIR/$VM_NAME.locked"
    SSH_OPTS=(
        -o BatchMode=yes
        -o ConnectTimeout=5
        -o ConnectionAttempts=1
        -o ServerAliveInterval=15
        -o ServerAliveCountMax=4
        -o LogLevel=ERROR
        -o StrictHostKeyChecking=no
        -o UserKnownHostsFile=/dev/null
        -p "$SSH_PORT"
        root@localhost
    )
}

usage()
{
    cat <<'EOF'
Usage:
  vm_manager.sh [--vm vm01|vm02] start <kernel-version>
  vm_manager.sh [--vm vm01|vm02] stop
  vm_manager.sh [--vm vm01|vm02] restart <kernel-version>
  vm_manager.sh [--vm vm01|vm02] status
  vm_manager.sh [--vm vm01|vm02] lock
  vm_manager.sh [--vm vm01|vm02] unlock
  vm_manager.sh [--vm vm01|vm02] run <command> [argument ...]
  vm_manager.sh [--vm vm01|vm02] run_xfstests <fstype> <test-case> [test-case ...]
  vm_manager.sh [--vm vm01|vm02] prune_logs <retention-days>

VM 01 is the default. The run and run_xfstests commands execute on an already
running selected VM. run_xfstests stores per-run artifacts under
host-share-dir/agent-automation/runs and restarts the VM after a panic, Oops,
warning, or SSH loss. prune_logs removes run artifact directories older than
the specified number of calendar days, including today.
run_xfstests temporarily uses NTFS_9P_MOUNT_OPTIONS for the host share and
restores the default 9p mount options before returning. When the selected
VM's NTFS_VM01_USE_XFSTESTS_IMAGE or NTFS_VM02_USE_XFSTESTS_IMAGE is set to
1, only /root/xfstests-dev.git is mounted from the optional xfstests image;
the other host-share bind mounts remain 9p.
vm01 uses host-share-dir/xfstests-dev-02.git for /root/xfstests-dev.git;
vm02 uses host-share-dir/xfstests-dev.git.
The lock command prevents start, stop, restart, run, and run_xfstests for the
selected VM until unlock is called. Locking does not stop a running VM.
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

prepare_dirs()
{
    mkdir -p "$RUNS_DIR"
}

vm_locked()
{
    [ -e "$VM_LOCK_FILE" ]
}

ensure_vm_unlocked()
{
    if vm_locked; then
        die "$VM_NAME is locked; run '$0 --vm $VM_NAME unlock' to unlock it"
    fi
}

lock_vm()
{
    prepare_dirs
    if vm_locked; then
        die "$VM_NAME is already locked"
    fi

    if ! {
        printf 'locked_by=%s\n' "${USER:-unknown}"
        printf 'locked_at=%s\n' "$(date --iso-8601=seconds)"
    } > "$VM_LOCK_FILE"; then
        die "failed to create lock file for $VM_NAME"
    fi
    log "$VM_NAME locked"
}

unlock_vm()
{
    if ! vm_locked; then
        die "$VM_NAME is not locked"
    fi

    rm -f -- "$VM_LOCK_FILE" ||
        die "failed to remove lock file for $VM_NAME"
    log "$VM_NAME unlocked"
}

ssh_ready()
{
    ssh "${SSH_OPTS[@]}" true </dev/null >/dev/null 2>&1
}

tracked_vm_running()
{
    local pid

    [ -r "$PID_FILE" ] || return 1
    read -r pid < "$PID_FILE"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

wait_for_ssh()
{
    local deadline=$((SECONDS + 180))

    while [ "$SECONDS" -lt "$deadline" ]; do
        if ssh_ready; then
            return 0
        fi
        sleep 2
    done

    return 1
}

start_vm()
{
    local kernel_version=$1

    ensure_vm_unlocked
    prepare_dirs
    if ssh_ready; then
        log "$VM_NAME is already reachable on SSH port $SSH_PORT"
        return 0
    fi

    if tracked_vm_running; then
        die "tracked VM is running but SSH is unavailable; run 'stop' before starting again"
    fi

    if [ -S "$MONITOR_SOCKET" ]; then
        if command -v socat >/dev/null 2>&1 &&
           printf 'info status\n' | socat - UNIX-CONNECT:"$MONITOR_SOCKET" \
               >/dev/null 2>&1; then
            die "monitor socket $MONITOR_SOCKET belongs to an untracked VM"
        fi
        log "Removing stale monitor socket $MONITOR_SOCKET"
        rm -f "$MONITOR_SOCKET"
    fi

    log "Starting $VM_NAME with kernel $kernel_version"
    : > "$CONSOLE_LOG"
    setsid sh -c 'exec 9>&-; cd "$1" && exec "./$2" "$3"' sh \
        "$ROOT_DIR" "$VM_SCRIPT" "$kernel_version" >>"$CONSOLE_LOG" 2>&1 &
    printf '%s\n' "$!" > "$PID_FILE"
    printf '%s\n' "$kernel_version" > "$KERNEL_FILE"

    if ! wait_for_ssh; then
        log "VM did not become reachable; console log: $CONSOLE_LOG"
        stop_vm
        return 1
    fi

    log "$VM_NAME is ready"
}

stop_vm()
{
    local pid

    ensure_vm_unlocked
    prepare_dirs
    if [ -S "$MONITOR_SOCKET" ] && command -v socat >/dev/null 2>&1; then
        printf 'quit\n' | socat - UNIX-CONNECT:"$MONITOR_SOCKET" >/dev/null 2>&1 || true
    fi

    if [ -r "$PID_FILE" ]; then
        read -r pid < "$PID_FILE"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            # The VM launcher and QEMU share the dedicated setsid process group.
            kill -- -"$pid" 2>/dev/null || true
            for _ in $(seq 1 10); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 1
            done
            if kill -0 "$pid" 2>/dev/null; then
                kill -KILL -- -"$pid" 2>/dev/null || true
            fi
        fi
    fi

    rm -f "$PID_FILE"
    log "$VM_NAME stopped"
}

status_vm()
{
    local lock_state=""

    if vm_locked; then
        lock_state=" (locked)"
    fi

    if ssh_ready; then
        if tracked_vm_running; then
            log "$VM_NAME is reachable and tracked$lock_state"
        else
            log "$VM_NAME is reachable but not tracked by vm_manager.sh$lock_state"
        fi
        return 0
    fi

    if tracked_vm_running; then
        log "$VM_NAME process is running but SSH is unavailable$lock_state"
        return 2
    fi

    log "$VM_NAME is stopped$lock_state"
    return 1
}

valid_fstype()
{
    [[ $1 =~ ^[A-Za-z0-9_-]+$ ]]
}

valid_kernel_version()
{
    [[ $1 =~ ^[A-Za-z0-9._-]+$ ]]
}

valid_test_case()
{
    [[ $1 =~ ^[A-Za-z0-9._/-]+$ ]]
}

snapshot_console_log()
{
    local run_dir=$1

    [ -f "$CONSOLE_LOG" ] && cp "$CONSOLE_LOG" "$run_dir/qemu-console.log"
}

kernel_fault_detected()
{
    local pattern='Kernel panic|Oops:|BUG:|KASAN:|UBSAN:|general protection fault|Unable to handle kernel'

    grep -Eqi "$pattern" "$@" 2>/dev/null
}

timeout_is_9p()
{
    local run_dir=$1
    local stack_files=()
    local dmesg_files=()
    local task_files=()
    local stack_file
    local task_file
    local d_state_comm

    [ -n "$run_dir" ] && [ -d "$run_dir" ] || return 1

    shopt -s nullglob
    stack_files=("$run_dir"/*.timeout.stacks)
    shopt -u nullglob

    if [ "${#stack_files[@]}" -gt 0 ]; then
        for stack_file in "${stack_files[@]}"; do
            [ -s "$stack_file" ] || return 1
        done

        if grep -Eqi 'p9_client_|v9fs_|p9_|ntfs|submit_bio|bio_|iomap|writeback|blk_' \
            "${stack_files[@]}" >/dev/null 2>&1; then
            awk '
                function finish_task()
                {
                    if (in_task && is_d) {
                        if (has_9p && !has_ntfs)
                            good = 1
                        else
                            bad = 1
                    }
                }
                /^== PID / {
                    finish_task()
                    in_task = 1
                    is_d = ($0 ~ /, D\)/)
                    has_9p = 0
                    has_ntfs = 0
                    next
                }
                /p9_client_|v9fs_|p9_/ { has_9p = 1 }
                /ntfs|submit_bio|bio_|iomap|writeback|blk_/ { has_ntfs = 1 }
                END {
                    finish_task()
                    exit !(in_task && good && !bad)
                }
            ' "${stack_files[@]}"
            return $?
        fi
    fi

    shopt -s nullglob
    dmesg_files=("$run_dir"/*.timeout.dmesg)
    shopt -u nullglob
    [ -f "$run_dir/guest-dmesg.log" ] &&
        dmesg_files+=("$run_dir/guest-dmesg.log")
    [ "${#dmesg_files[@]}" -gt 0 ] || return 1

    shopt -s nullglob
    task_files=("$run_dir"/*.timeout.tasks)
    shopt -u nullglob
    for task_file in "${task_files[@]}"; do
        if awk '$4 ~ /[DR]/ && $5 ~ /p9_client_|v9fs_|p9_/ {
                    has_9p = 1
                }
                $4 ~ /[DR]/ && $5 ~ /ntfs|submit_bio|bio_|iomap|writeback|blk_/ {
                    has_ntfs = 1
                }
                END {
                    exit !(has_9p && !has_ntfs)
                }' "$task_file"; then
            return 0
        fi
        while read -r d_state_comm; do
            [ -n "$d_state_comm" ] || continue
            if awk -v comm="$d_state_comm" '
                function finish_task()
                {
                    if (in_task) {
                        if (has_9p && !has_ntfs)
                            good = 1
                        else
                            bad = 1
                    }
                }
                /task:[^[:space:]]+[[:space:]]+state:[A-Z]/ {
                    finish_task()
                    in_task = (index($0, "task:" comm " ") > 0)
                    has_9p = 0
                    has_ntfs = 0
                    next
                }
                /p9_client_|v9fs_|p9_/ {
                    if (in_task)
                        has_9p = 1
                }
                /ntfs|submit_bio|bio_|iomap|writeback|blk_/ {
                    if (in_task)
                        has_ntfs = 1
                }
                END {
                    finish_task()
                    exit !(good && !bad)
                }
            ' "${dmesg_files[@]}"; then
                return 0
            fi
        done < <(awk '$4 == "D" { print $3 }' "$task_file")
    done

    awk '
        function finish_task()
        {
            if (in_task && is_d) {
                if (has_9p && !has_ntfs)
                    good = 1
                else
                    bad = 1
            }
        }
        /task:[^[:space:]]+[[:space:]]+state:[A-Z]/ {
            finish_task()
            in_task = 1
            is_d = ($0 ~ /state:D([[:space:]]|$)/)
            has_9p = 0
            has_ntfs = 0
            next
        }
        /p9_client_|v9fs_|p9_/ { has_9p = 1 }
        /ntfs|submit_bio|bio_|iomap|writeback|blk_/ { has_ntfs = 1 }
        END {
            finish_task()
            exit !(in_task && good && !bad)
        }
    ' "${dmesg_files[@]}"
}

restart_after_fault()
{
    local kernel_version=$1
    local reason=${2:-"VM fault detected"}

    log "$reason; restarting $VM_NAME"
    stop_vm
    start_vm "$kernel_version"
}

run_xfstests()
{
    local fstype=$1
    shift
    local test_cases=("$@")
    local kernel_version run_id run_dir ssh_status dmesg_status
    local use_xfstests_image

    ensure_vm_unlocked
    valid_fstype "$fstype" || die "invalid filesystem type: $fstype"
    [ "${#test_cases[@]}" -gt 0 ] || die "at least one test case is required"
    for test_case in "${test_cases[@]}"; do
        valid_test_case "$test_case" || die "invalid test case: $test_case"
    done
    case "$VM_NAME" in
        vm01) use_xfstests_image=${NTFS_VM01_USE_XFSTESTS_IMAGE:-0} ;;
        vm02) use_xfstests_image=${NTFS_VM02_USE_XFSTESTS_IMAGE:-0} ;;
    esac

    if ! ssh_ready; then
        die "$VM_NAME is not reachable on SSH port $SSH_PORT; start it first"
    fi
    [ -r "$KERNEL_FILE" ] ||
        die "unknown $VM_NAME kernel version; restart it with 'start <kernel-version>'"
    read -r kernel_version < "$KERNEL_FILE"
    valid_kernel_version "$kernel_version" ||
        die "invalid recorded $VM_NAME kernel version: $kernel_version"

    run_id="$(date '+%Y%m%d-%H%M%S')-${VM_NAME}-${fstype}-$$"
    run_dir="$RUNS_DIR/$run_id"
    mkdir -p "$run_dir"
    printf 'vm=%s\nfstype=%s\nkernel_version=%s\ntests=%s\nstarted=%s\n' \
        "$VM_NAME" "$fstype" "$kernel_version" "${test_cases[*]}" \
        "$(date --iso-8601=seconds)" > "$run_dir/metadata"

    log "xfstests run directory: $run_dir"
    log "Running ${fstype}: ${test_cases[*]}"
    ssh "${SSH_OPTS[@]}" env \
        "NTFS_9P_MOUNT_OPTIONS=$NTFS_9P_MOUNT_OPTIONS" \
        "NTFS_USE_XFSTESTS_IMAGE=$use_xfstests_image" \
        "NTFS_XFSTESTS_IMAGE_DEVICE=$NTFS_XFSTESTS_IMAGE_DEVICE" \
        bash -s -- "$run_id" "$VM_ID" "$fstype" "${test_cases[@]}" \
        > >(tee "$run_dir/ssh-output.log") 2>&1 <<'EOF'
set -eu

run_id=$1
vm_id=$2
fstype=$3
shift 3
use_xfstests_image=${NTFS_USE_XFSTESTS_IMAGE:-0}
xfstests_image_device=${NTFS_XFSTESTS_IMAGE_DEVICE:-/dev/disk/by-id/virtio-ntfs-xfstests}
case "$vm_id" in
	vm01)
		xfstests_host_dir=xfstests-dev-02.git
		;;
	vm02)
		xfstests_host_dir=xfstests-dev.git
		;;
	*)
		echo "invalid VM id: $vm_id" >&2
		exit 1
		;;
esac

unmount_share()
{
	for target in \
		/root/xfstests-dev.git /root/syzbot /root/logs /root/tests; do
		if mountpoint -q "$target"; then
			umount "$target"
		fi
	done
	if mountpoint -q /mnt/host-share; then
		umount /mnt/host-share
	fi
}

mount_share()
{
	local options=$1
	local use_image=${2:-0}

	unmount_share
	mount -t 9p -o "$options" host-share-dir /mnt/host-share
	if [ "$use_image" -eq 1 ]; then
		[ -b "$xfstests_image_device" ] || {
			echo "missing xfstests image device: $xfstests_image_device" >&2
			return 1
		}
		mount -t ext4 "$xfstests_image_device" /root/xfstests-dev.git
	else
		[ -d "/mnt/host-share/$xfstests_host_dir" ] || {
			echo "missing xfstests tree: /mnt/host-share/$xfstests_host_dir" >&2
			return 1
		}
		mount --bind "/mnt/host-share/$xfstests_host_dir" /root/xfstests-dev.git
	fi
	mount --bind /mnt/host-share/syzbot /root/syzbot
	mount --bind /mnt/host-share/logs /root/logs
	mount --bind /mnt/host-share/tests /root/tests
}

restore_default()
{
	mount_share trans=virtio 0
}

cleanup_default()
{
	restore_default >/dev/null 2>&1 || true
}

trap cleanup_default EXIT
mount_share "trans=virtio,$NTFS_9P_MOUNT_OPTIONS" "$use_xfstests_image"
status=0
/mnt/host-share/agent-automation/guest-run.sh \
	"$run_id" "$vm_id" "$fstype" "$@" || status=$?
if ! restore_default; then
	[ "$status" -ne 0 ] || status=1
fi
trap - EXIT
exit "$status"
EOF
    ssh_status=$?

    # Capture a final dmesg even when the guest script could not run its trap.
    ssh "${SSH_OPTS[@]}" dmesg > "$run_dir/host-collected-dmesg.log" 2>&1
    dmesg_status=$?
    snapshot_console_log "$run_dir"

    # guest-dmesg.log is cleared at the start of this test. Do not scan the
    # whole QEMU console because it can contain warnings from prior runs.
    if [ "$dmesg_status" -ne 0 ] ||
       kernel_fault_detected "$run_dir/guest-dmesg.log" \
           "$run_dir/host-collected-dmesg.log"; then
        printf 'outcome=vm-fault\nssh_status=%s\n' "$ssh_status" >> "$run_dir/metadata"
        restart_after_fault "$kernel_version" || return 3
        return 2
    fi

    if [ "$ssh_status" -eq 124 ]; then
        if timeout_is_9p "$run_dir"; then
            printf 'outcome=xfstests-timeout-9p\ntimeout_reason=9p\nssh_status=%s\n' \
                "$ssh_status" >> "$run_dir/metadata"
            log "xfstests timed out in 9p; restarting $VM_NAME for retry"
            restart_after_fault "$kernel_version" \
                "9p timeout detected" || return 3
            return 125
        fi
        printf 'outcome=xfstests-timeout\nssh_status=%s\n' "$ssh_status" >> "$run_dir/metadata"
        log "xfstests timed out with D-state tasks; restarting $VM_NAME"
        restart_after_fault "$kernel_version" || return 3
        return 124
    fi

    if [ "$ssh_status" -ne 0 ]; then
        printf 'outcome=xfstests-failure\nssh_status=%s\n' "$ssh_status" >> "$run_dir/metadata"
        log "xfstests failed; artifacts: $run_dir"
        return 1
    fi

    printf 'outcome=pass\nssh_status=0\n' >> "$run_dir/metadata"
    log "xfstests passed; artifacts: $run_dir"
}

run_ssh_command()
{
    ensure_vm_unlocked
    [ "$#" -gt 0 ] || die "a command is required"

    if ! ssh_ready; then
        die "$VM_NAME is not reachable on SSH port $SSH_PORT; start it first"
    fi

    ssh "${SSH_OPTS[@]}" env \
        "PATH=$GUEST_PATH" \
        "LD_LIBRARY_PATH=$GUEST_LD_LIBRARY_PATH" \
        "$@"
}

prune_logs()
{
    local retention_days=$1
    local max_age_days

    [[ $retention_days =~ ^[1-9][0-9]*$ ]] ||
        die "retention days must be a positive integer"
    max_age_days=$((retention_days - 1))

    # -daystart makes the retention boundary align with calendar days, not
    # the time of day at which this command happens to run.
    find "$RUNS_DIR" -mindepth 1 -maxdepth 1 -type d \
        -daystart -mtime +"$max_age_days" -print -exec rm -rf -- {} +
}

main()
{
    local command

    if [ "${1:-}" = --vm ]; then
        [ "$#" -ge 3 ] || { usage >&2; exit 1; }
        VM_NAME=$2
        shift 2
    fi
    configure_vm
    command=${1:-}

    case "$command" in
        start)
            [ "$#" -eq 2 ] || { usage >&2; exit 1; }
            start_vm "$2"
            ;;
        stop)
            [ "$#" -eq 1 ] || { usage >&2; exit 1; }
            stop_vm
            ;;
        restart)
            [ "$#" -eq 2 ] || { usage >&2; exit 1; }
            stop_vm
            start_vm "$2"
            ;;
        status)
            [ "$#" -eq 1 ] || { usage >&2; exit 1; }
            status_vm
            ;;
        lock)
            [ "$#" -eq 1 ] || { usage >&2; exit 1; }
            lock_vm
            ;;
        unlock)
            [ "$#" -eq 1 ] || { usage >&2; exit 1; }
            unlock_vm
            ;;
        run)
            [ "$#" -ge 2 ] || { usage >&2; exit 1; }
            run_ssh_command "${@:2}"
            ;;
        run_xfstests)
            [ "$#" -ge 3 ] || { usage >&2; exit 1; }
            run_xfstests "$2" "${@:3}"
            ;;
        prune_logs)
            [ "$#" -eq 2 ] || { usage >&2; exit 1; }
            prune_logs "$2"
            ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
}

if [ "${1:-}" = --vm ]; then
    [ "$#" -ge 3 ] || { usage >&2; exit 1; }
    VM_NAME=$2
fi
configure_vm
prepare_dirs
exec 9>"$OPERATION_LOCK_FILE"
flock -n 9 || die "another $VM_NAME management operation is already running"
main "$@"
