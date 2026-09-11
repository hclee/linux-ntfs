#!/bin/sh

KERNEL_VERSION=$1

if [ "${NTFS_VM02_USE_VDC_VDD:-0}" = 1 ]; then
	[ -n "${NTFS_VM02_LOGICAL_BLOCK_SIZE:-}" ] || exit 1
	[ -n "${NTFS_VM02_PHYSICAL_BLOCK_SIZE:-}" ] || exit 1
	NTFS_TEST_HOST_DEVICE=/dev/disk/by-id/ata-CT1000MX500SSD1_2208E60F18CD-part3
	NTFS_SCRATCH_HOST_DEVICE=/dev/disk/by-id/ata-CT1000MX500SSD1_2208E60F18CD-part4
	[ -b "$NTFS_TEST_HOST_DEVICE" ] || exit 1
	[ -b "$NTFS_SCRATCH_HOST_DEVICE" ] || exit 1

	# Keep root/helper/test/scratch/corpus in explicit virtio order.
	PROFILE_DRIVES="-drive file=./ubuntu24-minimal.raw,if=none,id=ntfs-boot,format=raw"
	PROFILE_DRIVES="$PROFILE_DRIVES -device virtio-blk-pci,drive=ntfs-boot,serial=ntfs-boot"
	PROFILE_DRIVES="$PROFILE_DRIVES -drive file=./large-disk-02.img,if=none,id=ntfs-helper,format=raw"
	PROFILE_DRIVES="$PROFILE_DRIVES -device virtio-blk-pci,drive=ntfs-helper,serial=ntfs-helper"
	PROFILE_DRIVES="$PROFILE_DRIVES -drive file=$NTFS_TEST_HOST_DEVICE,if=none,id=ntfs-test,format=raw,cache=none"
	PROFILE_DRIVES="$PROFILE_DRIVES -device virtio-blk-pci,drive=ntfs-test,logical_block_size=${NTFS_VM02_LOGICAL_BLOCK_SIZE},physical_block_size=${NTFS_VM02_PHYSICAL_BLOCK_SIZE},serial=ntfs-geometry-test"
	PROFILE_DRIVES="$PROFILE_DRIVES -drive file=$NTFS_SCRATCH_HOST_DEVICE,if=none,id=ntfs-scratch,format=raw,cache=none"
	PROFILE_DRIVES="$PROFILE_DRIVES -device virtio-blk-pci,drive=ntfs-scratch,logical_block_size=${NTFS_VM02_LOGICAL_BLOCK_SIZE},physical_block_size=${NTFS_VM02_PHYSICAL_BLOCK_SIZE},serial=ntfs-geometry-scratch"
	PROFILE_DRIVES="$PROFILE_DRIVES -drive file=/home/hyunchul/src2/linux-ntfs.git/qemu_tests/corpus/ntfs_wof_compressed.img,if=none,id=ntfs-corpus,format=raw"
	PROFILE_DRIVES="$PROFILE_DRIVES -device virtio-blk-pci,drive=ntfs-corpus,serial=ntfs-corpus"
	if [ -n "${NTFS_VM02_XFSTESTS_IMG:-}" ]; then
		[ -f "$NTFS_VM02_XFSTESTS_IMG" ] || {
			echo "missing xfstests image: $NTFS_VM02_XFSTESTS_IMG" >&2
			exit 1
		}
		PROFILE_DRIVES="$PROFILE_DRIVES -drive file=$NTFS_VM02_XFSTESTS_IMG,if=none,id=ntfs-xfstests,format=raw,cache=none"
		PROFILE_DRIVES="$PROFILE_DRIVES -device virtio-blk-pci,drive=ntfs-xfstests,serial=ntfs-xfstests"
	fi
	NTFS_VM02_EXPLICIT_BOOT=1 NTFS_VM02_SILENT_CONSOLE=1 \
		./run_vm.sh "$KERNEL_VERSION" 5 "-s -monitor unix:qemu-monitor-socket-02,server,nowait -qmp tcp:localhost:4444,server,nowait $PROFILE_DRIVES"
else
	./run_vm.sh "$KERNEL_VERSION" 5 '-s -monitor unix:qemu-monitor-socket-02,server,nowait -qmp tcp:localhost:4444,server,nowait -drive file=./large-disk-02.img,if=virtio -usb -device usb-host,vendorid=0x1f75,productid=0x0902 -drive file=/dev/disk/by-id/ata-CT1000MX500SSD1_2208E60F18CD-part3,media=disk,cache=none,format=raw,if=virtio -drive file=/dev/disk/by-id/ata-CT1000MX500SSD1_2208E60F18CD-part4,media=disk,cache=none,format=raw,if=virtio -drive file=/home/hyunchul/src2/linux-ntfs.git/qemu_tests/corpus/ntfs_wof_compressed.img,format=raw,if=virtio'
fi

#-drive file=/home/hyunchul/src2/linux-ntfs.git/qemu_tests/corpus/ntfs-symlink.vhdx,format=vhdx,if=virtio'
#-drive file=/dev/disk/by-id/usb-USB_SanDisk_3.2Gen1_010167b0cda278cf198f6abc271198c6b6e617011f85ebf4e25fa2ecb439d23397f300000000000000000000d0d04d74009058009155810740ac69a6-0:0,cache=none,format=raw,if=virtio'
#-drive file=/dev/disk/by-id/usb-Samsung_PSSD_T7_S5SYNJ0T100212K-0:0,media=disk,cache=none,format=raw,if=virtio'
#-drive file=/dev/disk/by-id/usb-Samsung_PSSD_T7_S6U9NJ0RC12972T-0:0,cache=none,format=raw,if=virtio'
#--drive file=/dev/disk/by-id/ata-Samsung_SSD_850_PRO_512GB_S257NX0H703346A-part3,cache=none,format=raw,if=virtio -drive file=/dev/disk/by-id/ata-Samsung_SSD_850_PRO_512GB_S257NX0H703346A-part4,cache=none,format=raw,if=virtio'
#-device qemu-xhci -drive file=/dev/disk/by-id/ata-CT1000MX500SSD1_2208E60F18CD,media=disk,cache=none,format=raw,if=virtio,id=ssd01'


# embedded 1T SSD


#-drive file=./large-disk-01.img,if=virtio'
#-drive file=/dev/disk/by-id/usb-USB_SanDisk_3.2Gen1_010167b0cda278cf198f6abc271198c6b6e617011f85ebf4e25fa2ecb439d23397f300000000000000000000d0d04d74009058009155810740ac69a6-0:0,cache=none,format=raw,if=virtio'

#-drive file=/home/hyunchul/src/webos/issues-webos4tv/25y/SWPRETEST-1509/sdb2.img,format=raw,if=virtio'

#-drive file=/mnt/sdb1/disk-256g.img,if=virtio'

#-drive file=/home/hyunchul/src/webos/issues/sda1.img,format=raw,if=virtio'
#-drive file=/dev/sdf,cache=none,format=raw,if=virtio'
#-drive file=/home/hyunchul/src2/exfatprogs.git/SeagateOneTouch.dump,format=raw,if=virtio'
#-drive file=/dev/sdb,cache=none,format=raw,if=virtio
