/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * All NTFS associated on-disk structures. Part of the Linux-NTFS
 * project.
 *
 * Copyright (c) 2001-2005 Anton Altaparmakov
 * Copyright (c) 2002 Richard Russon
 */

#ifndef _LINUX_NTFS_LAYOUT_H
#define _LINUX_NTFS_LAYOUT_H

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/list.h>
#include <asm/byteorder.h>

/* The NTFS oem_id "NTFS    " */
#define magicNTFS	cpu_to_le64(0x202020205346544eULL)

/*
 * Location of bootsector on partition:
 *	The standard NTFS_BOOT_SECTOR is on sector 0 of the partition.
 *	On NT4 and above there is one backup copy of the boot sector to
 *	be found on the last sector of the partition (not normally accessible
 *	from within Windows as the bootsector contained number of sectors
 *	value is one less than the actual value!).
 *	On versions of NT 3.51 and earlier, the backup copy was located at
 *	number of sectors/2 (integer divide), i.e. in the middle of the volume.
 */

/*
 * BIOS parameter block (bpb) structure.
 *
 * @bytes_per_sector:       Size of a sector in bytes (usually 512).
 *                          Matches the logical sector size of the underlying device.
 * @sectors_per_cluster:    Size of a cluster in sectors (NTFS cluster size / sector size).
 * @reserved_sectors:       Number of reserved sectors at the beginning of the volume.
 *                          Always set to 0 in NTFS.
 * @fats:                   Number of FAT tables.
 *                          Always 0 in NTFS (no FAT tables exist).
 * @root_entries:           Number of entries in the root directory.
 *                          Always 0 in NTFS.
 * @sectors:                Total number of sectors on the volume.
 *                          Always 0 in NTFS (use @large_sectors instead).
 * @media_type:             Media descriptor byte.
 *                          0xF8 for hard disk (fixed media) in NTFS.
 * @sectors_per_fat:        Number of sectors per FAT table.
 *                          Always 0 in NTFS.
 * @sectors_per_track:      Number of sectors per track.
 *                          Irrelevant for NTFS.
 * @heads:                  Number of heads (CHS geometry).
 *                          Irrelevant for NTFS.
 * @hidden_sectors:         Number of hidden sectors before the start of the partition.
 *                          Always 0 in NTFS boot sector.
 * @large_sectors:          Total number of sectors on the volume.
 */
struct bios_parameter_block {
	__le16 bytes_per_sector;
	u8 sectors_per_cluster;
	__le16 reserved_sectors;
	u8 fats;
	__le16 root_entries;
	__le16 sectors;
	u8 media_type;
	__le16 sectors_per_fat;
	__le16 sectors_per_track;
	__le16 heads;
	__le32 hidden_sectors;
	__le32 large_sectors;
} __packed;

/*
 * NTFS boot sector structure.
 *
 * @jump:               3-byte jump instruction to boot code (irrelevant for NTFS).
 *                      Typically 0xEB 0x52 0x90 or similar.
 * @oem_id:             OEM identifier string (8 bytes).
 *                      Always "NTFS    " (with trailing spaces) in NTFS volumes.
 * @bpb:                Legacy BIOS Parameter Block (see struct bios_parameter_block).
 *                      Mostly zeroed or set to fixed values for NTFS compatibility.
 * @unused:             4 bytes, reserved/unused.
 *                      NTFS disk editors show it as:
 *                        - physical_drive (0x80 for fixed disk)
 *                        - current_head (0)
 *                        - extended_boot_signature (0x80 or 0x28)
 *                        - unused (0)
 *                      Always zero in practice for NTFS.
 * @number_of_sectors:  Number of sectors in volume. Gives maximum volume
 *                      size of 2^63 sectors. Assuming standard sector
 *                      size of 512 bytes, the maximum byte size is
 *                      approx. 4.7x10^21 bytes. (-;
 * @mft_lcn:            Logical cluster number (LCN) of the $MFT data attribute.
 *                      Location of the Master File Table.
 * @mftmirr_lcn:        LCN of the $MFTMirr (first 3-4 MFT records copy).
 *                      Mirror for boot-time recovery.
 * @clusters_per_mft_record:
 *                      Size of each MFT record in clusters.
 * @reserved0:          3 bytes, reserved/zero.
 * @clusters_per_index_record:
 *                      Size of each index block/record in clusters.
 * @reserved1:          3 bytes, reserved/zero.
 * @volume_serial_number:
 *                      64-bit volume serial number.
 *                      Used for identification (irrelevant for NTFS operation).
 * @checksum:           32-bit checksum of the boot sector (excluding this field).
 *                      Used to detect boot sector corruption.
 * @bootstrap:          426 bytes of bootstrap code.
 *                      Irrelevant for NTFS (contains x86 boot loader stub).
 * @end_of_sector_marker:
 *                      2-byte end-of-sector signature.
 *                      Always 0xAA55 (little-endian magic number).
 */
struct ntfs_boot_sector {
	u8 jump[3];
	__le64 oem_id;
	struct bios_parameter_block bpb;
	u8 unused[4];
	__le64 number_of_sectors;
	__le64 mft_lcn;
	__le64 mftmirr_lcn;
	s8 clusters_per_mft_record;
	u8 reserved0[3];
	s8 clusters_per_index_record;
	u8 reserved1[3];
	__le64 volume_serial_number;
	__le32 checksum;
	u8 bootstrap[426];
	__le16 end_of_sector_marker;
} __packed;

static_assert(sizeof(struct ntfs_boot_sector) == 512);

/*
 * Magic identifiers present at the beginning of all ntfs record containing
 * records (like mft records for example).
 *
 * magic_FILE:      MFT entry header ("FILE" in ASCII).
 *                  Used in $MFT/$DATA for all master file table records.
 * magic_INDX:      Index buffer header ("INDX" in ASCII).
 *                  Used in $INDEX_ALLOCATION attributes (directories, $I30 indexes).
 * magic_HOLE:      Hole marker ("HOLE" in ASCII).
 *                  Introduced in NTFS 3.0+, used for sparse/hole regions in some contexts.
 * magic_RSTR:      Restart page header ("RSTR" in ASCII).
 *                  Used in $LogFile for restart pages (transaction log recovery).
 * magic_RCRD:      Log record page header ("RCRD" in ASCII).
 *                  Used in $LogFile for individual log record pages.
 * magic_CHKD:      Chkdsk modified marker ("CHKD" in ASCII).
 *                  Set by chkdsk when it modifies a record; indicates repair was done.
 * magic_BAAD:      Bad record marker ("BAAD" in ASCII).
 *                  Indicates a multi-sector transfer failure was detected.
 *                  The record is corrupted/unusable; often set during I/O errors.
 * magic_empty:     Empty/uninitialized page marker (0xffffffff).
 *                  Used in $LogFile when a page is filled with 0xff bytes
 *                  and has not yet been initialized. Must be formatted before use.
 */
enum {
	magic_FILE = cpu_to_le32(0x454c4946),
	magic_INDX = cpu_to_le32(0x58444e49),
	magic_HOLE = cpu_to_le32(0x454c4f48),
	magic_RSTR = cpu_to_le32(0x52545352),
	magic_RCRD = cpu_to_le32(0x44524352),
	magic_CHKD = cpu_to_le32(0x444b4843),
	magic_BAAD = cpu_to_le32(0x44414142),
	magic_empty = cpu_to_le32(0xffffffff)
};

/*
 * Generic magic comparison macros. Finally found a use for the ## preprocessor
 * operator! (-8
 */

static inline bool __ntfs_is_magic(__le32 x, __le32 r)
{
	return (x == r);
}
#define ntfs_is_magic(x, m)	__ntfs_is_magic(x, magic_##m)

static inline bool __ntfs_is_magicp(__le32 *p, __le32 r)
{
	return (*p == r);
}
#define ntfs_is_magicp(p, m)	__ntfs_is_magicp(p, magic_##m)

/*
 * Specialised magic comparison macros for the NTFS_RECORD_TYPEs defined above.
 */
#define ntfs_is_file_record(x)		(ntfs_is_magic(x, FILE))
#define ntfs_is_file_recordp(p)		(ntfs_is_magicp(p, FILE))
#define ntfs_is_mft_record(x)		(ntfs_is_file_record(x))
#define ntfs_is_mft_recordp(p)		(ntfs_is_file_recordp(p))
#define ntfs_is_indx_record(x)		(ntfs_is_magic(x, INDX))
#define ntfs_is_indx_recordp(p)		(ntfs_is_magicp(p, INDX))
#define ntfs_is_hole_record(x)		(ntfs_is_magic(x, HOLE))
#define ntfs_is_hole_recordp(p)		(ntfs_is_magicp(p, HOLE))

#define ntfs_is_rstr_record(x)		(ntfs_is_magic(x, RSTR))
#define ntfs_is_rstr_recordp(p)		(ntfs_is_magicp(p, RSTR))
#define ntfs_is_rcrd_record(x)		(ntfs_is_magic(x, RCRD))
#define ntfs_is_rcrd_recordp(p)		(ntfs_is_magicp(p, RCRD))

#define ntfs_is_chkd_record(x)		(ntfs_is_magic(x, CHKD))
#define ntfs_is_chkd_recordp(p)		(ntfs_is_magicp(p, CHKD))

#define ntfs_is_baad_record(x)		(ntfs_is_magic(x, BAAD))
#define ntfs_is_baad_recordp(p)		(ntfs_is_magicp(p, BAAD))

#define ntfs_is_empty_record(x)		(ntfs_is_magic(x, empty))
#define ntfs_is_empty_recordp(p)	(ntfs_is_magicp(p, empty))

/*
 * struct ntfs_record - Common header for all multi-sector protected NTFS records
 *
 * @magic:      4-byte magic identifier for the record type and/or status.
 *              Common values are defined in the magic_* enum (FILE, INDX, RSTR,
 *              RCRD, CHKD, BAAD, HOLE, empty).
 *              - "FILE" = MFT record
 *              - "INDX" = Index allocation block
 *              - "BAAD" = Record corrupted (multi-sector fixup failed)
 *              - 0xffffffff = Uninitialized/empty page
 * @usa_ofs:    Offset (in bytes) from the start of this record to the Update
 *              Sequence Array (USA).
 *              The USA is located at record + usa_ofs.
 * @usa_count:  Number of 16-bit entries in the USA array (including the Update
 *              Sequence Number itself).
 *              - Number of fixup locations = usa_count - 1
 *              - Each fixup location is a 16-bit value in the record that needs
 *                protection against torn writes.
 *
 * The Update Sequence Array (usa) is an array of the __le16 values which belong
 * to the end of each sector protected by the update sequence record in which
 * this array is contained. Note that the first entry is the Update Sequence
 * Number (usn), a cyclic counter of how many times the protected record has
 * been written to disk. The values 0 and -1 (ie. 0xffff) are not used. All
 * last le16's of each sector have to be equal to the usn (during reading) or
 * are set to it (during writing). If they are not, an incomplete multi sector
 * transfer has occurred when the data was written.
 * The maximum size for the update sequence array is fixed to:
 *	maximum size = usa_ofs + (usa_count * 2) = 510 bytes
 * The 510 bytes comes from the fact that the last __le16 in the array has to
 * (obviously) finish before the last __le16 of the first 512-byte sector.
 * This formula can be used as a consistency check in that usa_ofs +
 * (usa_count * 2) has to be less than or equal to 510.
 */
struct ntfs_record {
	__le32 magic;
	__le16 usa_ofs;
	__le16 usa_count;
} __packed;

/*
 * System files mft record numbers. All these files are always marked as used
 * in the bitmap attribute of the mft; presumably in order to avoid accidental
 * allocation for random other mft records. Also, the sequence number for each
 * of the system files is always equal to their mft record number and it is
 * never modified.
 *
 * FILE_MFT:        Master File Table (MFT) itself.
 *                  Data attribute contains all MFT entries;
 *                  Bitmap attribute tracks which records are in use (bit==1).
 * FILE_MFTMirr:    MFT mirror: copy of the first four (or more) MFT records
 *                  in its data attribute.
 *                  If cluster size > 4 KiB, copies first N records where
 *                  N = cluster_size / mft_record_size.
 * FILE_LogFile:    Journaling log ($LogFile) in data attribute.
 *                  Used for transaction logging and recovery.
 * FILE_Volume:     Volume information and name.
 *                  Contains $VolumeName (label) and $VolumeInformation
 *                  (flags, NTFS version). Windows calls this the volume DASD.
 * FILE_AttrDef:    Attribute definitions array in data attribute.
 *                  Defines all possible attribute types and their properties.
 * FILE_root:       Root directory ($Root).
 *                  The top-level directory of the filesystem.
 * FILE_Bitmap:     Cluster allocation bitmap ($Bitmap) in data attribute.
 *                  Tracks free/used clusters (LCNs) on the volume.
 * FILE_Boot:       Boot sector ($Boot) in data attribute.
 *                  Always located at cluster 0; contains BPB and NTFS parameters.
 * FILE_BadClus:    Bad cluster list ($BadClus) in non-resident data attribute.
 *                  Marks all known bad clusters.
 * FILE_Secure:     Security descriptors ($Secure).
 *                  Contains shared $SDS (security descriptors) and two indexes
 *                  ($SDH, $SII). Introduced in Windows 2000.
 *                  Before that, it was called $Quota but was unused.
 * FILE_UpCase:     Uppercase table ($UpCase) in data attribute.
 *                  Maps all 65536 Unicode characters to their uppercase forms.
 * FILE_Extend:     System directory ($Extend).
 *                  Contains additional system files ($ObjId, $Quota, $Reparse,
 *                  $UsnJrnl, etc.). Introduced in NTFS 3.0 (Windows 2000).
 * FILE_reserved12: Reserved for future use (MFT records 12–15).
 * FILE_reserved13: Reserved.
 * FILE_reserved14: Reserved.
 * FILE_reserved15: Reserved.
 * FILE_first_user: First possible user-created file MFT record number.
 *                  Used as a boundary to distinguish system files from user files.
 */
enum {
	FILE_MFT       = 0,
	FILE_MFTMirr   = 1,
	FILE_LogFile   = 2,
	FILE_Volume    = 3,
	FILE_AttrDef   = 4,
	FILE_root      = 5,
	FILE_Bitmap    = 6,
	FILE_Boot      = 7,
	FILE_BadClus   = 8,
	FILE_Secure    = 9,
	FILE_UpCase    = 10,
	FILE_Extend    = 11,
	FILE_reserved12 = 12,
	FILE_reserved13 = 13,
	FILE_reserved14 = 14,
	FILE_reserved15 = 15,
	FILE_first_user = 16,
};

/*
 * enum - Flags for MFT record header
 *
 * These are the so far known MFT_RECORD_* flags (16-bit) which contain
 * information about the mft record in which they are present.
 *
 * MFT_RECORD_IN_USE:        This MFT record is allocated and in use.
 *                           (bit set = record is valid/used; clear = free)
 * MFT_RECORD_IS_DIRECTORY:  This MFT record represents a directory.
 *                           (Used to quickly distinguish files from directories)
 * MFT_RECORD_IS_4:          Indicates the record is a special "record 4" type.
 *                           (Rarely used; related to NTFS internal special cases,
 *                           often for $AttrDef or early system files)
 * MFT_RECORD_IS_VIEW_INDEX: This MFT record is used as a view index.
 *                           (Specific to NTFS indexed views or object ID indexes)
 * MFT_REC_SPACE_FILLER:     Dummy value to force the enum to be 16-bit wide.
 *                           (Not a real flag; just a sentinel to ensure the type
 *                           is __le16 and no higher bits are accidentally used)
 */
enum {
	MFT_RECORD_IN_USE		= cpu_to_le16(0x0001),
	MFT_RECORD_IS_DIRECTORY		= cpu_to_le16(0x0002),
	MFT_RECORD_IS_4			= cpu_to_le16(0x0004),
	MFT_RECORD_IS_VIEW_INDEX	= cpu_to_le16(0x0008),
	MFT_REC_SPACE_FILLER		= cpu_to_le16(0xffff), /*Just to make flags 16-bit.*/
} __packed;

/*
 * mft references (aka file references or file record segment references) are
 * used whenever a structure needs to refer to a record in the mft.
 *
 * A reference consists of a 48-bit index into the mft and a 16-bit sequence
 * number used to detect stale references.
 *
 * For error reporting purposes we treat the 48-bit index as a signed quantity.
 *
 * The sequence number is a circular counter (skipping 0) describing how many
 * times the referenced mft record has been (re)used. This has to match the
 * sequence number of the mft record being referenced, otherwise the reference
 * is considered stale and removed.
 *
 * If the sequence number is zero it is assumed that no sequence number
 * consistency checking should be performed.
 */

/*
 * Define two unpacking macros to get to the reference (MREF) and
 * sequence number (MSEQNO) respectively.
 * The _LE versions are to be applied on little endian MFT_REFs.
 * Note: The _LE versions will return a CPU endian formatted value!
 */
#define MFT_REF_MASK_CPU 0x0000ffffffffffffULL
#define MFT_REF_MASK_LE cpu_to_le64(MFT_REF_MASK_CPU)

#define MK_MREF(m, s)	((u64)(((u64)(s) << 48) |		\
					((u64)(m) & MFT_REF_MASK_CPU)))
#define MK_LE_MREF(m, s) cpu_to_le64(MK_MREF(m, s))

#define MREF(x)		((unsigned long)((x) & MFT_REF_MASK_CPU))
#define MSEQNO(x)	((u16)(((x) >> 48) & 0xffff))
#define MREF_LE(x)	((unsigned long)(le64_to_cpu(x) & MFT_REF_MASK_CPU))
#define MREF_INO(x)	((unsigned long)MREF_LE(x))
#define MSEQNO_LE(x)	((u16)((le64_to_cpu(x) >> 48) & 0xffff))

#define IS_ERR_MREF(x)	(((x) & 0x0000800000000000ULL) ? true : false)
#define ERR_MREF(x)	((u64)((s64)(x)))
#define MREF_ERR(x)	((int)((s64)(x)))

/*
 * struct mft_record - NTFS Master File Table (MFT) record header
 *
 * The mft record header present at the beginning of every record in the mft.
 * This is followed by a sequence of variable length attribute records which
 * is terminated by an attribute of type AT_END which is a truncated attribute
 * in that it only consists of the attribute type code AT_END and none of the
 * other members of the attribute structure are present.
 *
 * magic:               Record magic ("FILE" for valid MFT entries).
 *                      See ntfs_record magic enum for other values.
 * usa_ofs:             Offset to Update Sequence Array (see ntfs_record).
 * usa_count:           Number of entries in USA (see ntfs_record).
 * lsn:                 Log sequence number (LSN) from $LogFile.
 *                      Incremented on every modification to this record.
 * sequence_number:     Reuse count of this MFT record slot.
 *                      Incremented (skipping zero) when the file is deleted.
 *                      Zero means never reused or special case.
 *                      Part of MFT reference (together with record number).
 * link_count:          Number of hard links (directory entries) to this file.
 *                      Only meaningful in base MFT records.
 *                      When deleting a directory entry:
 *                        - If link_count == 1, delete the whole file
 *                        - Else remove only the $FILE_NAME attribute and decrement
 * attrs_offset:        Byte offset from start of MFT record to first attribute.
 *                      Must be 8-byte aligned.
 * flags:               Bit array of MFT_RECORD_* flags (see MFT_RECORD_IN_USE enum).
 *                      MFT_RECORD_IN_USE cleared when record is freed/deleted.
 * bytes_in_use:        Number of bytes actually used in this MFT record.
 *                      Must be 8-byte aligned.
 *                      Includes header + all attributes + padding.
 * bytes_allocated:     Total allocated size of this MFT record.
 *                      Usually equal to MFT record size (1024 bytes or cluster size).
 * base_mft_record:     MFT reference to the base record.
 *                      0 for base records.
 *                      Non-zero for extension records → points to base record
 *                      containing the $ATTRIBUTE_LIST that describes this extension.
 * next_attr_instance:  Next attribute instance number to assign.
 *                      Incremented after each use.
 *                      Reset to 0 when MFT record is reused.
 *                      First instance is always 0.
 * reserved:            Reserved for alignment (NTFS 3.1+).
 * mft_record_number:   This MFT record's number (index in $MFT).
 *                      Only present in NTFS 3.1+ (Windows XP and above).
 */
struct mft_record {
	__le32 magic;
	__le16 usa_ofs;
	__le16 usa_count;

	__le64 lsn;
	__le16 sequence_number;
	__le16 link_count;
	__le16 attrs_offset;
	__le16 flags;
	__le32 bytes_in_use;
	__le32 bytes_allocated;
	__le64 base_mft_record;
	__le16 next_attr_instance;
	__le16 reserved;
	__le32 mft_record_number;
} __packed;

static_assert(sizeof(struct mft_record) == 48);

/**x
 * struct mft_record_old - Old NTFS MFT record header (pre-NTFS 3.1 / Windows XP)
 *
 * This is the older version of the MFT record header used in NTFS versions
 * prior to 3.1 (Windows XP and later). It lacks the additional fields
 * @reserved and @mft_record_number that were added in NTFS 3.1+.
 *
 * @magic:              Record magic ("FILE" for valid MFT entries).
 *                      See ntfs_record magic enum for other values.
 * @usa_ofs:            Offset to Update Sequence Array (see ntfs_record).
 * @usa_count:          Number of entries in USA (see ntfs_record).
 * @lsn:                Log sequence number (LSN) from $LogFile.
 *                      Incremented on every modification to this record.
 * @sequence_number:    Reuse count of this MFT record slot.
 *                      Incremented (skipping zero) when the file is deleted.
 *                      Zero means never reused or special case.
 *                      Part of MFT reference (together with record number).
 * @link_count:         Number of hard links (directory entries) to this file.
 *                      Only meaningful in base MFT records.
 *                      When deleting a directory entry:
 *                        - If link_count == 1, delete the whole file
 *                        - Else remove only the $FILE_NAME attribute and decrement
 * @attrs_offset:       Byte offset from start of MFT record to first attribute.
 *                      Must be 8-byte aligned.
 * @flags:              Bit array of MFT_RECORD_* flags (see MFT_RECORD_IN_USE enum).
 *                      MFT_RECORD_IN_USE cleared when record is freed/deleted.
 * @bytes_in_use:       Number of bytes actually used in this MFT record.
 *                      Must be 8-byte aligned.
 *                      Includes header + all attributes + padding.
 * @bytes_allocated:    Total allocated size of this MFT record.
 *                      Usually equal to MFT record size (1024 bytes or cluster size).
 * @base_mft_record:    MFT reference to the base record.
 *                      0 for base records.
 *                      Non-zero for extension records → points to base record
 *                      containing the $ATTRIBUTE_LIST that describes this extension.
 * @next_attr_instance: Next attribute instance number to assign.
 *                      Incremented after each use.
 *                      Reset to 0 when MFT record is reused.
 *                      First instance is always 0.
 */
struct mft_record_old {
	__le32 magic;
	__le16 usa_ofs;
	__le16 usa_count;

	__le64 lsn;
	__le16 sequence_number;
	__le16 link_count;
	__le16 attrs_offset;
	__le16 flags;
	__le32 bytes_in_use;
	__le32 bytes_allocated;
	__le64 base_mft_record;
	__le16 next_attr_instance;
} __packed;

static_assert(sizeof(struct mft_record_old) == 42);

/*
 * System defined attributes (32-bit).  Each attribute type has a corresponding
 * attribute name (Unicode string of maximum 64 character length) as described
 * by the attribute definitions present in the data attribute of the $AttrDef
 * system file.  On NTFS 3.0 volumes the names are just as the types are named
 * in the below defines exchanging AT_ for the dollar sign ($).  If that is not
 * a revealing choice of symbol I do not know what is... (-;
 */
enum {
	AT_UNUSED			= cpu_to_le32(0),
	AT_STANDARD_INFORMATION		= cpu_to_le32(0x10),
	AT_ATTRIBUTE_LIST		= cpu_to_le32(0x20),
	AT_FILE_NAME			= cpu_to_le32(0x30),
	AT_OBJECT_ID			= cpu_to_le32(0x40),
	AT_SECURITY_DESCRIPTOR		= cpu_to_le32(0x50),
	AT_VOLUME_NAME			= cpu_to_le32(0x60),
	AT_VOLUME_INFORMATION		= cpu_to_le32(0x70),
	AT_DATA				= cpu_to_le32(0x80),
	AT_INDEX_ROOT			= cpu_to_le32(0x90),
	AT_INDEX_ALLOCATION		= cpu_to_le32(0xa0),
	AT_BITMAP			= cpu_to_le32(0xb0),
	AT_REPARSE_POINT		= cpu_to_le32(0xc0),
	AT_EA_INFORMATION		= cpu_to_le32(0xd0),
	AT_EA				= cpu_to_le32(0xe0),
	AT_PROPERTY_SET			= cpu_to_le32(0xf0),
	AT_LOGGED_UTILITY_STREAM	= cpu_to_le32(0x100),
	AT_FIRST_USER_DEFINED_ATTRIBUTE	= cpu_to_le32(0x1000),
	AT_END				= cpu_to_le32(0xffffffff)
};

/*
 * The collation rules for sorting views/indexes/etc (32-bit).
 *
 * COLLATION_BINARY - Collate by binary compare where the first byte is most
 *	significant.
 * COLLATION_UNICODE_STRING - Collate Unicode strings by comparing their binary
 *	Unicode values, except that when a character can be uppercased, the
 *	upper case value collates before the lower case one.
 * COLLATION_FILE_NAME - Collate file names as Unicode strings. The collation
 *	is done very much like COLLATION_UNICODE_STRING. In fact I have no idea
 *	what the difference is. Perhaps the difference is that file names
 *	would treat some special characters in an odd way (see
 *	unistr.c::ntfs_collate_names() and unistr.c::legal_ansi_char_array[]
 *	for what I mean but COLLATION_UNICODE_STRING would not give any special
 *	treatment to any characters at all, but this is speculation.
 * COLLATION_NTOFS_ULONG - Sorting is done according to ascending __le32 key
 *	values. E.g. used for $SII index in FILE_Secure, which sorts by
 *	security_id (le32).
 * COLLATION_NTOFS_SID - Sorting is done according to ascending SID values.
 *	E.g. used for $O index in FILE_Extend/$Quota.
 * COLLATION_NTOFS_SECURITY_HASH - Sorting is done first by ascending hash
 *	values and second by ascending security_id values. E.g. used for $SDH
 *	index in FILE_Secure.
 * COLLATION_NTOFS_ULONGS - Sorting is done according to a sequence of ascending
 *	__le32 key values. E.g. used for $O index in FILE_Extend/$ObjId, which
 *	sorts by object_id (16-byte), by splitting up the object_id in four
 *	__le32 values and using them as individual keys. E.g. take the following
 *	two security_ids, stored as follows on disk:
 *		1st: a1 61 65 b7 65 7b d4 11 9e 3d 00 e0 81 10 42 59
 *		2nd: 38 14 37 d2 d2 f3 d4 11 a5 21 c8 6b 79 b1 97 45
 *	To compare them, they are split into four __le32 values each, like so:
 *		1st: 0xb76561a1 0x11d47b65 0xe0003d9e 0x59421081
 *		2nd: 0xd2371438 0x11d4f3d2 0x6bc821a5 0x4597b179
 *	Now, it is apparent why the 2nd object_id collates after the 1st: the
 *	first __le32 value of the 1st object_id is less than the first __le32 of
 *	the 2nd object_id. If the first __le32 values of both object_ids were
 *	equal then the second __le32 values would be compared, etc.
 */
enum {
	COLLATION_BINARY		= cpu_to_le32(0x00),
	COLLATION_FILE_NAME		= cpu_to_le32(0x01),
	COLLATION_UNICODE_STRING	= cpu_to_le32(0x02),
	COLLATION_NTOFS_ULONG		= cpu_to_le32(0x10),
	COLLATION_NTOFS_SID		= cpu_to_le32(0x11),
	COLLATION_NTOFS_SECURITY_HASH	= cpu_to_le32(0x12),
	COLLATION_NTOFS_ULONGS		= cpu_to_le32(0x13),
};

/*
 * enum - Attribute definition flags
 *
 * The flags (32-bit) describing attribute properties in the attribute
 * definition structure.
 * The INDEXABLE flag is fairly certainly correct as only the file
 * name attribute has this flag set and this is the only attribute indexed in
 * NT4.
 *
 * ATTR_DEF_INDEXABLE:      Attribute can be indexed.
 *                          (Used for creating indexes like $I30, $SDH, etc.)
 * ATTR_DEF_MULTIPLE:       Attribute type can be present multiple times
 *                          in the MFT record of an inode.
 *                          (e.g., multiple $FILE_NAME, $DATA streams)
 * ATTR_DEF_NOT_ZERO:       Attribute value must contain at least one non-zero byte.
 *                          (Prevents empty or all-zero values)
 * ATTR_DEF_INDEXED_UNIQUE: Attribute must be indexed and the value must be unique
 *                          for this attribute type across all MFT records of an inode.
 *                          (e.g., security descriptor IDs in $Secure)
 * ATTR_DEF_NAMED_UNIQUE:   Attribute must be named and the name must be unique
 *                          for this attribute type across all MFT records of an inode.
 *                          (e.g., named $DATA streams or alternate data streams)
 * ATTR_DEF_RESIDENT:       Attribute must be resident (stored in MFT record).
 *                          (Cannot be non-resident/sparse/compressed)
 * ATTR_DEF_ALWAYS_LOG:     Always log modifications to this attribute in $LogFile,
 *                          regardless of whether it is resident or non-resident.
 *                          Without this flag, modifications are logged only if resident.
 *                          (Used for critical metadata attributes)
 */
enum {
	ATTR_DEF_INDEXABLE	= cpu_to_le32(0x02),
	ATTR_DEF_MULTIPLE	= cpu_to_le32(0x04),
	ATTR_DEF_NOT_ZERO	= cpu_to_le32(0x08),
	ATTR_DEF_INDEXED_UNIQUE	= cpu_to_le32(0x10),
	ATTR_DEF_NAMED_UNIQUE	= cpu_to_le32(0x20),
	ATTR_DEF_RESIDENT	= cpu_to_le32(0x40),
	ATTR_DEF_ALWAYS_LOG	= cpu_to_le32(0x80),
};

/*
 * struct attr_def - Attribute definition entry ($AttrDef array)
 *
 * The data attribute of FILE_AttrDef contains a sequence of attribute
 * definitions for the NTFS volume. With this, it is supposed to be safe for an
 * older NTFS driver to mount a volume containing a newer NTFS version without
 * damaging it (that's the theory. In practice it's: not damaging it too much).
 * Entries are sorted by attribute type. The flags describe whether the
 * attribute can be resident/non-resident and possibly other things, but the
 * actual bits are unknown.
 *
 * @name:           Unicode (UTF-16LE) name of the attribute (e.g. "$DATA", "$FILE_NAME").
 *                  Zero-terminated string, maximum 0x40 characters (128 bytes).
 *                  Used for human-readable display and debugging.
 * @type:           Attribute type code (ATTR_TYPE_* constants).
 *                  Defines which attribute this entry describes (e.g. 0x10 = $STANDARD_INFORMATION).
 * @display_rule:   Default display rule (usually 0; rarely used in modern NTFS).
 *                  Controls how the attribute is displayed in tools (legacy).
 * @collation_rule: Default collation rule for indexing this attribute.
 *                  Determines sort order when indexed (e.g. CASE_SENSITIVE, UNICODE).
 *                  Used in $I30, $SDH, $SII, etc.
 * @flags:          Bit array of attribute constraints (ATTR_DEF_* flags).
 *                  See ATTR_DEF_INDEXABLE, ATTR_DEF_MULTIPLE, etc.
 *                  Defines whether the attribute can be indexed, multiple, resident-only, etc.
 * @min_size:       Optional minimum size of the attribute value (in bytes).
 *                  0 means no minimum enforced.
 * @max_size:       Maximum allowed size of the attribute value (in bytes).
 */
struct attr_def {
	__le16 name[0x40];
	__le32 type;
	__le32 display_rule;
	__le32 collation_rule;
	__le32 flags;
	__le64 min_size;
	__le64 max_size;
} __packed;

static_assert(sizeof(struct attr_def) == 160);

/*
 * enum - Attribute flags (16-bit) for non-resident attributes
 *
 * ATTR_IS_COMPRESSED:      Attribute is compressed.
 *                          If set, data is compressed using the method in
 *                          ATTR_COMPRESSION_MASK.
 * ATTR_COMPRESSION_MASK:   Mask for compression method.
 *                          Valid values are defined in NTFS compression types
 *                          (e.g., 0x02 = LZNT1, etc.).
 *                          Also serves as the first illegal value for method.
 * ATTR_IS_ENCRYPTED:       Attribute is encrypted.
 *                          Data is encrypted using EFS (Encrypting File System).
 * ATTR_IS_SPARSE:          Attribute is sparse.
 *                          Contains holes (unallocated regions) that read as zeros.
 */
enum {
	ATTR_IS_COMPRESSED    = cpu_to_le16(0x0001),
	ATTR_COMPRESSION_MASK = cpu_to_le16(0x00ff),
	ATTR_IS_ENCRYPTED     = cpu_to_le16(0x4000),
	ATTR_IS_SPARSE	      = cpu_to_le16(0x8000),
} __packed;

/*
 * Attribute compression.
 *
 * Only the data attribute is ever compressed in the current ntfs driver in
 * Windows. Further, compression is only applied when the data attribute is
 * non-resident. Finally, to use compression, the maximum allowed cluster size
 * on a volume is 4kib.
 *
 * The compression method is based on independently compressing blocks of X
 * clusters, where X is determined from the compression_unit value found in the
 * non-resident attribute record header (more precisely: X = 2^compression_unit
 * clusters). On Windows NT/2k, X always is 16 clusters (compression_unit = 4).
 *
 * There are three different cases of how a compression block of X clusters
 * can be stored:
 *
 *   1) The data in the block is all zero (a sparse block):
 *	  This is stored as a sparse block in the runlist, i.e. the runlist
 *	  entry has length = X and lcn = -1. The mapping pairs array actually
 *	  uses a delta_lcn value length of 0, i.e. delta_lcn is not present at
 *	  all, which is then interpreted by the driver as lcn = -1.
 *	  NOTE: Even uncompressed files can be sparse on NTFS 3.0 volumes, then
 *	  the same principles apply as above, except that the length is not
 *	  restricted to being any particular value.
 *
 *   2) The data in the block is not compressed:
 *	  This happens when compression doesn't reduce the size of the block
 *	  in clusters. I.e. if compression has a small effect so that the
 *	  compressed data still occupies X clusters, then the uncompressed data
 *	  is stored in the block.
 *	  This case is recognised by the fact that the runlist entry has
 *	  length = X and lcn >= 0. The mapping pairs array stores this as
 *	  normal with a run length of X and some specific delta_lcn, i.e.
 *	  delta_lcn has to be present.
 *
 *   3) The data in the block is compressed:
 *	  The common case. This case is recognised by the fact that the run
 *	  list entry has length L < X and lcn >= 0. The mapping pairs array
 *	  stores this as normal with a run length of X and some specific
 *	  delta_lcn, i.e. delta_lcn has to be present. This runlist entry is
 *	  immediately followed by a sparse entry with length = X - L and
 *	  lcn = -1. The latter entry is to make up the vcn counting to the
 *	  full compression block size X.
 *
 * In fact, life is more complicated because adjacent entries of the same type
 * can be coalesced. This means that one has to keep track of the number of
 * clusters handled and work on a basis of X clusters at a time being one
 * block. An example: if length L > X this means that this particular runlist
 * entry contains a block of length X and part of one or more blocks of length
 * L - X. Another example: if length L < X, this does not necessarily mean that
 * the block is compressed as it might be that the lcn changes inside the block
 * and hence the following runlist entry describes the continuation of the
 * potentially compressed block. The block would be compressed if the
 * following runlist entry describes at least X - L sparse clusters, thus
 * making up the compression block length as described in point 3 above. (Of
 * course, there can be several runlist entries with small lengths so that the
 * sparse entry does not follow the first data containing entry with
 * length < X.)
 *
 * NOTE: At the end of the compressed attribute value, there most likely is not
 * just the right amount of data to make up a compression block, thus this data
 * is not even attempted to be compressed. It is just stored as is, unless
 * the number of clusters it occupies is reduced when compressed in which case
 * it is stored as a compressed compression block, complete with sparse
 * clusters at the end.
 */

/*
 * enum - Flags for resident attributes (8-bit)
 *
 * RESIDENT_ATTR_IS_INDEXED: Attribute is referenced in an index.
 *                           (e.g., part of an index key or entry)
 *                           Has implications for deletion and modification:
 *                            - Cannot be freely removed if indexed
 *                            - Index must be updated when value changes
 *                            - Used for attributes like $FILE_NAME in directories
 */
enum {
	RESIDENT_ATTR_IS_INDEXED = 0x01,
} __packed;

/*
 * Attribute record header. Always aligned to 8-byte boundary.
 */
struct attr_record {
	__le32 type;		/* The (32-bit) type of the attribute. */
	__le32 length;		/*
				 * Byte size of the resident part of the
				 * attribute (aligned to 8-byte boundary).
				 * Used to get to the next attribute.
				 */
	u8 non_resident;	/*
				 * If 0, attribute is resident.
				 * If 1, attribute is non-resident.
				 */
	u8 name_length;		/* Unicode character size of name of attribute. 0 if unnamed. */
	__le16 name_offset;	/*
				 * If name_length != 0, the byte offset to the
				 * beginning of the name from the attribute
				 * record. Note that the name is stored as a
				 * Unicode string. When creating, place offset
				 * just at the end of the record header. Then,
				 * follow with attribute value or mapping pairs
				 * array, resident and non-resident attributes
				 * respectively, aligning to an 8-byte
				 * boundary.
				 */
	__le16 flags;	/* Flags describing the attribute. */
	__le16 instance;	/*
				 * The instance of this attribute record. This
				 * number is unique within this mft record (see
				 * MFT_RECORD/next_attribute_instance notes in
				 * mft.h for more details).
				 */
	union {
		/* Resident attributes. */
		struct {
			__le32 value_length; /* Byte size of attribute value. */
			__le16 value_offset; /*
					      * Byte offset of the attribute
					      * value from the start of the
					      * attribute record. When creating,
					      * align to 8-byte boundary if we
					      * have a name present as this might
					      * not have a length of a multiple
					      * of 8-bytes.
					      */
			u8 flags;	/* See above. */
			s8 reserved;	  /* Reserved/alignment to 8-byte boundary. */
		} __packed resident;
		/* Non-resident attributes. */
		struct {
			__le64 lowest_vcn; /*
					    * Lowest valid virtual cluster number
					    * for this portion of the attribute value or
					    * 0 if this is the only extent (usually the
					    * case). - Only when an attribute list is used
					    * does lowest_vcn != 0 ever occur.
					    */
			__le64 highest_vcn; /*
					     * Highest valid vcn of this extent of
					     * the attribute value. - Usually there is only one
					     * portion, so this usually equals the attribute
					     * value size in clusters minus 1. Can be -1 for
					     * zero length files. Can be 0 for "single extent"
					     * attributes.
					     */
			__le16 mapping_pairs_offset; /*
						      * Byte offset from the beginning of
						      * the structure to the mapping pairs
						      * array which contains the mappings
						      * between the vcns and the logical cluster
						      * numbers (lcns).
						      * When creating, place this at the end of
						      * this record header aligned to 8-byte
						      * boundary.
						      */
			u8 compression_unit; /*
					      * The compression unit expressed as the log
					      * to the base 2 of the number of
					      * clusters in a compression unit.  0 means not
					      * compressed.  (This effectively limits the
					      * compression unit size to be a power of two
					      * clusters.)  WinNT4 only uses a value of 4.
					      * Sparse files have this set to 0 on XPSP2.
					      */
			u8 reserved[5];		/* Align to 8-byte boundary. */
/*
 * The sizes below are only used when lowest_vcn is zero, as otherwise it would
 * be difficult to keep them up-to-date.
 */
			__le64 allocated_size;	/*
						 * Byte size of disk space allocated
						 * to hold the attribute value. Always
						 * is a multiple of the cluster size.
						 * When a file is compressed, this field
						 * is a multiple of the compression block
						 * size (2^compression_unit) and it represents
						 * the logically allocated space rather than
						 * the actual on disk usage. For this use
						 * the compressed_size (see below).
						 */
			__le64 data_size;	/*
						 * Byte size of the attribute value. Can be
						 * larger than allocated_size if attribute value
						 * is compressed or sparse.
						 */
			__le64 initialized_size; /*
						  * Byte size of initialized portion of
						  * the attribute value. Usually equals data_size.
						  */
			__le64 compressed_size;	/*
						 * Byte size of the attribute value after
						 * compression.  Only present when compressed
						 * or sparse.  Always is a multiple of the cluster
						 * size.  Represents the actual amount of disk
						 * space being used on the disk.
						 */
		} __packed non_resident;
	} __packed data;
} __packed;

/*
 * File attribute flags (32-bit) appearing in the file_attributes fields of the
 * STANDARD_INFORMATION attribute of MFT_RECORDs and the FILENAME_ATTR
 * attributes of MFT_RECORDs and directory index entries.
 *
 * All of the below flags appear in the directory index entries but only some
 * appear in the STANDARD_INFORMATION attribute whilst only some others appear
 * in the FILENAME_ATTR attribute of MFT_RECORDs.  Unless otherwise stated the
 * flags appear in all of the above.
 */
enum {
	FILE_ATTR_READONLY		= cpu_to_le32(0x00000001),
	FILE_ATTR_HIDDEN		= cpu_to_le32(0x00000002),
	FILE_ATTR_SYSTEM		= cpu_to_le32(0x00000004),
	/* Old DOS volid. Unused in NT.	= cpu_to_le32(0x00000008), */

	FILE_ATTR_DIRECTORY		= cpu_to_le32(0x00000010),
	/*
	 * Note, FILE_ATTR_DIRECTORY is not considered valid in NT.  It is
	 * reserved for the DOS SUBDIRECTORY flag.
	 */
	FILE_ATTR_ARCHIVE		= cpu_to_le32(0x00000020),
	FILE_ATTR_DEVICE		= cpu_to_le32(0x00000040),
	FILE_ATTR_NORMAL		= cpu_to_le32(0x00000080),

	FILE_ATTR_TEMPORARY		= cpu_to_le32(0x00000100),
	FILE_ATTR_SPARSE_FILE		= cpu_to_le32(0x00000200),
	FILE_ATTR_REPARSE_POINT		= cpu_to_le32(0x00000400),
	FILE_ATTR_COMPRESSED		= cpu_to_le32(0x00000800),

	FILE_ATTR_OFFLINE		= cpu_to_le32(0x00001000),
	FILE_ATTR_NOT_CONTENT_INDEXED	= cpu_to_le32(0x00002000),
	FILE_ATTR_ENCRYPTED		= cpu_to_le32(0x00004000),

	FILE_ATTR_VALID_FLAGS		= cpu_to_le32(0x00007fb7),
	/*
	 * Note, FILE_ATTR_VALID_FLAGS masks out the old DOS VolId and the
	 * FILE_ATTR_DEVICE and preserves everything else.  This mask is used
	 * to obtain all flags that are valid for reading.
	 */
	FILE_ATTR_VALID_SET_FLAGS	= cpu_to_le32(0x000031a7),
	/*
	 * Note, FILE_ATTR_VALID_SET_FLAGS masks out the old DOS VolId, the
	 * F_A_DEVICE, F_A_DIRECTORY, F_A_SPARSE_FILE, F_A_REPARSE_POINT,
	 * F_A_COMPRESSED, and F_A_ENCRYPTED and preserves the rest.  This mask
	 * is used to obtain all flags that are valid for setting.
	 */
	/* Supposed to mean no data locally, possibly repurposed */
	FILE_ATTRIBUTE_RECALL_ON_OPEN	= cpu_to_le32(0x00040000),
	/*
	 * The flag FILE_ATTR_DUP_FILENAME_INDEX_PRESENT is present in all
	 * FILENAME_ATTR attributes but not in the STANDARD_INFORMATION
	 * attribute of an mft record.
	 */
	FILE_ATTR_DUP_FILE_NAME_INDEX_PRESENT	= cpu_to_le32(0x10000000),
	/*
	 * Note, this is a copy of the corresponding bit from the mft record,
	 * telling us whether this is a directory or not, i.e. whether it has
	 * an index root attribute or not.
	 */
	FILE_ATTR_DUP_VIEW_INDEX_PRESENT	= cpu_to_le32(0x20000000),
	/*
	 * Note, this is a copy of the corresponding bit from the mft record,
	 * telling us whether this file has a view index present (eg. object id
	 * index, quota index, one of the security indexes or the encrypting
	 * filesystem related indexes).
	 */
};

/*
 * NOTE on times in NTFS: All times are in MS standard time format, i.e. they
 * are the number of 100-nanosecond intervals since 1st January 1601, 00:00:00
 * universal coordinated time (UTC). (In Linux time starts 1st January 1970,
 * 00:00:00 UTC and is stored as the number of 1-second intervals since then.)
 */

/*
 * Attribute: Standard information (0x10).
 *
 * NOTE: Always resident.
 * NOTE: Present in all base file records on a volume.
 * NOTE: There is conflicting information about the meaning of each of the time
 *	 fields but the meaning as defined below has been verified to be
 *	 correct by practical experimentation on Windows NT4 SP6a and is hence
 *	 assumed to be the one and only correct interpretation.
 */
struct standard_information {
	__le64 creation_time;		/*
					 * Time file was created. Updated when
					 * a filename is changed(?).
					 */
	__le64 last_data_change_time;	/* Time the data attribute was last modified. */
	__le64 last_mft_change_time;	/* Time this mft record was last modified. */
	__le64 last_access_time;	/*
					 * Approximate time when the file was
					 * last accessed (obviously this is not
					 * updated on read-only volumes). In
					 * Windows this is only updated when
					 * accessed if some time delta has
					 * passed since the last update. Also,
					 * last access time updates can be
					 * disabled altogether for speed.
					 */
	__le32 file_attributes; /* Flags describing the file. */
	union {
	/* NTFS 1.2 */
		struct {
			u8 reserved12[12];	/* Reserved/alignment to 8-byte boundary. */
		} __packed v1;
	/* NTFS 3.x */
		struct {
/*
 * If a volume has been upgraded from a previous NTFS version, then these
 * fields are present only if the file has been accessed since the upgrade.
 * Recognize the difference by comparing the length of the resident attribute
 * value. If it is 48, then the following fields are missing. If it is 72 then
 * the fields are present. Maybe just check like this:
 *	if (resident.ValueLength < sizeof(struct standard_information)) {
 *		Assume NTFS 1.2- format.
 *		If (volume version is 3.x)
 *			Upgrade attribute to NTFS 3.x format.
 *		else
 *			Use NTFS 1.2- format for access.
 *	} else
 *		Use NTFS 3.x format for access.
 * Only problem is that it might be legal to set the length of the value to
 * arbitrarily large values thus spoiling this check. - But chkdsk probably
 * views that as a corruption, assuming that it behaves like this for all
 * attributes.
 */
			__le32 maximum_versions; /*
						  * Maximum allowed versions for
						  * file. Zero if version numbering
						  * is disabled.
						  */
			__le32 version_number;	/*
						 * This file's version (if any).
						 * Set to zero if maximum_versions
						 * is zero.
						 */
			__le32 class_id;	/*
						 * Class id from bidirectional
						 * class id index (?).
						 */
			__le32 owner_id;	/*
						 * Owner_id of the user owning
						 * the file. Translate via $Q index
						 * in FILE_Extend /$Quota to the quota
						 * control entry for the user owning
						 * the file. Zero if quotas are disabled.
						 */
			__le32 security_id;	/*
						 * Security_id for the file. Translate via
						 * $SII index and $SDS data stream in
						 * FILE_Secure to the security descriptor.
						 */
			__le64 quota_charged;	/*
						 * Byte size of the charge to the quota for
						 * all streams of the file. Note: Is zero
						 * if quotas are disabled.
						 */
			__le64 usn;		/*
						 * Last update sequence number of the file.
						 * This is a direct index into the transaction
						 * log file ($UsnJrnl).  It is zero if the usn
						 * journal is disabled or this file has not been
						 * subject to logging yet.  See usnjrnl.h
						 * for details.
						 */
		} __packed v3;
	} __packed ver;
} __packed;

/*
 * Attribute: Attribute list (0x20).
 *
 * - Can be either resident or non-resident.
 * - Value consists of a sequence of variable length, 8-byte aligned,
 * ATTR_LIST_ENTRY records.
 * - The list is not terminated by anything at all! The only way to know when
 * the end is reached is to keep track of the current offset and compare it to
 * the attribute value size.
 * - The attribute list attribute contains one entry for each attribute of
 * the file in which the list is located, except for the list attribute
 * itself. The list is sorted: first by attribute type, second by attribute
 * name (if present), third by instance number. The extents of one
 * non-resident attribute (if present) immediately follow after the initial
 * extent. They are ordered by lowest_vcn and have their instance set to zero.
 * It is not allowed to have two attributes with all sorting keys equal.
 * - Further restrictions:
 *	- If not resident, the vcn to lcn mapping array has to fit inside the
 *	  base mft record.
 *	- The attribute list attribute value has a maximum size of 256kb. This
 *	  is imposed by the Windows cache manager.
 * - Attribute lists are only used when the attributes of mft record do not
 * fit inside the mft record despite all attributes (that can be made
 * non-resident) having been made non-resident. This can happen e.g. when:
 *	- File has a large number of hard links (lots of file name
 *	  attributes present).
 *	- The mapping pairs array of some non-resident attribute becomes so
 *	  large due to fragmentation that it overflows the mft record.
 *	- The security descriptor is very complex (not applicable to
 *	  NTFS 3.0 volumes).
 *	- There are many named streams.
 */
struct attr_list_entry {
	__le32 type;		/* Type of referenced attribute. */
	__le16 length;		/* Byte size of this entry (8-byte aligned). */
	u8 name_length;		/*
				 * Size in Unicode chars of the name of the
				 * attribute or 0 if unnamed.
				 */
	u8 name_offset;		/*
				 * Byte offset to beginning of attribute name
				 * (always set this to where the name would
				 * start even if unnamed).
				 */
	__le64 lowest_vcn;	/*
				 * Lowest virtual cluster number of this portion
				 * of the attribute value. This is usually 0. It
				 * is non-zero for the case where one attribute
				 * does not fit into one mft record and thus
				 * several mft records are allocated to hold
				 * this attribute. In the latter case, each mft
				 * record holds one extent of the attribute and
				 * there is one attribute list entry for each
				 * extent. NOTE: This is DEFINITELY a signed
				 * value! The windows driver uses cmp, followed
				 * by jg when comparing this, thus it treats it
				 * as signed.
				 */
	__le64 mft_reference;	/*
				 * The reference of the mft record holding
				 * the attr record for this portion of the
				 * attribute value.
				 */
	__le16 instance;	/*
				 * If lowest_vcn = 0, the instance of the
				 * attribute being referenced; otherwise 0.
				 */
	__le16 name[];		/*
				 * Use when creating only. When reading use
				 * name_offset to determine the location of the name.
				 */
} __packed;

/*
 * The maximum allowed length for a file name.
 */
#define MAXIMUM_FILE_NAME_LENGTH	255

/*
 * Possible namespaces for filenames in ntfs (8-bit).
 */
enum {
	FILE_NAME_POSIX		= 0x00,
	/*
	 * This is the largest namespace. It is case sensitive and allows all
	 * Unicode characters except for: '\0' and '/'.  Beware that in
	 * WinNT/2k/2003 by default files which eg have the same name except
	 * for their case will not be distinguished by the standard utilities
	 * and thus a "del filename" will delete both "filename" and "fileName"
	 * without warning.  However if for example Services For Unix (SFU) are
	 * installed and the case sensitive option was enabled at installation
	 * time, then you can create/access/delete such files.
	 * Note that even SFU places restrictions on the filenames beyond the
	 * '\0' and '/' and in particular the following set of characters is
	 * not allowed: '"', '/', '<', '>', '\'.  All other characters,
	 * including the ones no allowed in WIN32 namespace are allowed.
	 * Tested with SFU 3.5 (this is now free) running on Windows XP.
	 */
	FILE_NAME_WIN32		= 0x01,
	/*
	 * The standard WinNT/2k NTFS long filenames. Case insensitive.  All
	 * Unicode chars except: '\0', '"', '*', '/', ':', '<', '>', '?', '\',
	 * and '|'.  Further, names cannot end with a '.' or a space.
	 */
	FILE_NAME_DOS		= 0x02,
	/*
	 * The standard DOS filenames (8.3 format). Uppercase only.  All 8-bit
	 * characters greater space, except: '"', '*', '+', ',', '/', ':', ';',
	 * '<', '=', '>', '?', and '\'.\
	 */
	FILE_NAME_WIN32_AND_DOS	= 0x03,
	/*
	 * 3 means that both the Win32 and the DOS filenames are identical and
	 * hence have been saved in this single filename record.
	 */
} __packed;

/*
 * Attribute: Filename (0x30).
 *
 * NOTE: Always resident.
 * NOTE: All fields, except the parent_directory, are only updated when the
 *	 filename is changed. Until then, they just become out of sync with
 *	 reality and the more up to date values are present in the standard
 *	 information attribute.
 * NOTE: There is conflicting information about the meaning of each of the time
 *	 fields but the meaning as defined below has been verified to be
 *	 correct by practical experimentation on Windows NT4 SP6a and is hence
 *	 assumed to be the one and only correct interpretation.
 */
struct file_name_attr {
/*hex ofs*/
	__le64 parent_directory;		/* Directory this filename is referenced from. */
	__le64 creation_time;		/* Time file was created. */
	__le64 last_data_change_time;	/* Time the data attribute was last modified. */
	__le64 last_mft_change_time;	/* Time this mft record was last modified. */
	__le64 last_access_time;		/* Time this mft record was last accessed. */
	__le64 allocated_size;		/*
					 * Byte size of on-disk allocated space
					 * for the unnamed data attribute.  So for normal
					 * $DATA, this is the allocated_size from
					 * the unnamed $DATA attribute and for compressed
					 * and/or sparse $DATA, this is the
					 * compressed_size from the unnamed
					 * $DATA attribute.  For a directory or
					 * other inode without an unnamed $DATA attribute,
					 * this is always 0.  NOTE: This is a multiple of
					 * the cluster size.
					 */
	__le64 data_size;		/*
					 * Byte size of actual data in unnamed
					 * data attribute.  For a directory or
					 * other inode without an unnamed $DATA
					 * attribute, this is always 0.
					 */
	__le32 file_attributes;		/* Flags describing the file. */
	union {
		struct {
			__le16 packed_ea_size;	/*
						 * Size of the buffer needed to
						 * pack the extended attributes
						 * (EAs), if such are present.
						 */
			__le16 reserved;	/* Reserved for alignment. */
		} __packed ea;
		struct {
			__le32 reparse_point_tag; /*
						   * Type of reparse point,
						   * present only in reparse
						   * points and only if there are
						   * no EAs.
						   */
		} __packed rp;
	} __packed type;
	u8 file_name_length;			/* Length of file name in (Unicode) characters. */
	u8 file_name_type;			/* Namespace of the file name.*/
	__le16 file_name[];			/* File name in Unicode. */
} __packed;

/*
 * GUID structures store globally unique identifiers (GUID). A GUID is a
 * 128-bit value consisting of one group of eight hexadecimal digits, followed
 * by three groups of four hexadecimal digits each, followed by one group of
 * twelve hexadecimal digits. GUIDs are Microsoft's implementation of the
 * distributed computing environment (DCE) universally unique identifier (UUID).
 * Example of a GUID:
 *	1F010768-5A73-BC91-0010A52216A7
 */
struct guid {
	__le32 data1;	/* The first eight hexadecimal digits of the GUID. */
	__le16 data2;	/* The first group of four hexadecimal digits. */
	__le16 data3;	/* The second group of four hexadecimal digits. */
	u8 data4[8];	/*
			 * The first two bytes are the third group of four
			 * hexadecimal digits. The remaining six bytes are the
			 * final 12 hexadecimal digits.
			 */
} __packed;

/*
 * struct OBJECT_ID_ATTR - Attribute: Object id (NTFS 3.0+) (0x40).
 *
 * NOTE: Always resident.
 */
struct object_id_attr {
	struct guid object_id;	/* Unique id assigned to the file.*/
	/*
	 * The following fields are optional. The attribute value size is 16
	 * bytes, i.e. sizeof(struct guid), if these are not present at all.
	 * Note, the entries can be present but one or more (or all) can be
	 * zero meaning that particular value(s) is(are) not defined. Note,
	 * when the fields are missing here, it is well possible that they are
	 * to be found within the $Extend/$ObjId system file indexed under the
	 * above object_id.
	 */
	union {
		struct {
			struct guid birth_volume_id;
			struct guid birth_object_id;
			struct guid domain_id;
		} __packed;
		u8 extended_info[48];
	} __packed;
} __packed;

/*
 * These relative identifiers (RIDs) are used with the above identifier
 * authorities to make up universal well-known SIDs.
 *
 * Note: The relative identifier (RID) refers to the portion of a SID, which
 * identifies a user or group in relation to the authority that issued the SID.
 * For example, the universal well-known SID Creator Owner ID (S-1-3-0) is
 * made up of the identifier authority SECURITY_CREATOR_SID_AUTHORITY (3) and
 * the relative identifier SECURITY_CREATOR_OWNER_RID (0).
 */
enum {					/* Identifier authority. */
	SECURITY_NULL_RID			= 0,	/* S-1-0 */
	SECURITY_WORLD_RID			= 0,	/* S-1-1 */
	SECURITY_LOCAL_RID			= 0,	/* S-1-2 */

	SECURITY_CREATOR_OWNER_RID		= 0,	/* S-1-3 */
	SECURITY_CREATOR_GROUP_RID		= 1,	/* S-1-3 */

	SECURITY_CREATOR_OWNER_SERVER_RID	= 2,	/* S-1-3 */
	SECURITY_CREATOR_GROUP_SERVER_RID	= 3,	/* S-1-3 */

	SECURITY_DIALUP_RID			= 1,
	SECURITY_NETWORK_RID			= 2,
	SECURITY_BATCH_RID			= 3,
	SECURITY_INTERACTIVE_RID		= 4,
	SECURITY_SERVICE_RID			= 6,
	SECURITY_ANONYMOUS_LOGON_RID		= 7,
	SECURITY_PROXY_RID			= 8,
	SECURITY_ENTERPRISE_CONTROLLERS_RID	= 9,
	SECURITY_SERVER_LOGON_RID		= 9,
	SECURITY_PRINCIPAL_SELF_RID		= 0xa,
	SECURITY_AUTHENTICATED_USER_RID		= 0xb,
	SECURITY_RESTRICTED_CODE_RID		= 0xc,
	SECURITY_TERMINAL_SERVER_RID		= 0xd,

	SECURITY_LOGON_IDS_RID			= 5,
	SECURITY_LOGON_IDS_RID_COUNT		= 3,

	SECURITY_LOCAL_SYSTEM_RID		= 0x12,

	SECURITY_NT_NON_UNIQUE			= 0x15,

	SECURITY_BUILTIN_DOMAIN_RID		= 0x20,

	/*
	 * Well-known domain relative sub-authority values (RIDs).
	 */

	/* Users. */
	DOMAIN_USER_RID_ADMIN			= 0x1f4,
	DOMAIN_USER_RID_GUEST			= 0x1f5,
	DOMAIN_USER_RID_KRBTGT			= 0x1f6,

	/* Groups. */
	DOMAIN_GROUP_RID_ADMINS			= 0x200,
	DOMAIN_GROUP_RID_USERS			= 0x201,
	DOMAIN_GROUP_RID_GUESTS			= 0x202,
	DOMAIN_GROUP_RID_COMPUTERS		= 0x203,
	DOMAIN_GROUP_RID_CONTROLLERS		= 0x204,
	DOMAIN_GROUP_RID_CERT_ADMINS		= 0x205,
	DOMAIN_GROUP_RID_SCHEMA_ADMINS		= 0x206,
	DOMAIN_GROUP_RID_ENTERPRISE_ADMINS	= 0x207,
	DOMAIN_GROUP_RID_POLICY_ADMINS		= 0x208,

	/* Aliases. */
	DOMAIN_ALIAS_RID_ADMINS			= 0x220,
	DOMAIN_ALIAS_RID_USERS			= 0x221,
	DOMAIN_ALIAS_RID_GUESTS			= 0x222,
	DOMAIN_ALIAS_RID_POWER_USERS		= 0x223,

	DOMAIN_ALIAS_RID_ACCOUNT_OPS		= 0x224,
	DOMAIN_ALIAS_RID_SYSTEM_OPS		= 0x225,
	DOMAIN_ALIAS_RID_PRINT_OPS		= 0x226,
	DOMAIN_ALIAS_RID_BACKUP_OPS		= 0x227,

	DOMAIN_ALIAS_RID_REPLICATOR		= 0x228,
	DOMAIN_ALIAS_RID_RAS_SERVERS		= 0x229,
	DOMAIN_ALIAS_RID_PREW2KCOMPACCESS	= 0x22a,
};

/*
 * The universal well-known SIDs:
 *
 *	NULL_SID			S-1-0-0
 *	WORLD_SID			S-1-1-0
 *	LOCAL_SID			S-1-2-0
 *	CREATOR_OWNER_SID		S-1-3-0
 *	CREATOR_GROUP_SID		S-1-3-1
 *	CREATOR_OWNER_SERVER_SID	S-1-3-2
 *	CREATOR_GROUP_SERVER_SID	S-1-3-3
 *
 *	(Non-unique IDs)		S-1-4
 *
 * NT well-known SIDs:
 *
 *	NT_AUTHORITY_SID	S-1-5
 *	DIALUP_SID		S-1-5-1
 *
 *	NETWORD_SID		S-1-5-2
 *	BATCH_SID		S-1-5-3
 *	INTERACTIVE_SID		S-1-5-4
 *	SERVICE_SID		S-1-5-6
 *	ANONYMOUS_LOGON_SID	S-1-5-7		(aka null logon session)
 *	PROXY_SID		S-1-5-8
 *	SERVER_LOGON_SID	S-1-5-9		(aka domain controller account)
 *	SELF_SID		S-1-5-10	(self RID)
 *	AUTHENTICATED_USER_SID	S-1-5-11
 *	RESTRICTED_CODE_SID	S-1-5-12	(running restricted code)
 *	TERMINAL_SERVER_SID	S-1-5-13	(running on terminal server)
 *
 *	(Logon IDs)		S-1-5-5-X-Y
 *
 *	(NT non-unique IDs)	S-1-5-0x15-...
 *
 *	(Built-in domain)	S-1-5-0x20
 */

/*
 * The SID structure is a variable-length structure used to uniquely identify
 * users or groups. SID stands for security identifier.
 *
 * The standard textual representation of the SID is of the form:
 *	S-R-I-S-S...
 * Where:
 *    - The first "S" is the literal character 'S' identifying the following
 *	digits as a SID.
 *    - R is the revision level of the SID expressed as a sequence of digits
 *	either in decimal or hexadecimal (if the later, prefixed by "0x").
 *    - I is the 48-bit identifier_authority, expressed as digits as R above.
 *    - S... is one or more sub_authority values, expressed as digits as above.
 *
 * Example SID; the domain-relative SID of the local Administrators group on
 * Windows NT/2k:
 *	S-1-5-32-544
 * This translates to a SID with:
 *	revision = 1,
 *	sub_authority_count = 2,
 *	identifier_authority = {0,0,0,0,0,5},	// SECURITY_NT_AUTHORITY
 *	sub_authority[0] = 32,			// SECURITY_BUILTIN_DOMAIN_RID
 *	sub_authority[1] = 544			// DOMAIN_ALIAS_RID_ADMINS
 */
struct ntfs_sid {
	u8 revision;
	u8 sub_authority_count;
	union {
		struct {
			u16 high_part;  /* High 16-bits. */
			u32 low_part;   /* Low 32-bits. */
		} __packed parts;
		u8 value[6];            /* Value as individual bytes. */
	} identifier_authority;
	__le32 sub_authority[];		/* At least one sub_authority. */
} __packed;

/*
 * The predefined ACE types (8-bit, see below).
 */
enum {
	ACCESS_MIN_MS_ACE_TYPE			= 0,
	ACCESS_ALLOWED_ACE_TYPE			= 0,
	ACCESS_DENIED_ACE_TYPE			= 1,
	SYSTEM_AUDIT_ACE_TYPE			= 2,
	SYSTEM_ALARM_ACE_TYPE			= 3, /* Not implemented as of Win2k. */
	ACCESS_MAX_MS_V2_ACE_TYPE		= 3,

	ACCESS_ALLOWED_COMPOUND_ACE_TYPE	= 4,
	ACCESS_MAX_MS_V3_ACE_TYPE		= 4,

	/* The following are Win2k only. */
	ACCESS_MIN_MS_OBJECT_ACE_TYPE		= 5,
	ACCESS_ALLOWED_OBJECT_ACE_TYPE		= 5,
	ACCESS_DENIED_OBJECT_ACE_TYPE		= 6,
	SYSTEM_AUDIT_OBJECT_ACE_TYPE		= 7,
	SYSTEM_ALARM_OBJECT_ACE_TYPE		= 8,
	ACCESS_MAX_MS_OBJECT_ACE_TYPE		= 8,

	ACCESS_MAX_MS_V4_ACE_TYPE		= 8,

	/* This one is for WinNT/2k. */
	ACCESS_MAX_MS_ACE_TYPE			= 8,
} __packed;

/*
 * The ACE flags (8-bit) for audit and inheritance (see below).
 *
 * SUCCESSFUL_ACCESS_ACE_FLAG is only used with system audit and alarm ACE
 * types to indicate that a message is generated (in Windows!) for successful
 * accesses.
 *
 * FAILED_ACCESS_ACE_FLAG is only used with system audit and alarm ACE types
 * to indicate that a message is generated (in Windows!) for failed accesses.
 */
enum {
	/* The inheritance flags. */
	OBJECT_INHERIT_ACE		= 0x01,
	CONTAINER_INHERIT_ACE		= 0x02,
	NO_PROPAGATE_INHERIT_ACE	= 0x04,
	INHERIT_ONLY_ACE		= 0x08,
	INHERITED_ACE			= 0x10,	/* Win2k only. */
	VALID_INHERIT_FLAGS		= 0x1f,

	/* The audit flags. */
	SUCCESSFUL_ACCESS_ACE_FLAG	= 0x40,
	FAILED_ACCESS_ACE_FLAG		= 0x80,
} __packed;

/*
 * The access mask (32-bit). Defines the access rights.
 *
 * The specific rights (bits 0 to 15).  These depend on the type of the object
 * being secured by the ACE.
 */
enum {
	/* Specific rights for files and directories are as follows: */

	/* Right to read data from the file. (FILE) */
	FILE_READ_DATA			= cpu_to_le32(0x00000001),
	/* Right to list contents of a directory. (DIRECTORY) */
	FILE_LIST_DIRECTORY		= cpu_to_le32(0x00000001),

	/* Right to write data to the file. (FILE) */
	FILE_WRITE_DATA			= cpu_to_le32(0x00000002),
	/* Right to create a file in the directory. (DIRECTORY) */
	FILE_ADD_FILE			= cpu_to_le32(0x00000002),

	/* Right to append data to the file. (FILE) */
	FILE_APPEND_DATA		= cpu_to_le32(0x00000004),
	/* Right to create a subdirectory. (DIRECTORY) */
	FILE_ADD_SUBDIRECTORY		= cpu_to_le32(0x00000004),

	/* Right to read extended attributes. (FILE/DIRECTORY) */
	FILE_READ_EA			= cpu_to_le32(0x00000008),

	/* Right to write extended attributes. (FILE/DIRECTORY) */
	FILE_WRITE_EA			= cpu_to_le32(0x00000010),

	/* Right to execute a file. (FILE) */
	FILE_EXECUTE			= cpu_to_le32(0x00000020),
	/* Right to traverse the directory. (DIRECTORY) */
	FILE_TRAVERSE			= cpu_to_le32(0x00000020),

	/*
	 * Right to delete a directory and all the files it contains (its
	 * children), even if the files are read-only. (DIRECTORY)
	 */
	FILE_DELETE_CHILD		= cpu_to_le32(0x00000040),

	/* Right to read file attributes. (FILE/DIRECTORY) */
	FILE_READ_ATTRIBUTES		= cpu_to_le32(0x00000080),

	/* Right to change file attributes. (FILE/DIRECTORY) */
	FILE_WRITE_ATTRIBUTES		= cpu_to_le32(0x00000100),

	/*
	 * The standard rights (bits 16 to 23).  These are independent of the
	 * type of object being secured.
	 */

	/* Right to delete the object. */
	DELETE				= cpu_to_le32(0x00010000),

	/*
	 * Right to read the information in the object's security descriptor,
	 * not including the information in the SACL, i.e. right to read the
	 * security descriptor and owner.
	 */
	READ_CONTROL			= cpu_to_le32(0x00020000),

	/* Right to modify the DACL in the object's security descriptor. */
	WRITE_DAC			= cpu_to_le32(0x00040000),

	/* Right to change the owner in the object's security descriptor. */
	WRITE_OWNER			= cpu_to_le32(0x00080000),

	/*
	 * Right to use the object for synchronization.  Enables a process to
	 * wait until the object is in the signalled state.  Some object types
	 * do not support this access right.
	 */
	SYNCHRONIZE			= cpu_to_le32(0x00100000),

	/*
	 * The following STANDARD_RIGHTS_* are combinations of the above for
	 * convenience and are defined by the Win32 API.
	 */

	/* These are currently defined to READ_CONTROL. */
	STANDARD_RIGHTS_READ		= cpu_to_le32(0x00020000),
	STANDARD_RIGHTS_WRITE		= cpu_to_le32(0x00020000),
	STANDARD_RIGHTS_EXECUTE		= cpu_to_le32(0x00020000),

	/* Combines DELETE, READ_CONTROL, WRITE_DAC, and WRITE_OWNER access. */
	STANDARD_RIGHTS_REQUIRED	= cpu_to_le32(0x000f0000),

	/*
	 * Combines DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, and
	 * SYNCHRONIZE access.
	 */
	STANDARD_RIGHTS_ALL		= cpu_to_le32(0x001f0000),

	/*
	 * The access system ACL and maximum allowed access types (bits 24 to
	 * 25, bits 26 to 27 are reserved).
	 */
	ACCESS_SYSTEM_SECURITY		= cpu_to_le32(0x01000000),
	MAXIMUM_ALLOWED			= cpu_to_le32(0x02000000),

	/*
	 * The generic rights (bits 28 to 31).  These map onto the standard and
	 * specific rights.
	 */

	/* Read, write, and execute access. */
	GENERIC_ALL			= cpu_to_le32(0x10000000),

	/* Execute access. */
	GENERIC_EXECUTE			= cpu_to_le32(0x20000000),

	/*
	 * Write access.  For files, this maps onto:
	 *	FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA |
	 *	FILE_WRITE_EA | STANDARD_RIGHTS_WRITE | SYNCHRONIZE
	 * For directories, the mapping has the same numerical value.  See
	 * above for the descriptions of the rights granted.
	 */
	GENERIC_WRITE			= cpu_to_le32(0x40000000),

	/*
	 * Read access.  For files, this maps onto:
	 *	FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA |
	 *	STANDARD_RIGHTS_READ | SYNCHRONIZE
	 * For directories, the mapping has the same numberical value.  See
	 * above for the descriptions of the rights granted.
	 */
	GENERIC_READ			= cpu_to_le32(0x80000000),
};

/*
 * The predefined ACE type structures are as defined below.
 */

struct ntfs_ace {
	u8 type;		/* Type of the ACE. */
	u8 flags;		/* Flags describing the ACE. */
	__le16 size;		/* Size in bytes of the ACE. */
	__le32 mask;	/* Access mask associated with the ACE. */
	struct ntfs_sid sid;	/* The SID associated with the ACE. */
} __packed;

/*
 * The object ACE flags (32-bit).
 */
enum {
	ACE_OBJECT_TYPE_PRESENT			= cpu_to_le32(1),
	ACE_INHERITED_OBJECT_TYPE_PRESENT	= cpu_to_le32(2),
};

/*
 * An ACL is an access-control list (ACL).
 * An ACL starts with an ACL header structure, which specifies the size of
 * the ACL and the number of ACEs it contains. The ACL header is followed by
 * zero or more access control entries (ACEs). The ACL as well as each ACE
 * are aligned on 4-byte boundaries.
 */
struct ntfs_acl {
	u8 revision;	/* Revision of this ACL. */
	u8 alignment1;
	__le16 size;	/*
			 * Allocated space in bytes for ACL. Includes this
			 * header, the ACEs and the remaining free space.
			 */
	__le16 ace_count;	/* Number of ACEs in the ACL. */
	__le16 alignment2;
} __packed;

static_assert(sizeof(struct ntfs_acl) == 8);

/*
 * The security descriptor control flags (16-bit).
 *
 * SE_OWNER_DEFAULTED - This boolean flag, when set, indicates that the SID
 *	pointed to by the Owner field was provided by a defaulting mechanism
 *	rather than explicitly provided by the original provider of the
 *	security descriptor.  This may affect the treatment of the SID with
 *	respect to inheritance of an owner.
 *
 * SE_GROUP_DEFAULTED - This boolean flag, when set, indicates that the SID in
 *	the Group field was provided by a defaulting mechanism rather than
 *	explicitly provided by the original provider of the security
 *	descriptor.  This may affect the treatment of the SID with respect to
 *	inheritance of a primary group.
 *
 * SE_DACL_PRESENT - This boolean flag, when set, indicates that the security
 *	descriptor contains a discretionary ACL.  If this flag is set and the
 *	Dacl field of the SECURITY_DESCRIPTOR is null, then a null ACL is
 *	explicitly being specified.
 *
 * SE_DACL_DEFAULTED - This boolean flag, when set, indicates that the ACL
 *	pointed to by the Dacl field was provided by a defaulting mechanism
 *	rather than explicitly provided by the original provider of the
 *	security descriptor.  This may affect the treatment of the ACL with
 *	respect to inheritance of an ACL.  This flag is ignored if the
 *	DaclPresent flag is not set.
 *
 * SE_SACL_PRESENT - This boolean flag, when set,  indicates that the security
 *	descriptor contains a system ACL pointed to by the Sacl field.  If this
 *	flag is set and the Sacl field of the SECURITY_DESCRIPTOR is null, then
 *	an empty (but present) ACL is being specified.
 *
 * SE_SACL_DEFAULTED - This boolean flag, when set, indicates that the ACL
 *	pointed to by the Sacl field was provided by a defaulting mechanism
 *	rather than explicitly provided by the original provider of the
 *	security descriptor.  This may affect the treatment of the ACL with
 *	respect to inheritance of an ACL.  This flag is ignored if the
 *	SaclPresent flag is not set.
 *
 * SE_SELF_RELATIVE - This boolean flag, when set, indicates that the security
 *	descriptor is in self-relative form.  In this form, all fields of the
 *	security descriptor are contiguous in memory and all pointer fields are
 *	expressed as offsets from the beginning of the security descriptor.
 */
enum {
	SE_OWNER_DEFAULTED		= cpu_to_le16(0x0001),
	SE_GROUP_DEFAULTED		= cpu_to_le16(0x0002),
	SE_DACL_PRESENT			= cpu_to_le16(0x0004),
	SE_DACL_DEFAULTED		= cpu_to_le16(0x0008),

	SE_SACL_PRESENT			= cpu_to_le16(0x0010),
	SE_SACL_DEFAULTED		= cpu_to_le16(0x0020),

	SE_DACL_AUTO_INHERIT_REQ	= cpu_to_le16(0x0100),
	SE_SACL_AUTO_INHERIT_REQ	= cpu_to_le16(0x0200),
	SE_DACL_AUTO_INHERITED		= cpu_to_le16(0x0400),
	SE_SACL_AUTO_INHERITED		= cpu_to_le16(0x0800),

	SE_DACL_PROTECTED		= cpu_to_le16(0x1000),
	SE_SACL_PROTECTED		= cpu_to_le16(0x2000),
	SE_RM_CONTROL_VALID		= cpu_to_le16(0x4000),
	SE_SELF_RELATIVE		= cpu_to_le16(0x8000)
} __packed;

/*
 * Self-relative security descriptor. Contains the owner and group SIDs as well
 * as the sacl and dacl ACLs inside the security descriptor itself.
 */
struct security_descriptor_relative {
	u8 revision;	/* Revision level of the security descriptor. */
	u8 alignment;
	__le16 control;	/*
			 * Flags qualifying the type of * the descriptor as well as
			 * the following fields.
			 */
	__le32 owner;	/*
			 * Byte offset to a SID representing an object's
			 * owner. If this is NULL, no owner SID is present in
			 * the descriptor.
			 */
	__le32 group;	/*
			 * Byte offset to a SID representing an object's
			 * primary group. If this is NULL, no primary group
			 * SID is present in the descriptor.
			 */
	__le32 sacl;	/*
			 * Byte offset to a system ACL. Only valid, if
			 * SE_SACL_PRESENT is set in the control field. If
			 * SE_SACL_PRESENT is set but sacl is NULL, a NULL ACL
			 * is specified.
			 */
	__le32 dacl;	/*
			 * Byte offset to a discretionary ACL. Only valid, if
			 * SE_DACL_PRESENT is set in the control field. If
			 * SE_DACL_PRESENT is set but dacl is NULL, a NULL ACL
			 * (unconditionally granting access) is specified.
			 */
} __packed;

static_assert(sizeof(struct security_descriptor_relative) == 20);

/*
 * On NTFS 3.0+, all security descriptors are stored in FILE_Secure. Only one
 * referenced instance of each unique security descriptor is stored.
 *
 * FILE_Secure contains no unnamed data attribute, i.e. it has zero length. It
 * does, however, contain two indexes ($SDH and $SII) as well as a named data
 * stream ($SDS).
 *
 * Every unique security descriptor is assigned a unique security identifier
 * (security_id, not to be confused with a SID). The security_id is unique for
 * the NTFS volume and is used as an index into the $SII index, which maps
 * security_ids to the security descriptor's storage location within the $SDS
 * data attribute. The $SII index is sorted by ascending security_id.
 *
 * A simple hash is computed from each security descriptor. This hash is used
 * as an index into the $SDH index, which maps security descriptor hashes to
 * the security descriptor's storage location within the $SDS data attribute.
 * The $SDH index is sorted by security descriptor hash and is stored in a B+
 * tree. When searching $SDH (with the intent of determining whether or not a
 * new security descriptor is already present in the $SDS data stream), if a
 * matching hash is found, but the security descriptors do not match, the
 * search in the $SDH index is continued, searching for a next matching hash.
 *
 * When a precise match is found, the security_id coresponding to the security
 * descriptor in the $SDS attribute is read from the found $SDH index entry and
 * is stored in the $STANDARD_INFORMATION attribute of the file/directory to
 * which the security descriptor is being applied. The $STANDARD_INFORMATION
 * attribute is present in all base mft records (i.e. in all files and
 * directories).
 *
 * If a match is not found, the security descriptor is assigned a new unique
 * security_id and is added to the $SDS data attribute. Then, entries
 * referencing the this security descriptor in the $SDS data attribute are
 * added to the $SDH and $SII indexes.
 *
 * Note: Entries are never deleted from FILE_Secure, even if nothing
 * references an entry any more.
 */

/*
 * The index entry key used in the $SII index. The collation type is
 * COLLATION_NTOFS_ULONG.
 */
struct sii_index_key {
	__le32 security_id; /* The security_id assigned to the descriptor. */
} __packed;

/*
 * The index entry key used in the $SDH index. The keys are sorted first by
 * hash and then by security_id. The collation rule is
 * COLLATION_NTOFS_SECURITY_HASH.
 */
struct sdh_index_key {
	__le32 hash;	  /* Hash of the security descriptor. */
	__le32 security_id; /* The security_id assigned to the descriptor. */
} __packed;

/*
 * Possible flags for the volume (16-bit).
 */
enum {
	VOLUME_IS_DIRTY			= cpu_to_le16(0x0001),
	VOLUME_RESIZE_LOG_FILE		= cpu_to_le16(0x0002),
	VOLUME_UPGRADE_ON_MOUNT		= cpu_to_le16(0x0004),
	VOLUME_MOUNTED_ON_NT4		= cpu_to_le16(0x0008),

	VOLUME_DELETE_USN_UNDERWAY	= cpu_to_le16(0x0010),
	VOLUME_REPAIR_OBJECT_ID		= cpu_to_le16(0x0020),

	VOLUME_CHKDSK_UNDERWAY		= cpu_to_le16(0x4000),
	VOLUME_MODIFIED_BY_CHKDSK	= cpu_to_le16(0x8000),

	VOLUME_FLAGS_MASK		= cpu_to_le16(0xc03f),

	/* To make our life easier when checking if we must mount read-only. */
	VOLUME_MUST_MOUNT_RO_MASK	= cpu_to_le16(0xc027),
} __packed;

/*
 * Attribute: Volume information (0x70).
 *
 * NOTE: Always resident.
 * NOTE: Present only in FILE_Volume.
 * NOTE: Windows 2000 uses NTFS 3.0 while Windows NT4 service pack 6a uses
 *	 NTFS 1.2. I haven't personally seen other values yet.
 */
struct volume_information {
	__le64 reserved;		/* Not used (yet?). */
	u8 major_ver;		/* Major version of the ntfs format. */
	u8 minor_ver;		/* Minor version of the ntfs format. */
	__le16 flags;		/* Bit array of VOLUME_* flags. */
} __packed;

/*
 * Index header flags (8-bit).
 */
enum {
	/*
	 * When index header is in an index root attribute:
	 */
	SMALL_INDEX = 0, /*
			  * The index is small enough to fit inside the index
			  * root attribute and there is no index allocation
			  * attribute present.
			  */
	LARGE_INDEX = 1, /*
			  * The index is too large to fit in the index root
			  * attribute and/or an index allocation attribute is
			  * present.
			  */
	/*
	 * When index header is in an index block, i.e. is part of index
	 * allocation attribute:
	 */
	LEAF_NODE  = 0, /*
			 * This is a leaf node, i.e. there are no more nodes
			 * branching off it.
			 */
	INDEX_NODE = 1, /*
			 * This node indexes other nodes, i.e. it is not a leaf
			 * node.
			 */
	NODE_MASK  = 1, /* Mask for accessing the *_NODE bits. */
} __packed;

/*
 * This is the header for indexes, describing the INDEX_ENTRY records, which
 * follow the index_header. Together the index header and the index entries
 * make up a complete index.
 *
 * IMPORTANT NOTE: The offset, length and size structure members are counted
 * relative to the start of the index header structure and not relative to the
 * start of the index root or index allocation structures themselves.
 */
struct index_header {
	__le32 entries_offset;		/*
					 * Byte offset to first INDEX_ENTRY
					 * aligned to 8-byte boundary.
					 */
	__le32 index_length;		/*
					 * Data size of the index in bytes,
					 * i.e. bytes used from allocated
					 * size, aligned to 8-byte boundary.
					 */
	__le32 allocated_size;		/*
					 * Byte size of this index (block),
					 * multiple of 8 bytes.
					 */
	/*
	 * NOTE: For the index root attribute, the above two numbers are always
	 * equal, as the attribute is resident and it is resized as needed. In
	 * the case of the index allocation attribute the attribute is not
	 * resident and hence the allocated_size is a fixed value and must
	 * equal the index_block_size specified by the INDEX_ROOT attribute
	 * corresponding to the INDEX_ALLOCATION attribute this INDEX_BLOCK
	 * belongs to.
	 */
	u8 flags;			/* Bit field of INDEX_HEADER_FLAGS. */
	u8 reserved[3];			/* Reserved/align to 8-byte boundary. */
} __packed;

/*
 * Attribute: Index root (0x90).
 *
 * NOTE: Always resident.
 *
 * This is followed by a sequence of index entries (INDEX_ENTRY structures)
 * as described by the index header.
 *
 * When a directory is small enough to fit inside the index root then this
 * is the only attribute describing the directory. When the directory is too
 * large to fit in the index root, on the other hand, two additional attributes
 * are present: an index allocation attribute, containing sub-nodes of the B+
 * directory tree (see below), and a bitmap attribute, describing which virtual
 * cluster numbers (vcns) in the index allocation attribute are in use by an
 * index block.
 *
 * NOTE: The root directory (FILE_root) contains an entry for itself. Other
 * directories do not contain entries for themselves, though.
 */
struct index_root {
	__le32 type;			/*
					 * Type of the indexed attribute. Is
					 * $FILE_NAME for directories, zero
					 * for view indexes. No other values
					 * allowed.
					 */
	__le32 collation_rule;		/*
					 * Collation rule used to sort the index
					 * entries. If type is $FILE_NAME, this
					 * must be COLLATION_FILE_NAME.
					 */
	__le32 index_block_size;	/*
					 * Size of each index block in bytes (in
					 * the index allocation attribute).
					 */
	u8 clusters_per_index_block;	/*
					 * Cluster size of each index block (in
					 * the index allocation attribute), when
					 * an index block is >= than a cluster,
					 * otherwise this will be the log of
					 * the size (like how the encoding of
					 * the mft record size and the index
					 * record size found in the boot sector
					 * work). Has to be a power of 2.
					 */
	u8 reserved[3];			/* Reserved/align to 8-byte boundary. */
	struct index_header index;	/* Index header describing the following index entries. */
} __packed;

/*
 * Attribute: Index allocation (0xa0).
 *
 * NOTE: Always non-resident (doesn't make sense to be resident anyway!).
 *
 * This is an array of index blocks. Each index block starts with an
 * index_block structure containing an index header, followed by a sequence of
 * index entries (INDEX_ENTRY structures), as described by the struct index_header.
 */
struct index_block {
	__le32 magic;		/* Magic is "INDX". */
	__le16 usa_ofs;		/* See ntfs_record struct definition. */
	__le16 usa_count;	/* See ntfs_record struct  definition. */

	__le64 lsn;		/*
				 * LogFile sequence number of the last
				 * modification of this index block.
				 */
	__le64 index_block_vcn;	/*
				 * Virtual cluster number of the index block.
				 * If the cluster_size on the volume is <= the
				 * index_block_size of the directory,
				 * index_block_vcn counts in units of clusters,
				 * and in units of sectors otherwise.
				 */
	struct index_header index;	/* Describes the following index entries. */
/*
 * When creating the index block, we place the update sequence array at this
 * offset, i.e. before we start with the index entries. This also makes sense,
 * otherwise we could run into problems with the update sequence array
 * containing in itself the last two bytes of a sector which would mean that
 * multi sector transfer protection wouldn't work. As you can't protect data
 * by overwriting it since you then can't get it back...
 * When reading use the data from the ntfs record header.
 */
} __packed;

static_assert(sizeof(struct index_block) == 40);

/*
 * The system file FILE_Extend/$Reparse contains an index named $R listing
 * all reparse points on the volume. The index entry keys are as defined
 * below. Note, that there is no index data associated with the index entries.
 *
 * The index entries are sorted by the index key file_id. The collation rule is
 * COLLATION_NTOFS_ULONGS.
 */
struct reparse_index_key {
	__le32 reparse_tag;	/* Reparse point type (inc. flags). */
	__le64 file_id;		/*
				 * Mft record of the file containing
				 * the reparse point attribute.
				 */
} __packed;

/*
 * Quota flags (32-bit).
 *
 * The user quota flags.  Names explain meaning.
 */
enum {
	QUOTA_FLAG_DEFAULT_LIMITS	= cpu_to_le32(0x00000001),
	QUOTA_FLAG_LIMIT_REACHED	= cpu_to_le32(0x00000002),
	QUOTA_FLAG_ID_DELETED		= cpu_to_le32(0x00000004),

	QUOTA_FLAG_USER_MASK		= cpu_to_le32(0x00000007),
	/* This is a bit mask for the user quota flags. */

	/*
	 * These flags are only present in the quota defaults index entry, i.e.
	 * in the entry where owner_id = QUOTA_DEFAULTS_ID.
	 */
	QUOTA_FLAG_TRACKING_ENABLED	= cpu_to_le32(0x00000010),
	QUOTA_FLAG_ENFORCEMENT_ENABLED	= cpu_to_le32(0x00000020),
	QUOTA_FLAG_TRACKING_REQUESTED	= cpu_to_le32(0x00000040),
	QUOTA_FLAG_LOG_THRESHOLD	= cpu_to_le32(0x00000080),

	QUOTA_FLAG_LOG_LIMIT		= cpu_to_le32(0x00000100),
	QUOTA_FLAG_OUT_OF_DATE		= cpu_to_le32(0x00000200),
	QUOTA_FLAG_CORRUPT		= cpu_to_le32(0x00000400),
	QUOTA_FLAG_PENDING_DELETES	= cpu_to_le32(0x00000800),
};

/*
 * The system file FILE_Extend/$Quota contains two indexes $O and $Q. Quotas
 * are on a per volume and per user basis.
 *
 * The $Q index contains one entry for each existing user_id on the volume. The
 * index key is the user_id of the user/group owning this quota control entry,
 * i.e. the key is the owner_id. The user_id of the owner of a file, i.e. the
 * owner_id, is found in the standard information attribute. The collation rule
 * for $Q is COLLATION_NTOFS_ULONG.
 *
 * The $O index contains one entry for each user/group who has been assigned
 * a quota on that volume. The index key holds the SID of the user_id the
 * entry belongs to, i.e. the owner_id. The collation rule for $O is
 * COLLATION_NTOFS_SID.
 *
 * The $O index entry data is the user_id of the user corresponding to the SID.
 * This user_id is used as an index into $Q to find the quota control entry
 * associated with the SID.
 *
 * The $Q index entry data is the quota control entry and is defined below.
 */
struct quota_control_entry {
	__le32 version;		/* Currently equals 2. */
	__le32 flags;		/* Flags describing this quota entry. */
	__le64 bytes_used;	/* How many bytes of the quota are in use. */
	__le64 change_time;	/* Last time this quota entry was changed. */
	__le64 threshold;	/* Soft quota (-1 if not limited). */
	__le64 limit;		/* Hard quota (-1 if not limited). */
	__le64 exceeded_time;	/* How long the soft quota has been exceeded. */
	struct ntfs_sid sid;	/*
				 * The SID of the user/object associated with
				 * this quota entry.  Equals zero for the quota
				 * defaults entry (and in fact on a WinXP
				 * volume, it is not present at all).
				 */
} __packed;

/*
 * Predefined owner_id values (32-bit).
 */
enum {
	QUOTA_INVALID_ID	= cpu_to_le32(0x00000000),
	QUOTA_DEFAULTS_ID	= cpu_to_le32(0x00000001),
	QUOTA_FIRST_USER_ID	= cpu_to_le32(0x00000100),
};

/*
 * Current constants for quota control entries.
 */
enum {
	/* Current version. */
	QUOTA_VERSION	= 2,
};

/*
 * Index entry flags (16-bit).
 */
enum {
	INDEX_ENTRY_NODE = cpu_to_le16(1), /*
					    * This entry contains a sub-node,
					    * i.e. a reference to an index block
					    * in form of a virtual cluster number
					    * (see below).
					    */
	INDEX_ENTRY_END  = cpu_to_le16(2), /*
					    * This signifies the last entry in an
					    * index block.  The index entry does not
					    * represent a file but it can point
					    * to a sub-node.
					    */

	INDEX_ENTRY_SPACE_FILLER = cpu_to_le16(0xffff), /* gcc: Force enum bit width to 16-bit. */
} __packed;

/*
 * This the index entry header (see below).
 */
struct index_entry_header {
/*  0*/	union {
		struct { /* Only valid when INDEX_ENTRY_END is not set. */
			__le64 indexed_file;	/*
						 * The mft reference of the file
						 * described by this index entry.
						 * Used for directory indexes.
						 */
		} __packed dir;
		struct {
			/* Used for views/indexes to find the entry's data. */
			__le16 data_offset;	/*
						 * Data byte offset from this
						 * INDEX_ENTRY. Follows the index key.
						 */
			__le16 data_length;	/* Data length in bytes. */
			__le32 reservedV;		/* Reserved (zero). */
		} __packed vi;
	} __packed data;
	__le16 length;		/* Byte size of this index entry, multiple of 8-bytes. */
	__le16 key_length;	/*
				 * Byte size of the key value, which is in the index entry.
				 * It follows field reserved. Not multiple of 8-bytes.
				 */
	__le16 flags; /* Bit field of INDEX_ENTRY_* flags. */
	__le16 reserved;		 /* Reserved/align to 8-byte boundary. */
} __packed;

static_assert(sizeof(struct index_entry_header) == 16);

/*
 * This is an index entry. A sequence of such entries follows each index_header
 * structure. Together they make up a complete index. The index follows either
 * an index root attribute or an index allocation attribute.
 *
 * NOTE: Before NTFS 3.0 only filename attributes were indexed.
 */
struct index_entry {
	union {
		struct { /* Only valid when INDEX_ENTRY_END is not set. */
			__le64 indexed_file;	/*
						 * The mft reference of the file
						 * described by this index entry.
						 * Used for directory indexes.
						 */
		} __packed dir;
		struct { /* Used for views/indexes to find the entry's data. */
			__le16 data_offset;	/*
						 * Data byte offset from this INDEX_ENTRY.
						 * Follows the index key.
						 */
			__le16 data_length;	/* Data length in bytes. */
			__le32 reservedV;		/* Reserved (zero). */
		} __packed vi;
	} __packed data;
	__le16 length;		 /* Byte size of this index entry, multiple of 8-bytes. */
	__le16 key_length;	 /*
				  * Byte size of the key value, which is in the index entry.
				  * It follows field reserved. Not multiple of 8-bytes.
				  */
	__le16 flags;		/* Bit field of INDEX_ENTRY_* flags. */
	__le16 reserved;		 /* Reserved/align to 8-byte boundary. */

	union {
		/*
		 * The key of the indexed attribute. NOTE: Only present
		 * if INDEX_ENTRY_END bit in flags is not set. NOTE: On
		 * NTFS versions before 3.0 the only valid key is the
		 * struct file_name_attr. On NTFS 3.0+ the following
		 * additional index keys are defined:
		 */
		struct file_name_attr file_name;	/* $I30 index in directories. */
		struct sii_index_key sii;	/* $SII index in $Secure. */
		struct sdh_index_key sdh;	/* $SDH index in $Secure. */
		struct guid object_id;	/*
					 * $O index in FILE_Extend/$ObjId: The object_id
					 * of the mft record found in the data part of
					 * the index.
					 */
		struct reparse_index_key reparse;	/* $R index in FILE_Extend/$Reparse. */
		struct ntfs_sid sid;	/*
					 * $O index in FILE_Extend/$Quota:
					 * SID of the owner of the user_id.
					 */
		__le32 owner_id;	/*
					 * $Q index in FILE_Extend/$Quota:
					 * user_id of the owner of the quota
					 * control entry in the data part of
					 * the index.
					 */
	} __packed key;
	/*
	 * The (optional) index data is inserted here when creating.
	 * __le64 vcn;	   If INDEX_ENTRY_NODE bit in flags is set, the last
	 *		   eight bytes of this index entry contain the virtual
	 *		   cluster number of the index block that holds the
	 *		   entries immediately preceding the current entry (the
	 *		   vcn references the corresponding cluster in the data
	 *		   of the non-resident index allocation attribute). If
	 *		   the key_length is zero, then the vcn immediately
	 *		   follows the INDEX_ENTRY_HEADER. Regardless of
	 *		   key_length, the address of the 8-byte boundary
	 *		   aligned vcn of INDEX_ENTRY{_HEADER} *ie is given by
	 *		   (char*)ie + le16_to_cpu(ie*)->length) - sizeof(VCN),
	 *		   where sizeof(VCN) can be hardcoded as 8 if wanted.
	 */
} __packed;

/*
 * The reparse point tag defines the type of the reparse point. It also
 * includes several flags, which further describe the reparse point.
 *
 * The reparse point tag is an unsigned 32-bit value divided in three parts:
 *
 * 1. The least significant 16 bits (i.e. bits 0 to 15) specify the type of
 *    the reparse point.
 * 2. The 12 bits after this (i.e. bits 16 to 27) are reserved for future use.
 * 3. The most significant four bits are flags describing the reparse point.
 *    They are defined as follows:
 *	bit 28: Directory bit. If set, the directory is not a surrogate
 *		and can be used the usual way.
 *	bit 29: Name surrogate bit. If set, the filename is an alias for
 *		another object in the system.
 *	bit 30: High-latency bit. If set, accessing the first byte of data will
 *		be slow. (E.g. the data is stored on a tape drive.)
 *	bit 31: Microsoft bit. If set, the tag is owned by Microsoft. User
 *		defined tags have to use zero here.
 * 4. Moreover, on Windows 10 :
 *	Some flags may be used in bits 12 to 15 to further describe the
 *	reparse point.
 */
enum {
	IO_REPARSE_TAG_DIRECTORY	= cpu_to_le32(0x10000000),
	IO_REPARSE_TAG_IS_ALIAS		= cpu_to_le32(0x20000000),
	IO_REPARSE_TAG_IS_HIGH_LATENCY	= cpu_to_le32(0x40000000),
	IO_REPARSE_TAG_IS_MICROSOFT	= cpu_to_le32(0x80000000),

	IO_REPARSE_TAG_RESERVED_ZERO	= cpu_to_le32(0x00000000),
	IO_REPARSE_TAG_RESERVED_ONE	= cpu_to_le32(0x00000001),
	IO_REPARSE_TAG_RESERVED_RANGE	= cpu_to_le32(0x00000001),

	IO_REPARSE_TAG_CSV		= cpu_to_le32(0x80000009),
	IO_REPARSE_TAG_DEDUP		= cpu_to_le32(0x80000013),
	IO_REPARSE_TAG_DFS		= cpu_to_le32(0x8000000A),
	IO_REPARSE_TAG_DFSR		= cpu_to_le32(0x80000012),
	IO_REPARSE_TAG_HSM		= cpu_to_le32(0xC0000004),
	IO_REPARSE_TAG_HSM2		= cpu_to_le32(0x80000006),
	IO_REPARSE_TAG_MOUNT_POINT	= cpu_to_le32(0xA0000003),
	IO_REPARSE_TAG_NFS		= cpu_to_le32(0x80000014),
	IO_REPARSE_TAG_SIS		= cpu_to_le32(0x80000007),
	IO_REPARSE_TAG_SYMLINK		= cpu_to_le32(0xA000000C),
	IO_REPARSE_TAG_WIM		= cpu_to_le32(0x80000008),
	IO_REPARSE_TAG_DFM		= cpu_to_le32(0x80000016),
	IO_REPARSE_TAG_WOF		= cpu_to_le32(0x80000017),
	IO_REPARSE_TAG_WCI		= cpu_to_le32(0x80000018),
	IO_REPARSE_TAG_CLOUD		= cpu_to_le32(0x9000001A),
	IO_REPARSE_TAG_APPEXECLINK	= cpu_to_le32(0x8000001B),
	IO_REPARSE_TAG_GVFS		= cpu_to_le32(0x9000001C),
	IO_REPARSE_TAG_LX_SYMLINK	= cpu_to_le32(0xA000001D),
	IO_REPARSE_TAG_AF_UNIX		= cpu_to_le32(0x80000023),
	IO_REPARSE_TAG_LX_FIFO		= cpu_to_le32(0x80000024),
	IO_REPARSE_TAG_LX_CHR		= cpu_to_le32(0x80000025),
	IO_REPARSE_TAG_LX_BLK		= cpu_to_le32(0x80000026),

	IO_REPARSE_TAG_VALID_VALUES	= cpu_to_le32(0xf000ffff),
	IO_REPARSE_PLUGIN_SELECT	= cpu_to_le32(0xffff0fff),
};

/*
 * Attribute: Reparse point (0xc0).
 *
 * NOTE: Can be resident or non-resident.
 */
struct reparse_point {
	__le32 reparse_tag;		/* Reparse point type (inc. flags). */
	__le16 reparse_data_length;	/* Byte size of reparse data. */
	__le16 reserved;			/* Align to 8-byte boundary. */
	u8 reparse_data[0];		/* Meaning depends on reparse_tag. */
} __packed;

/*
 * Attribute: Extended attribute (EA) information (0xd0).
 *
 * NOTE: Always resident. (Is this true???)
 */
struct ea_information {
	__le16 ea_length;		/* Byte size of the packed extended attributes. */
	__le16 need_ea_count;	/*
				 * The number of extended attributes which have
				 * the NEED_EA bit set.
				 */
	__le32 ea_query_length;	/*
				 * Byte size of the buffer required to query
				 * the extended attributes when calling
				 * ZwQueryEaFile() in Windows NT/2k. I.e.
				 * the byte size of the unpacked extended attributes.
				 */
} __packed;

/*
 * Extended attribute flags (8-bit).
 */
enum {
	NEED_EA	= 0x80		/*
				 * If set the file to which the EA belongs
				 * cannot be interpreted without understanding
				 * the associates extended attributes.
				 */
} __packed;

/*
 * Attribute: Extended attribute (EA) (0xe0).
 *
 * NOTE: Can be resident or non-resident.
 *
 * Like the attribute list and the index buffer list, the EA attribute value is
 * a sequence of EA_ATTR variable length records.
 */
struct ea_attr {
	__le32 next_entry_offset;	/* Offset to the next EA_ATTR. */
	u8 flags;		/* Flags describing the EA. */
	u8 ea_name_length;	/*
				 * Length of the name of the EA in bytes
				 * excluding the '\0' byte terminator.
				 */
	__le16 ea_value_length;	/* Byte size of the EA's value. */
	u8 ea_name[];		/*
				 * Name of the EA.  Note this is ASCII, not
				 * Unicode and it is zero terminated.
				 */
	/* u8 ea_value[]; */	/* The value of the EA.  Immediately follows the name. */
} __packed;

#endif /* _LINUX_NTFS_LAYOUT_H */
