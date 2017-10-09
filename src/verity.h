#ifndef __MOUNT_VERITY_H
#define __MOUNT_VERITY_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mntent.h>
#include <linux/dm-ioctl.h>
//#include <openssl/rsa.h>
//#include "libbb.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VERITY_PROTOCOL_VERSION 2

#define VERITY_DISABLED     -2
#define VERITY_FAIL         -1
#define VERITY_SUCCESS       0

#define MTD_READ_PAGE_SIZE                2048
#define MTD_READ_BUFFER_SIZE            MTD_READ_PAGE_SIZE

// Magic number at start of verity metadata
#define VERITY_METADATA_MAGIC_NUMBER 0xb001b001
#define VERITY_METADATA_SIZE         (32*1024)

#define DM_BUF_SIZE 4096

#define DEVICE_MAPPER_NAME    "/dev/mapper/control"

#define MTD_PROC_FILENAME   "/proc/mtd"

#define UBI_VOLUME_NAMES_FILENAME   "/var/run/ubi_volnames"
#define MAX_PRINT_BUF_LEN 512
#define MY_DI(fmt, args...) ({char str_cmd[MAX_PRINT_BUF_LEN]={0,};char str_cmd1[MAX_PRINT_BUF_LEN]={0,}; snprintf(str_cmd1,MAX_PRINT_BUF_LEN,fmt,##args); strncpy(str_cmd,"echo \"",MAX_PRINT_BUF_LEN); strncat(str_cmd,str_cmd1,MAX_PRINT_BUF_LEN); strncat(str_cmd,"\" > /dev/kmsg",MAX_PRINT_BUF_LEN); system(str_cmd);})
#define DI MY_DI
#define DE MY_DI

// Verity modes
enum verity_mode {
    VERITY_MODE_EIO = 0,
    VERITY_MODE_LOGGING = 1,
    VERITY_MODE_RESTART = 2,
    VERITY_MODE_LAST = VERITY_MODE_RESTART,
    VERITY_MODE_DEFAULT = VERITY_MODE_RESTART
};

#define CA_CERT_HASH_PATH   	"/etc/ca.cer.bin.hash"
#define QFP_FUSE_DRIVER_NAME   "/dev/qfpfuse"
#define USE_TELIT_KEY          0
#define USE_CUSTOMER_KEY       1
#define TELIT_KEY_FIRST_ROW    182
#define TELIT_KEY_LAST_ROW     186
#define CUSTOMER_KEY_FIRST_ROW	119
#define CUSTOMER_KEY_LAST_ROW  123
#define TELIT_PROD_ID_ROW	43
#define TELIT_PROD_ID_ROWS	1
#define TELIT_PROD_ID_MASK	0x00000000FFFF0000
#define CUSTOMER_PROD_ID_ROW	124
#define CUSTOMER_PROD_ID_ROWS	2
#define CUSTOMER_PROD_ID_MASK1	0x00FFFFFFFFFFFFFF
#define CUSTOMER_PROD_ID_MASK2	0x00000000FF000000

#define QFP_FUSE_IOC_MAGIC   	0x92
#define QFP_FUSE_IOC_WRITE     _IO(QFP_FUSE_IOC_MAGIC, 1)
#define QFP_FUSE_IOC_READ      _IO(QFP_FUSE_IOC_MAGIC, 2)

#define CA_CERT_HASH_EFUSE_ROWS 		5
#define EFUSE_BYTES_IN_ROW 			8

#define RSANUMBYTES 256           /* 2048 bit key length */
#define RSANUMWORDS (RSANUMBYTES / sizeof(uint32_t))
#define SHA256_DIGEST_SIZE      32

typedef struct qfp_fuse {
	uint32_t row_num;
	uint32_t rows;
	uint64_t *data;
} qfe_fuse_req;

/*NOTE! the size of verity_metadata_header structure shall be less then MTD_READ_BUFFER_SIZE
  otherwise read_verity_metadata() should be modified accordingly
*/
#pragma pack(push, 1)
typedef struct metadata_hdr {
	uint32_t magic;
	uint32_t version;
	uint32_t key_index;
	uint32_t device_size;
	uint32_t volume_name_len;
	uint32_t verity_data_size;
	uint32_t dm_table_size;
	uint32_t ca_cert_size;
	uint32_t attest_ca_cert_size;
	uint32_t attest_cert_size;
} verity_metadata_header;
#pragma pack(pop)

/*
 * The entries must be kept in the same order as they were seen in the fstab.
 * Unless explicitly requested, a lookup on mount point should always
 * return the 1st one.
 */

//int mount_setup_verity(struct mntent *fstab);

#ifdef __cplusplus
}
#endif

#endif /* __MOUNT_VERITY_H */
