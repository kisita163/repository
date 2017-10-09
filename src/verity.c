/*
 ============================================================================
 Name        : mount.c
 Author      : Hugues
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mntent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>

#include "verity.h"

static int mount_setup_verity(char * volume , char * volume_metadata);
static int read_certificate(int cert_size, char **cert, char *read_buf, char **read_buf_ptr, int read_buf_size, int device_fd);
static int read_verity_metadata(char *block_device,
                                char *verity_device,
                                char **signature,
                                char **table,
                                int  *key_index,
                                int  *device_size,
                                char **ca_cert,
                                char **attest_ca_cert,
                                char **attest_cert,
                                int  *ca_cert_length,
                                int  *attest_ca_cert_length,
                                int  *attest_cert_length,
                                char **metadata,
                                int  *metadata_length);
static void   print_buffer(char * buffer , int size);
static int    create_verity_device(struct dm_ioctl *io, char *name, int fd);
static void   verity_ioctl_init(struct dm_ioctl *io, char *name, unsigned flags);
static size_t lv_strlcpy(char *dest, const char *src, size_t size);

int main(int argc, char **argv) {
    //TODO you need to check parameters here
    printf("Entered arguments are  : %s and %s\n",argv[0],argv[1]);

    char * volume = argv[1]; //  File system to be mounted
    char * verity = argv[2];    //  File system containing verity stuff

    mount_setup_verity(volume,verity);

	return EXIT_SUCCESS;
}

static int mount_setup_verity(char * volume , char * volume_metadata)
{
    int retval                         = VERITY_FAIL;
    int fd                             = -1;
    int mode                           = VERITY_MODE_EIO;
    int res                            = 0;
    char *verity_blk_name              = NULL;
    char *verity_table                 = NULL;
    char *signature                    = NULL;
    char *metadata                     = NULL;
    int  metadata_len                  = 0;
    char *mount_point                  = NULL;
    int key_index                      = 0;
    int device_size                    = 0;
    char *ca_cert                      = NULL;
    char *attest_ca_cert               = NULL;
    char *attest_cert                  = NULL;
    int ca_cert_len                    = 0;
    int attest_ca_cert_len             = 0;
    int attest_cert_len                = 0;
    // TODO - FIX THIS - HOW TO ENABLE THIS? _Alignas(struct dm_ioctl) char buffer[DM_BUF_SIZE];
    char buffer[DM_BUF_SIZE];
    struct dm_ioctl *io = (struct dm_ioctl *) buffer;
    char *cert = NULL;
    int  cert_size = 0;


    printf("%d %s() Started.", __LINE__, __func__);
    if (NULL == volume)
    {
        printf("%d %s() volume is NULL", __LINE__, __func__);
        return retval;
    }

    // read the verity block at the end of the block device
    // send error code up the chain so we can detect attempts to disable verity

    res = read_verity_metadata(volume,       // Filesystem containing data to be mounted
                               volume_metadata,  // Filesystem containg verity stuff
                               &signature,
                               &verity_table,
                               &key_index,
                               &device_size,
                               &ca_cert,
                               &attest_ca_cert,
                               &attest_cert,
                               &ca_cert_len,
                               &attest_ca_cert_len,
                               &attest_cert_len,
                               &metadata,
                               &metadata_len);
    if (res < 0)
    {
        printf("%d %s() read_verity_metadata returned() res = %d. Jumping to goto out\n", __LINE__, __func__, res);
        goto out;
    }

    // get the device mapper fd
    fd = open(DEVICE_MAPPER_NAME, O_RDWR);
    if(fd < 0)
    {
        printf("%d %s() Error opening device mapper (%d %s)\n", __LINE__, __func__, errno, strerror(errno));
        goto out;
    }

    // create the device
    res = create_verity_device(io,"/home/kisita/verity_test", fd);
    if(res < 0)
    {
        printf("%d %s() Couldn't create verity device! returned res = %d.\n", __LINE__, __func__, res);
        goto out;
    }


    out:
    printf("%d %s() ######################### retval = %d.\n", __LINE__, __func__, retval);
    return retval;
}



static int read_verity_metadata(char *block_device,
                                char *verity_device,
                                char **signature,
                                char **table,
                                int  *key_index,
                                int  *device_size,
                                char **ca_cert,
                                char **attest_ca_cert,
                                char **attest_cert,
                                int  *ca_cert_length,
                                int  *attest_ca_cert_length,
                                int  *attest_cert_length,
                                char **metadata,
                                int  *metadata_length)
{
    int  device_fd                       = -1;
    int  retval                          = VERITY_FAIL;
    char read_buf[MTD_READ_BUFFER_SIZE]  = {0x00};
    char *read_buf_ptr                   = NULL;
    int  res                             = 0;

    verity_metadata_header metadata_hdr;

    if (NULL == block_device)
    {
       printf("%d %s() Error: Bad argument", __LINE__, __func__);
       goto out;
    }

    *signature             = NULL;
    *table                 = NULL;
    *ca_cert               = NULL;
    *attest_ca_cert        = NULL;
    *attest_cert           = NULL;
    *ca_cert_length        = 0;
    *attest_ca_cert_length = 0;
    *attest_cert_length    = 0;
    *metadata_length       = 0;
    *metadata              = NULL;

    printf("Start reading metadata from %s\n",verity_device);

    // read my /dev/loop1 device here

    device_fd = open(verity_device, O_RDONLY  | O_CLOEXEC);
    if(device_fd < 0)
    {
    	printf("%d %s() Error: Could not open block_printfvice %s (%s).", __LINE__, __func__,verity_device, strerror(errno));
    	 goto out;
    }

    // reading one page into local buffer
    // now it supposed to contain
    // MAGIC_NUMBER  PROTOCOL_VERSION  KEY_INDEX DEVICE_SIZE DATA_DEVICE_NAME_LEN VOLUME NAME LEN VERITY_DATA_SIZE
    // VERITY_TABLE_SIZE CA_CERT_SIZE ATTEST_CA_CERT_SIZE ATTEST_CERT_SIZE VERITY_TABLE DATA_DEVICE_NAME VOLUME NAME SIGNATURE

    memset(&(read_buf[0]), 0, MTD_READ_BUFFER_SIZE);
    res = read(device_fd, &read_buf[0], MTD_READ_BUFFER_SIZE);
    if (res != MTD_READ_BUFFER_SIZE)
    {
    	 printf("%d %s() Device read failed res = %d (%d, %s).", __LINE__, __func__, res, errno, strerror(errno));
    	 goto out;
    }

    if (sizeof(verity_metadata_header) > MTD_READ_BUFFER_SIZE)
    {
    	 printf("%d %s() size of verity_metadata_header(%d) is bigger then MTD_READ_BUFFER_SIZE(%d)", __LINE__, __func__,(int) sizeof(verity_metadata_header), MTD_READ_BUFFER_SIZE);
    	 goto out;
    }
    memcpy((void *)&metadata_hdr, (const void *)&read_buf[0], sizeof(verity_metadata_header));

    // check the magic number
    if (VERITY_METADATA_MAGIC_NUMBER != metadata_hdr.magic)
    {
    	 printf("%d %s() Error: Couldn't find verity metadata at offset %d! magic_number = %x", __LINE__, __func__, 0, metadata_hdr.magic);
    	 goto out;
    }

    // check the protocol version
    if (VERITY_PROTOCOL_VERSION != metadata_hdr.version)
    {
    	 printf("%d %s() Got unknown verity metadata protocol version %d!", __LINE__, __func__, metadata_hdr.version);
    	 goto out;
    }

    // get the key index
    *key_index = metadata_hdr.key_index;
    printf("%d %s() key_index = %d\n", __LINE__, __func__, *key_index);

    // get the device size
    *device_size = metadata_hdr.device_size;
    printf("%d %s() device_size = %d\n", __LINE__, __func__, *device_size);

    //get volume_name_len
    printf("%d %s() volume_name_len = %d\n", __LINE__, __func__,  metadata_hdr.volume_name_len);

    // get verity_data_size
    printf("%d %s() verity_data_size = 0x%X\n", __LINE__, __func__, metadata_hdr.verity_data_size);

    // get the size of the table
    printf("%d %s() table_length = %d\n", __LINE__, __func__, metadata_hdr.dm_table_size);

    // get the size of the ca_cert
    *ca_cert_length = metadata_hdr.ca_cert_size;
    printf("%d %s() ca_cert_length = %d\n", __LINE__, __func__, *ca_cert_length);

    // get the size of the attest_ca_cert
    *attest_ca_cert_length = metadata_hdr.attest_ca_cert_size;
    printf("%d %s() attest_ca_cert_length = %d\n", __LINE__, __func__, *attest_ca_cert_length);

    // get the size of the attest_cert
    *attest_cert_length = metadata_hdr.attest_cert_size;
    printf("%d %s() attest_cert_length = %d\n", __LINE__, __func__, *attest_cert_length);

    *table = calloc(metadata_hdr.dm_table_size + 1, sizeof(char));
    if (NULL == *table)
    {
    	 printf("%d %s() Couldn't allocate memory for verity table! table_length = %d\n", __LINE__, __func__, metadata_hdr.dm_table_size);
    	 goto out;
    }

    *signature = (char*) malloc(RSANUMBYTES);
    if (NULL == *signature)
    {
    	 printf("%d %s() Couldn't allocate memory for signature! signature size = %d\n", __LINE__, __func__, RSANUMBYTES);
    	 goto out;
    }

    // get the table + null terminator
    read_buf_ptr = &read_buf[0] + sizeof(verity_metadata_header);
    memcpy(*table, read_buf_ptr, metadata_hdr.dm_table_size);
    (*table)[metadata_hdr.dm_table_size] = '\0';

    // get the metadata
    read_buf_ptr += metadata_hdr.dm_table_size + metadata_hdr.volume_name_len;
    *metadata_length = read_buf_ptr - &read_buf[0];
    printf("%d %s() metadata_length = %d\n", __LINE__, __func__, *metadata_length);
    *metadata = (char *)malloc(*metadata_length);
    if (NULL == *metadata)
    {
    	 printf("%d %s() Couldn't allocate memory for metadata! metadata length = %d\n", __LINE__, __func__, *metadata_length);
    	 goto out;
    }
    memcpy(*metadata, &read_buf[0], *metadata_length);

    // get the signature
    memcpy(*signature, read_buf_ptr, RSANUMBYTES);

    // the certificates starts on the next page. read one page into local buffer
    memset(&(read_buf[0]), 0, MTD_READ_BUFFER_SIZE);
    res = read(device_fd, &read_buf[0], MTD_READ_BUFFER_SIZE);
    if (res != MTD_READ_BUFFER_SIZE)
    {
    	 printf("%d %s() Device read failed res = %d (%d, %s).\n", __LINE__, __func__, res, errno, strerror(errno));
    	 goto out;
    }
    read_buf_ptr = &read_buf[0];

    // get the CA cert
	if (*ca_cert_length > 0)
	{
		 if ((res = read_certificate(*ca_cert_length, ca_cert, &read_buf[0], &read_buf_ptr, MTD_READ_BUFFER_SIZE, device_fd)) < 0)
		 {
			 DE("%d %s() Read ca certificate failed res = %d\n", __LINE__, __func__, res);
			 goto out;
		 }
	}

	// get the attest CA cert
	if (*attest_ca_cert_length > 0)
	{
		 if ((res = read_certificate(*attest_ca_cert_length, attest_ca_cert, &read_buf[0], &read_buf_ptr, MTD_READ_BUFFER_SIZE, device_fd)) < 0)
		 {
			 printf("%d %s() Read attest ca certificate failed res = %d\n", __LINE__, __func__, res);
			 goto out;
		 }
	}

	// get the attest cert
	if (*attest_cert_length > 0)
	{
		 if ((res = read_certificate(*attest_cert_length, attest_cert, &read_buf[0], &read_buf_ptr, MTD_READ_BUFFER_SIZE, device_fd)) < 0)
		 {
			 printf("%d %s() Read attest certificate failed res = %d", __LINE__, __func__, res);
			 goto out;
		 }
	}

    retval = VERITY_SUCCESS;

out:

    if (-1 != device_fd)
    {
        close(device_fd);
    }

    printf("%d %s retval = %d\n", __LINE__, __func__, retval);
    return retval;
}


static int read_certificate(int cert_size, char **cert, char *read_buf, char **read_buf_ptr, int read_buf_size, int device_fd)
{
    int cert_bytes_lefs_to_copy = 0, bytes_left_in_read_buf_to_copy = 0, cert_bytes_to_copy = 0;
    char *cert_ptr = NULL;

    if ((NULL == cert) || (NULL == read_buf) || (NULL == read_buf_ptr) || (NULL == *read_buf_ptr) || (device_fd < 0) ||
        (*read_buf_ptr < read_buf) || (*read_buf_ptr >= (read_buf + read_buf_size)))
    {
        printf("%d %s() Error: Bad argument", __LINE__, __func__);
        return -1;
    }

    if (cert_size > 0)
    {
        *cert = (char*) malloc(cert_size);
        if (NULL == *cert)
        {
            printf("%d %s() Couldn't allocate memory for certificate!", __LINE__, __func__);
            return -1;
        }

        cert_ptr = *cert;
        cert_bytes_lefs_to_copy = cert_size;
        bytes_left_in_read_buf_to_copy = read_buf_size - (*read_buf_ptr - read_buf);
        while (cert_bytes_lefs_to_copy > 0)
        {
            if (bytes_left_in_read_buf_to_copy <= 0)
            {
                memset(read_buf, 0, read_buf_size);
                if (read(device_fd, read_buf, read_buf_size) != read_buf_size)
                {
                    printf("%d %s() Device read failed (%d, %s).", __LINE__, __func__, errno, strerror(errno));
                    free(*cert);
                *cert = NULL;
                    return -1;
                }
                //printf("Certificate is  : ");
                //print_buffer(read_buf,read_buf_size);
                *read_buf_ptr = read_buf;
                bytes_left_in_read_buf_to_copy = read_buf_size;
            }
            cert_bytes_to_copy = cert_bytes_lefs_to_copy <= bytes_left_in_read_buf_to_copy ? cert_bytes_lefs_to_copy : bytes_left_in_read_buf_to_copy;
            memcpy(cert_ptr, *read_buf_ptr, cert_bytes_to_copy);
            cert_ptr += cert_bytes_to_copy;
            *read_buf_ptr += cert_bytes_to_copy;
            cert_bytes_lefs_to_copy -= cert_bytes_to_copy;
            bytes_left_in_read_buf_to_copy -= cert_bytes_to_copy;
        }
    }
    //printf("Certificate is  : ");
    //print_buffer(read_buf,read_buf_size);
    return 0;
}

static int create_verity_device(struct dm_ioctl *io, char *name, int fd)
{
	printf("Creating the device with parameters : \n\t name  : %s\n\t fd = %d\n",name,fd);
    verity_ioctl_init(io, name, 1);
    if(0 != ioctl(fd, DM_DEV_CREATE, io))
    {
        printf("Error creating device mapping (%s)\n", strerror(errno));
        return -1;
    }

    return 0;
}

static void print_buffer(char * buffer , int size){
    int k = 0 ;
    for(k = 0 ; k < size ; k++){
        printf("%02x",buffer);
    }
    printf("\n");
}

static void verity_ioctl_init(struct dm_ioctl *io, char *name, unsigned flags)
{
    memset(io, 0, DM_BUF_SIZE);
    io->data_size = DM_BUF_SIZE;
    io->data_start = sizeof(struct dm_ioctl);
    io->version[0] = 4;
    io->version[1] = 0;
    io->version[2] = 0;
    io->flags = flags | DM_READONLY_FLAG;
    if (NULL != name)
    {
        lv_strlcpy(io->name, name, sizeof(io->name));
    }
}

/**
 * lv_strlcpy - Copy a C-string into a sized buffer
 * @dest: Where to copy the string to
 * @src: Where to copy the string from
 * @size: size of destination buffer
 *
 * Compatible with *BSD: the result is always a valid
 * NUL-terminated string that fits in the buffer (unless,
 * of course, the buffer size is zero). It does not pad
 * out the result like strncpy() does.
 */
static size_t lv_strlcpy(char *dest, const char *src, size_t size)
{
    size_t ret = strlen(src);

    if(size)
    {
        size_t len = (ret >= size) ? size - 1 : ret;
        memcpy(dest, src, len);
        dest[len] = '\0';
    }
    return ret;
}


