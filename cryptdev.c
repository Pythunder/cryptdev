#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <openssl/sha.h>
#include <linux/fs.h>
#include <linux/dm-ioctl.h>

struct dm_crypt {
	struct dm_ioctl io;
	struct dm_target_spec spec;
	char param[1024];
};

static int control_fd;

static void hash_pass(const char *str, char *out)
{
	unsigned int i, j, n;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	SHA256((unsigned char*)str, strlen(str), hash);
	for(i = 0, j = 0; i < sizeof(hash); i++) {
		n = (hash[i] & 0xf0) >> 4;
		out[j++] = n + (n > 9 ? 'a' - 10 : '0');
		n = (hash[i] & 0x0f);
		out[j++] = n + (n > 9 ? 'a' - 10 : '0');
	}
	out[j] = '\0';
	explicit_bzero(hash, sizeof(hash));
}

static void read_pass(char *buf, size_t size)
{
	ssize_t sz;
	struct termios newtios, oldtios;

	tcgetattr(0, &oldtios);
	newtios = oldtios;
	newtios.c_lflag &= ~(ECHO | ISIG);

	tcsetattr(0, TCSAFLUSH, &newtios);
	write(1, "Password: ", 10);
	sz = read(0, buf, size - 1);
	write(1, "\n", 1);
	tcsetattr(0, TCSAFLUSH, &oldtios);

	if (sz > 0) {
		if (buf[sz-1] == '\n')
			--sz;
		buf[sz] = '\0';
	} else
		exit(0);
}

static void dm_init(struct dm_crypt *dm, const char *dm_name)
{
	memset(dm, 0, sizeof(*dm));
	dm->io.data_size = sizeof(*dm);
	dm->io.data_start = sizeof(dm->io);
	dm->io.version[0] = DM_VERSION_MAJOR;
	dm->io.version[1] = DM_VERSION_MINOR;
	dm->io.version[2] = DM_VERSION_PATCHLEVEL;
	strncpy(dm->io.name, dm_name, sizeof(dm->io.name) - 1);
}

static void get_blk_size(const char* path, uint64_t *size)
{
	int fd;

	if ((fd = open(path, O_RDONLY)) < 0)
		err(1, "open %s", path);

	if (ioctl(fd, BLKGETSIZE, size) < 0)
		err(1, "ioctl(BLKGETSIZE)");
	close(fd);
}

static void dm_open(const char *path, const char *name)
{
	uint64_t size;
	char buf[256];
	struct dm_crypt dm;

	get_blk_size(path, &size);
	read_pass(buf, sizeof(buf));
	hash_pass(buf, buf);

	dm_init(&dm, name);
	if (ioctl(control_fd, DM_DEV_CREATE, &dm) < 0)
		err(1, "ioctl(DM_DEV_CREATE)");

	dm_init(&dm, name);
	dm.io.target_count = 1;
	dm.spec.length = size;
	snprintf(dm.spec.target_type, sizeof(dm.spec.target_type), "crypt");
	snprintf(dm.param, sizeof(dm.param), "aes-xts-plain64 %s 0 %s 0", buf, path);

	if (ioctl(control_fd, DM_TABLE_LOAD, &dm) < 0)
		err(1, "ioctl(DM_TABLE_LOAD)");

	dm_init(&dm, name);
	if (ioctl(control_fd, DM_DEV_SUSPEND, &dm) < 0)
		err(1, "ioctl(DM_DEV_SUSPEND)");

	snprintf(buf, sizeof(buf), "/dev/mapper/%s", name);
	mknod(buf, S_IFBLK | 0600, dm.io.dev);
}

static void dm_close(const char *name)
{
	char buf[256];
	struct dm_crypt dm;

	dm_init(&dm, name);
	if (ioctl(control_fd, DM_DEV_REMOVE, &dm) < 0)
		err(1, "ioctl(DM_DEV_REMOVE)");

	snprintf(buf, sizeof(buf), "/dev/mapper/%s", name);
	unlink(buf);
}

void usage(void)
{
	extern char *__progname;
	fprintf(stderr, "Usage: %s <action> <action-specific>\n\n"
			"<action> is one of:\n"
			"\topen <device> <name>\n"
			"\tclose <name>\n", __progname);
	exit(1);
}

int main(int argc, char** argv)
{
        if ((control_fd = open("/dev/mapper/control", O_RDWR)) < 0)
		err(1, "open /dev/mapper/control");

	if      (argc == 4 && !strcmp(argv[1], "open"))
		dm_open(argv[2], argv[3]);
	else if (argc == 3 && !strcmp(argv[1], "close"))
		dm_close(argv[2]);
	else
		usage();
}
