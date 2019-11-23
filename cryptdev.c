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
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)str, strlen(str), hash);
        for(unsigned i = 0; i < sizeof(hash); i++) {
                sprintf(out, "%02x", hash[i]);
                out += 2;
        }
	*out = '\0';
	explicit_bzero(hash, sizeof(hash));
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

static void read_pass(char *buf, size_t size)
{
	struct termios newtios, oldtios;
	tcgetattr(0, &oldtios);
	newtios = oldtios;
	newtios.c_lflag &= ~(ECHO | ISIG);
	tcsetattr(0, TCSAFLUSH, &newtios);

	write(1, "Password: ", 10);
	ssize_t sz = read(0, buf, size-1);
	if (sz > 0) {
		if (buf[sz-1] == '\n')
			--sz;
		buf[sz] = '\0';
	} else
		buf[0] = '\0';
	write(1, "\n", 1);

	tcsetattr(0, TCSAFLUSH, &oldtios);
}

static void cmd_open(int argc, char** argv)
{
	uint64_t size = 0;
	char dev[256], passwd[256], hash[65];
	const char* path = argv[1];
	const char* name = argv[2];
	struct dm_crypt dm;

	if (argc < 3)
		errx(1, "Usage: %s DEV NAME", argv[0]);

	get_blk_size(path, &size);

	dm_init(&dm, name);
	if (ioctl(control_fd, DM_DEV_CREATE, &dm) == -1)
		err(1, "ioctl(DM_DEV_CREATE)");

	dm_init(&dm, name);
	dm.io.target_count = 1;
	dm.spec.sector_start = 0;
	dm.spec.length = size;
	strncpy(dm.spec.target_type, "crypt", sizeof(dm.spec.target_type) - 1);

	read_pass(passwd, sizeof(passwd));
	hash_pass(passwd, hash);

	snprintf(dm.param, sizeof(dm.param), "aes-xts-plain64 %s 0 %s 0", hash, path);
	if (ioctl(control_fd, DM_TABLE_LOAD, &dm) < 0)
		err(1, "ioctl(DM_TABLE_LOAD)");

	dm_init(&dm, name);
	if (ioctl(control_fd, DM_DEV_SUSPEND, &dm))
		err(1, "ioctl(DM_DEV_SUSPEND)");

	/* Create device in /dev/mapper/ */
	snprintf(dev, sizeof(dev) - 1, "/dev/mapper/%s", name);
	mknod(dev, S_IFBLK | 0600, dm.io.dev);
}

static void cmd_close(int argc, char** argv)
{
	struct dm_crypt dm;
	char path[256];
	const char *name = argv[1];

	if (argc < 2)
		errx(1, "Usage: %s NAME", argv[0]);

	dm_init(&dm, name);
	if (ioctl(control_fd, DM_DEV_REMOVE, &dm))
		err(1, "ioctl(DM_DEV_REMOVE)");

	snprintf(path, sizeof(path) - 1, "/dev/mapper/%s", name);
	unlink(path);
}

int main(int argc, char** argv)
{
	if (argc < 2)
		errx(1, "usage: %s CMD [ARG]...", argv[0]);

        if ((control_fd = open("/dev/mapper/control", O_RDWR)) < 0)
		err(1, "open /dev/mapper/control");

	--argc, ++argv;
	if (!strcmp(argv[0], "open"))
		cmd_open(argc, argv);
	else if(!strcmp(argv[0], "close"))
		cmd_close(argc, argv);
	else
		errx(1, "unknown command: %s", argv[0]);
}
