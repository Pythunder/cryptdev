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

#define ELEMS(arr) (sizeof(arr) / sizeof(arr[0]))
#define DM_CRYPT_BUF_SIZE 4096
#define MAX_PASS_LEN 128
#define DM_CRYPT_ALG "aes-xts-plain64"
#define DM_CONTROL_PATH "/dev/" DM_DIR "/" DM_CONTROL_NODE

#define KEYSIZE ((SHA256_DIGEST_LENGTH*2)+1) /* SHA sum in hex + NUL */

struct cmd_func {
	const char* name;
	void (*func)(int,char**);
};

static void cmd_open(int argc, char** argv);
static void cmd_close(int argc, char** argv);

static int control_fd = -1;
static const struct cmd_func cmd_list[] = {
        {"open", cmd_open},
        {"close", cmd_close},
};

static void
pass_to_masterkey(const char* str, size_t len, char* out)
{
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)str, len, hash);
        for(unsigned i = 0; i < sizeof(hash); i++) {
                sprintf(out, "%02x", hash[i]);
                out += 2;
        }
	*out = '\0';
	explicit_bzero(hash, sizeof(hash));
}

static void
ioctl_init(struct dm_ioctl* io, size_t size, const char* name)
{
	memset(io, 0, size);
	io->data_size = size;
	io->data_start = sizeof(*io);
	io->version[0] = DM_VERSION_MAJOR;
	io->version[1] = DM_VERSION_MINOR;
	io->version[2] = DM_VERSION_PATCHLEVEL;
	strncpy(io->name, name, sizeof(io->name)-1);
}

static int
get_blk_size(const char* path, __u64* size)
{
	int ret = 0;
	int fd = open(path, O_RDONLY);
	if (fd == -1)
		return -1;

	ret = ioctl(fd, BLKGETSIZE64, size);
	close(fd);

	return ret;
}

static int
read_pass(char* hash)
{
	struct termios newtios, oldtios;
	tcgetattr(0, &oldtios);
	newtios = oldtios;
	newtios.c_lflag &= ~(ECHO | ISIG);
	newtios.c_lflag |= ECHONL | ICANON;
	tcsetattr(0, TCSAFLUSH, &newtios);

	write(1, "Password: ", 10);
	char buf[MAX_PASS_LEN] = {0};
	ssize_t sz = read(0, buf, sizeof(buf));
	if (sz > 0) {
		if(buf[sz-1] == '\n')
			--sz;
		pass_to_masterkey(buf, sz, hash);
	}
	explicit_bzero(buf, sizeof(buf));

	tcsetattr(0, TCSAFLUSH, &oldtios);
	return sz;
}

static void
cmd_open(int argc, char** argv)
{
	if (argc < 3)
		errx(1, "Usage: %s DEV NAME", argv[0]);

	__u64 size = 0;
	const char* path = argv[1];
	const char* name = argv[2];
	char buf[DM_CRYPT_BUF_SIZE];
	struct dm_ioctl* io = (struct dm_ioctl *) buf;
	struct dm_target_spec* spec = (struct dm_target_spec*) &buf[sizeof(*io)];
	char* params = buf + sizeof(*io) + sizeof(*spec);

	if (get_blk_size(path, &size))
		err(1, "failed to get size of %s", path);
	size >>= 9; /* Number of 512 byte blocks */

	ioctl_init(io, sizeof(buf), name);
	if (ioctl(control_fd, DM_DEV_CREATE, io) == -1)
		err(1, "ioctl(DM_DEV_CREATE)");

	ioctl_init(io, sizeof(buf), name);
	io->target_count = 1;
	spec->sector_start = 0;
	spec->length = size;
	strcpy(spec->target_type, "crypt");

	char pass[KEYSIZE] = {0};
	if(read_pass(pass) == -1 || *pass == 0)
		exit(1);

	sprintf(params, DM_CRYPT_ALG " %s 0 %s 0", pass, path);
	int ret = ioctl(control_fd, DM_TABLE_LOAD, io);

	/* Destroy key */
	explicit_bzero(pass, sizeof(pass));
	explicit_bzero(params, sizeof(params));

	if (ret)
		err(1, "ioctl(DM_TABLE_LOAD)");

	ioctl_init(io, sizeof(buf), name);
	if (ioctl(control_fd, DM_DEV_SUSPEND, io))
		err(1, "ioctl(DM_DEV_SUSPEND)");

	/* Create device in /dev/mapper/ */
	char dev[256] = {0};
	snprintf(dev, sizeof(dev)-1, "/dev/" DM_DIR "/%s", name);
	mknod(dev, S_IFBLK | 0600, io->dev);
}

static void
cmd_close(int argc, char** argv)
{
	if (argc < 2)
		errx(1, "Usage: %s NAME", argv[0]);

        const char* name = argv[1];
        char buf[DM_CRYPT_BUF_SIZE];
        struct dm_ioctl* io = (struct dm_ioctl *)buf;

	ioctl_init(io, sizeof(buf), name);
	if (ioctl(control_fd, DM_DEV_REMOVE, io))
		err(1, "ioctl(DM_DEV_REMOVE)");


	char dev[256] = {0};
	snprintf(dev, sizeof(dev)-1, "/dev/" DM_DIR "/%s", name);
	unlink(dev);
}

int
main(int argc, char** argv)
{
	if (argc < 2)
		errx(1, "Usage: %s CMD [ARG]...", argv[0]);

	struct cmd_func cmd = {0};
	for (unsigned i = 0; i < ELEMS(cmd_list); i++) {
		if(strcmp(argv[1], cmd_list[i].name) == 0)
		{
			cmd = cmd_list[i];
			break;
		}
	}
	if (!cmd.func)
		errx(1, "%s: no such command", argv[1]);

        control_fd = open(DM_CONTROL_PATH, O_RDWR);
        if (control_fd == -1)
                err(1, "open " DM_CONTROL_PATH);

	cmd.func(argc-1, &argv[1]);
	close(control_fd);
	return 0;
}
