#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

struct fs_node {
    char *path;
    int is_dir;
    char *content;
    struct fs_node *father;
    struct fs_node *child, *next;
    struct stat stbuf;
};

struct fs_node *root;

static int is_prefix(const char *pre, const char *str) {
    int n = strlen(pre), m = strlen(str);
    if (n > m) return 0;
    if(strncmp(pre, str, n)) return 0;
    return n == m || str[n] == '/';
}

static struct fs_node *find_node(const char *path, int find_father) {
    struct fs_node *cur = root;
    int len = strlen(path), level = 0;
    for (int i = 1; i < len; ++i)
        if (i == len - 1 || path[i] == '/')
            ++level;
    level -= find_father;
    if (level < 0) return NULL;

    while (level--) {
        int flag = 0;
        for (struct fs_node *p = cur->child; p; p = p->next)
            if (is_prefix(p->path, path)) {
                cur = p;
                flag = 1;
                break;
            }
        if (!flag) return NULL;
    }
    return cur;
}

static int create_node(const char *path, mode_t mode, int is_dir) {
    struct fs_node *father_node = find_node(path, 1);
    if (!father_node) return -ENOENT;
    if (!father_node->is_dir) return -ENOTDIR;
    struct fs_node *node = malloc(sizeof(struct fs_node));
    node->is_dir = is_dir;
    node->path = malloc(strlen(path) + 1);
    strcpy(node->path, path);
    node->content = NULL;

    node->father = father_node;
    node->child = NULL;
    node->next = father_node->child;
    father_node->child = node;

    node->stbuf.st_mode = is_dir ? S_IFDIR | mode : S_IFREG | mode;
    node->stbuf.st_nlink = is_dir ? 2 : 1;
    node->stbuf.st_uid = getuid();
    node->stbuf.st_gid = getgid();
    node->stbuf.st_size = 0;
    node->stbuf.st_atime = node->stbuf.st_mtime = node->stbuf.st_ctime = time(NULL);

    if (is_dir) father_node->stbuf.st_nlink++;
    return 0;
}

static int remove_node(const char *path, int is_dir) {
    struct fs_node *node = find_node(path, 0);
    if (!node) return -ENOENT;
    if (node->is_dir != is_dir) return is_dir ? -ENOTDIR : -EISDIR;
    if (is_dir && node->child) return -ENOTEMPTY;
    if (node->father == NULL) return -EACCES;

    if (node->next) node->next->father = node->father;
    if (node->father->child == node) node->father->child = node->next;
    else {
        struct fs_node *p = node->father->child;
        while (p->next != node) p = p->next;
        p->next = node->next;
    }
    free(node->path);
    free(node);
    if (is_dir) node->father->stbuf.st_nlink--;
    return 0;
}

static int fs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    struct fs_node *node = find_node(path, 0);
    if (!node) return -ENOENT;
    *stbuf = node->stbuf;
    return 0;
}

static void *fs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    root = malloc(sizeof(struct fs_node));
    root->path = malloc(2);
    strcpy(root->path, "/");
    root->is_dir = 1;
    root->content = NULL;
    root->father = NULL;
    root->child = root->next = NULL;
    root->stbuf.st_mode = S_IFDIR | 0755;
    root->stbuf.st_nlink = 2;
    root->stbuf.st_uid = getuid();
    root->stbuf.st_gid = getgid();
    root->stbuf.st_size = 0;
    root->stbuf.st_atime = root->stbuf.st_mtime = root->stbuf.st_ctime = time(NULL);
    return 0;
}

static int fs_mkdir(const char *path, mode_t mode) {
    return create_node(path, mode, 1);
}

static int fs_rmdir(const char *path) {
    return remove_node(path, 1);
}

static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    struct fs_node *node = find_node(path, 0);
    if (!node) return -ENOENT;
    if (!node->is_dir) return -ENOTDIR;
    filler(buf, ".", NULL, 0, 0);
    if (node->father) filler(buf, "..", NULL, 0, 0);
    int len = strlen(path);
    if (path[len - 1] != '/') ++len;
    for (struct fs_node *p = node->child; p; p = p->next)
        filler(buf, p->path + len, &p->stbuf, 0, 0);
    return 0;
}

static int fs_mknod(const char *path, mode_t mode, dev_t dev) {
    return create_node(path, mode, 0);
}

static int fs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
    struct fs_node *node = find_node(path, 0);
    if (!node) return -ENOENT;
    node->stbuf.st_atime = tv[0].tv_sec;
    node->stbuf.st_mtime = tv[1].tv_sec;
    return 0;
}

static int fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    struct fs_node *node = find_node(path, 0);
    if (!node) return -ENOENT;
    if (node->is_dir) return -EISDIR;
    if (offset >= node->stbuf.st_size) return 0;
    if (offset + size > node->stbuf.st_size) size = node->stbuf.st_size - offset;
    memcpy(buf, node->content + offset, size);
    node->stbuf.st_atime = time(NULL);
    return size;
}

static int fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    struct fs_node *node = find_node(path, 0);
    if (!node) return -ENOENT;
    if (node->is_dir) return -EISDIR;
    if (offset + size > node->stbuf.st_size) {
        node->content = realloc(node->content, offset + size);
        node->stbuf.st_size = offset + size;
    }
    memcpy(node->content + offset, buf, size);
    node->stbuf.st_mtime = node->stbuf.st_atime = time(NULL);
    return size;
}

static int fs_unlink(const char *path) {
    return remove_node(path, 0);
}

static int fs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    struct fs_node *node = find_node(path, 0);
    if (!node) return -ENOENT;
    node->stbuf.st_mode = (node->stbuf.st_mode & ~0777) | mode;
    return 0;
}

static int fs_access(const char *path, int mask) {
    struct fs_node *node = find_node(path, 0);
    if (!node) return -ENOENT;
    if (node->stbuf.st_mode & mask) return 0;
    return -EACCES;
}

static int fs_open(const char *path, struct fuse_file_info *fi) {
    struct fs_node *node = find_node(path, 0);
    if (!node) return -ENOENT;
    if (node->is_dir) return -EISDIR;
    return 0;
}

static struct fuse_operations fs_ops = {
    .init = fs_init,
    .getattr = fs_getattr,
    .mkdir = fs_mkdir,
    .rmdir = fs_rmdir,
    .readdir = fs_readdir,
    .mknod = fs_mknod,
    .utimens = fs_utimens,
    .read = fs_read,
    .write = fs_write,
    .unlink = fs_unlink,
    .chmod = fs_chmod,
    .access = fs_access,
    .open = fs_open,
};

int main(int argc, char *argv[]) {
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	ret = fuse_main(args.argc, args.argv, &fs_ops, NULL);
	fuse_opt_free_args(&args);
	return ret;
}