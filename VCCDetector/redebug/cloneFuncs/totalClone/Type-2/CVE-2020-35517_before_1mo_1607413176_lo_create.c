static void lo_create(fuse_req_t req, fuse_ino_t parent, const char *name,
                      mode_t mode, struct fuse_file_info *fi)
{
    int fd;
    struct lo_data *lo = lo_data(req);
    struct lo_inode *parent_inode;
    struct fuse_entry_param e;
    int err;
    struct lo_cred old = {};

    fuse_log(FUSE_LOG_DEBUG, "lo_create(parent=%" PRIu64 ", name=%s)\n", parent,
             name);

    if (!is_safe_path_component(name)) {
        fuse_reply_err(req, EINVAL);
        return;
    }

    parent_inode = lo_inode(req, parent);
    if (!parent_inode) {
        fuse_reply_err(req, EBADF);
        return;
    }

    err = lo_change_cred(req, &old);
    if (err) {
        goto out;
    }

    update_open_flags(lo->writeback, lo->allow_direct_io, fi);

    fd = openat(parent_inode->fd, name, (fi->flags | O_CREAT) & ~O_NOFOLLOW,
                mode);
    err = fd == -1 ? errno : 0;
    lo_restore_cred(&old);

    if (!err) {
        ssize_t fh;

        pthread_mutex_lock(&lo->mutex);
        fh = lo_add_fd_mapping(req, fd);
        pthread_mutex_unlock(&lo->mutex);
        if (fh == -1) {
            close(fd);
            err = ENOMEM;
            goto out;
        }

        fi->fh = fh;
        err = lo_do_lookup(req, parent, name, &e);
    }
    if (lo->cache == CACHE_NONE) {
        fi->direct_io = 1;
    } else if (lo->cache == CACHE_ALWAYS) {
        fi->keep_cache = 1;
    }

out:
    lo_inode_put(lo, &parent_inode);

    if (err) {
        fuse_reply_err(req, err);
    } else {
        fuse_reply_create(req, &e, fi);
    }
}
