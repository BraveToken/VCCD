int propagate_umount(struct list_head *list)
{
	struct mount *mnt;

	list_for_each_entry_reverse(mnt, list, mnt_list)
		mark_umount_candidates(mnt);

	list_for_each_entry(mnt, list, mnt_list)
		__propagate_umount(mnt);
	return 0;
}
