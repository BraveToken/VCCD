static void virtio_blk_handle_scsi(VirtIOBlockReq *req)
{
    virtio_blk_req_complete(req, VIRTIO_BLK_S_UNSUPP);
}
