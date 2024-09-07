void dtls1_reset_seq_numbers(SSL *s, int rw)
{
    unsigned char *seq;
    unsigned int seq_bytes = sizeof(s->rlayer.read_sequence);

    if (rw & SSL3_CC_READ) {
        seq = s->rlayer.read_sequence;
        s->rlayer.d->r_epoch++;
        memcpy(&s->rlayer.d->bitmap, &s->rlayer.d->next_bitmap,
               sizeof(s->rlayer.d->bitmap));
        memset(&s->rlayer.d->next_bitmap, 0, sizeof(s->rlayer.d->next_bitmap));

        /*
         * We must not use any buffered messages received from the previous
         * epoch
         */
        dtls1_clear_received_buffer(s);
    } else {
        seq = s->rlayer.write_sequence;
        memcpy(s->rlayer.d->last_write_sequence, seq,
               sizeof(s->rlayer.write_sequence));
        s->rlayer.d->w_epoch++;
    }

    memset(seq, 0, seq_bytes);
}
