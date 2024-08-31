void vbe_ioport_write_data(void *opaque, uint32_t addr, uint32_t val)
{
    VGACommonState *s = opaque;

    if (s->vbe_index <= VBE_DISPI_INDEX_NB) {
        trace_vga_vbe_write(s->vbe_index, val);
        switch(s->vbe_index) {
        case VBE_DISPI_INDEX_ID:
            if (val == VBE_DISPI_ID0 ||
                val == VBE_DISPI_ID1 ||
                val == VBE_DISPI_ID2 ||
                val == VBE_DISPI_ID3 ||
                val == VBE_DISPI_ID4) {
                s->vbe_regs[s->vbe_index] = val;
            }
            break;
        case VBE_DISPI_INDEX_XRES:
        case VBE_DISPI_INDEX_YRES:
        case VBE_DISPI_INDEX_BPP:
        case VBE_DISPI_INDEX_VIRT_WIDTH:
        case VBE_DISPI_INDEX_X_OFFSET:
        case VBE_DISPI_INDEX_Y_OFFSET:
            s->vbe_regs[s->vbe_index] = val;
            vbe_fixup_regs(s);
            vbe_update_vgaregs(s);
            break;
        case VBE_DISPI_INDEX_BANK:
            val &= s->vbe_bank_mask;
            s->vbe_regs[s->vbe_index] = val;
            s->bank_offset = (val << 16);
            vga_update_memory_access(s);
            break;
        case VBE_DISPI_INDEX_ENABLE:
            if ((val & VBE_DISPI_ENABLED) &&
                !(s->vbe_regs[VBE_DISPI_INDEX_ENABLE] & VBE_DISPI_ENABLED)) {

                s->vbe_regs[VBE_DISPI_INDEX_VIRT_WIDTH] = 0;
                s->vbe_regs[VBE_DISPI_INDEX_X_OFFSET] = 0;
                s->vbe_regs[VBE_DISPI_INDEX_Y_OFFSET] = 0;
                s->vbe_regs[VBE_DISPI_INDEX_ENABLE] |= VBE_DISPI_ENABLED;
                vbe_fixup_regs(s);
                vbe_update_vgaregs(s);

                /* clear the screen */
                if (!(val & VBE_DISPI_NOCLEARMEM)) {
                    memset(s->vram_ptr, 0,
                           s->vbe_regs[VBE_DISPI_INDEX_YRES] * s->vbe_line_offset);
                }
            } else {
                s->bank_offset = 0;
            }
            s->dac_8bit = (val & VBE_DISPI_8BIT_DAC) > 0;
            s->vbe_regs[s->vbe_index] = val;
            vga_update_memory_access(s);
            break;
        default:
            break;
        }
    }
}
