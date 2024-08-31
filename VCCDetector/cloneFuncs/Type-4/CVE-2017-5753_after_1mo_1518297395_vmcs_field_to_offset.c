static inline short vmcs_field_to_offset(unsigned long field)
{
	const size_t size = ARRAY_SIZE(vmcs_field_to_offset_table);
	unsigned short offset;
	unsigned index;

	if (field >> 15)
		return -ENOENT;

	index = ROL16(field, 6);
	if (index >= size)
		return -ENOENT;

	index = array_index_nospec(index, size);
	offset = vmcs_field_to_offset_table[index];
	if (offset == 0)
		return -ENOENT;
	return offset;
}
