[BITS 32]

section .data
crc_res							: dd 0
len_crc_str						: dd 0
addr_crc_str					: dd 0

section .text

%ifdef PREFIX
	global calc_crc32_c
%else
	global _calc_crc32_c
%endif

%include "crc32.inc"








