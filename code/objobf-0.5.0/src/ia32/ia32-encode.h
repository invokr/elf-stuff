/* ia32-encode.h - ia32 instruction encoding, include file
 *
 * by scut
 */

#ifndef	IA32_ENCODE_H
#define	IA32_ENCODE_H


/* ia32_encode_instruction
 *
 * encode the instruction `inst' to `dest'. there must be enough space free,
 * up to 16 bytes can be used. `inst' is complete except the opc.opcode
 * pointer, which is selected through `inst_num'.
 *
 * return zero on failure
 * return length of instruction (prefix plus opcode) on success
 */

unsigned int
ia32_encode_instruction (unsigned int inst_num, ia32_instruction *inst,
	unsigned char *dest);

#endif

