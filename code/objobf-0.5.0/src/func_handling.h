/* func_handling.h - additional function processing for be2 engine
 * include file
 *
 * by scut
 */

#ifndef	FUNC_HANDLING_H
#define	FUNC_HANDLING_H

/* linked list of pairs of executeable section and their relocation data
 */
typedef struct code_pair {
	struct code_pair *	next;
	elf_section *	code_section;
	elf_rel_list *	reloc;
} code_pair;



/* func_bblock_deref_interfunc
 *
 * this is a postprocessing function to the normal analysis. normally,
 * static inter-function references (_END_CALL, _END_TRANSFER_INTER,
 * _END_IF_INTER) are processed by peeking into the memory of the instruction.
 * this is suboptimal as we could already know what it references in advance.
 * hence we scan all basic blocks for such end types and fill in the
 * appropiate target basic block within their endbr[] array. also, we remove
 * the other_xref entry of the basic block that changes the instruction. this
 * is necessary to help the 'func_list_filter_dynamic' function (otherwise it
 * would put any call as dynamic). the `flist' and `flist_count' parameters
 * denote the global function list, as usual.
 *
 * return number of basic blocks dereferenced in any case
 */

unsigned int
func_bblock_deref_interfunc (ia32_function **flist, unsigned int flist_count);


/* fix_ustart
 *
 * _start is not function sometimes, so make it one.
 * FIXME: check if its really necessary still (its quite old code), and maybe
 *        find a better way.
 *
 * return in any case
 */

void
fix_ustart (elf_base *obj);


/* find_position_curious_functions
 *
 * there are functions (such as call_gmon_start), which have hardcoded
 * instructions such as:
 *
 *   # 0x0007 # 07 . E8 00 00 00 00     # call dword (32)0x00000000
 *   # 0x000c # 0c . 5B                 # pop ebx
 *   # 0x000d # 0d . 81 C3 03 00 00 00  # add ebx, (32)0x00000003
 *   # 0x0013 # 13 . 8B 83 00 00 00 00  # mov eax, dword [ebx + (32)0x00000000]
 *
 * where the current eip is obtained and relative computations take place.
 * this is done to process certain global data before any relocation might
 * have happened (call_gmon_start is called from _init for example). while
 * understandable, we do not provide emulation of a GOT (and do not want to do
 * that, anyway). hence, we find all functions, which contain position 
 */

void
find_position_curious_functions (ia32_function **flist, unsigned int flist_count);


/* find_abnormal_end_functions
 *
 * when a function runs over its symbol-table stored boundary, or when the
 * last instruction is abnormal (no ret/hlt/..) this is noted with an internal
 * flag in the function structure, called is_abnormal_end. this utility
 * function just dumps a list of all functions ending abnormaly.
 *
 * return in any case.
 */

void
find_abnormal_end_functions (ia32_function **flist, unsigned int flist_count);


/* func_output
 *
 * dump the function `fname' as VCG formatted file `outputfile'. the function
 * must be within `flist', which is `flist_count' items long. if `loop_detect'
 * is non-zero, the basic blocks will be grouped into natural loops.
 *
 * return in any case.
 */

void
func_output (const char *outputfile, ia32_function **flist, unsigned int flist_count,
	char *fname, int loop_detect);


/* func_livereg
 *
 * do a live register dataflow analysis on the function named `livereg_func'.
 * it must be located within `flist', which is `flist_count' items long. write
 * the output as VCG graph to `outputfile'. `loop_detect' has the same
 * behaviour as with func_output.
 *
 * return in any case
 */

void
func_livereg (const char *outputfile, ia32_function **flist, unsigned int flist_count,
	char *livereg_func, int loop_detect);


/* func_domtree
 *
 * output a dominator tree graph as VCG file to `outputfile'. the dominator
 * tree is build for the function `domtree_func', which has to be within
 * `flist', which is `flist_count' items long.
 *
 * return in any case
 */

void
func_domtree (const char *outputfile, ia32_function **flist,
	unsigned int flist_count, char *domtree_func);


/* restore_section_data
 *
 * restore the backup'ed sections of `base'.
 *
 * return in any case
 */

void
restore_section_data (elf_base *base);


/* backup_section_data
 *
 * create a backup of the original section data for every section of `base'.
 *
 * return in any case
 */

void
backup_section_data (elf_base *base);


/* get_rodata_relocation
 *
 * get the relocation list structure for the ".rodata" and ".rel.rodata"
 * sections.
 *
 * return NULL on failure
 * return list structure on success
 */

elf_reloc_list *
get_rodata_relocation (elf_base *base, elf_rel_list *rel_list);


/* relocate_sections
 *
 * for each code/data section of `base' a relocation table is available within
 * `rel_list', do the relocation.
 *
 * return in any case.
 */

void
relocate_sections (elf_base *base, elf_rel_list *rel_list);


/* code_pair_extract
 *
 * create a list of relocation sections and the section they relocate. keep
 * only the ones refering to code sections and store both sections in a
 * "code_pair" structure. everything happens within the ELF file `base'.
 *
 * return linked list of code_pair structures on success
 * return NULL on failure
 */

code_pair *
code_pair_extract (elf_base *base, elf_section_list *seclist,
	elf_rel_list *rel_list);


/* relocate_data
 *
 * process a single data sections' relocation entries listed in `rl'. use the
 * elf base information within `eb' for lookups. the relocations within the
 * code section is done at runtime, when each basic block is being executed.
 * but data sections relocations have to be processed prior to executing any
 * code, since we cannot predict accesses to the data sections (yet).
 *
 * return in any case
 */

void
relocate_data (elf_base *eb, elf_reloc_list *rl);


#endif

