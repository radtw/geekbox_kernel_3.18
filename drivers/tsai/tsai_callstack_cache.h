/*
 * tsai_callstack_cache.h
 *
 *  Created on: 13 Jul 2018
 *      Author: cheng.tsai
 */

#ifndef TSAI_CALLSTACK_CACHE_H_
#define TSAI_CALLSTACK_CACHE_H_

#include <linux/rbtree.h>

struct ts_rb_node {
	struct rb_node n;
	unsigned int key;
};

/* use this structure to store ELF symbolic information */
struct ts_elf_info {
	unsigned int load_virtual_address;
	void* symbol_table;
	int symbol_count;

	void* symbol_string_table;
	void* symbol_table_sorted;
	int symbol_sorted_count;

	void* section_string_table;
	const char** section_str_ptr_array;
	int section_count;
};

struct ts_binary_node {
	struct ts_rb_node rb; /* key is hash calculated by ts_binary_hash_from_fullpath */
	struct ts_elf_info* pelf;
	char filename[32]; /* first 31 charater for the filename */
	struct rb_root root_demangle;
	void* demangled_symbol_string; /* store demangled symbols */
	unsigned int demangled_alloc_size; /* each time increase one page (4KB) */
	unsigned int demangled_symbol_string_write_cursor;

};

/* global, not specific to any process, learned info about specific .so and func will be stored here to speed up
 * unwinding for next time
 * */
struct ts_callstack_binary_cache {
	struct rb_root root_bin;

};

struct ts_demangle_entry {
	struct ts_rb_node rb;
	unsigned int offset;
};

void ts_callstack_binary_cache_init(struct ts_callstack_binary_cache* bc);

unsigned int ts_binary_hash_from_fullpath(const char* fullpath);
unsigned int ts_binary_hash(struct file* filp);

struct ts_binary_node* ts_binary_node_get(struct ts_callstack_binary_cache* bincache, struct file* filp);
void ts_binary_node_remove(struct ts_callstack_binary_cache* bincache, struct ts_binary_node* bn);

int ts_binary_node_parse_elf(struct ts_binary_node* bn, struct file* filp);

const char* ts_binary_node_find_demangle(struct ts_binary_node* bn, const char* mangled);

struct ts_rb_node* ts_rb_find(struct rb_root* root, unsigned int key);
void ts_rb_insert(struct rb_root* root, struct ts_rb_node* n);
void ts_rb_remove(struct rb_root* root, struct ts_rb_node* n);

struct mm_struct *tsai_get_task_mm_no_irq(struct task_struct *task);
void tsai_backup_mm(unsigned int* out_save_mm, struct mm_struct** out_mm, struct mm_struct* mm);
void tsai_restore_mm(unsigned int* out_save_mm, struct mm_struct** out_mm);

void tsai_force_load_user_address(struct mm_struct *tsk_mm, unsigned int addr);
unsigned int tsai_force_read_user_address(struct mm_struct *tsk_mm, unsigned int addr);
int tsai_force_read_user_address_size(struct mm_struct *tsk_mm, unsigned int addr, void* buf, int size);
int tsai_force_write_user_address_size(struct mm_struct *tsk_mm, unsigned int addr, void* buf, int size);

pte_t* tsai_address_is_on_mmu(struct mm_struct* mm, uint64_t address, unsigned int* is_locked);

/* =============================================================================== */
void tsai_mmu_pfn_reset(void);
int tsai_get_user_data_caution(struct mm_struct* mm, unsigned int pc, long sz, void* pinsn);


int tsai_rq_is_locked(void);

void* tsai_task_rq_lock(struct task_struct *p, unsigned long *flags);
void tsai_task_rq_unlock(void* rq, struct task_struct *p, unsigned long *flags);

int tsai_task_prevent_run(struct task_struct* p, int skip_lock, atomic_t* success,int* out_state, int* out_on_rq, int* out_on_core);
void tsai_task_restore_run(struct task_struct* p, int skip_lock, atomic_t* atmflag, int* p_state, int* p_on_rq);


int tsai_task_on_cpu(struct task_struct* p);
const char* tsai_task_on_cpu_str(struct task_struct* p);

#endif /* TSAI_CALLSTACK_CACHE_H_ */
