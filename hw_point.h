#ifndef _HW_POINT_H_
#define _HW_POINT_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/ktime.h>
#include "asm/current.h"
#include <linux/slab.h>
#include "comm.h" 
// 断点类型映射
#define HW_BP_TYPE_R    1
#define HW_BP_TYPE_W    2
#define HW_BP_TYPE_RW   3
#define HW_BP_TYPE_X    4

#define MAX_HIT_RECORDS 16

struct hw_bp_context {
    struct list_head list;      
    pid_t pid;                  
    uintptr_t addr;             
    struct perf_event *pe;      
    int type;
    int len;

    // --- 新增：寄存器劫持配置 ---
    bool is_write_regs;    
    int reg_index;        
    uint64_t reg_value;   
    // -------------------------

    struct HWBP_HIT_ITEM hit_records[MAX_HIT_RECORDS];
    int head;                   
    int tail;                   
    int count;                  
    spinlock_t lock;            
};

// 修改函数签名，直接传递 info 指针以包含所有配置
int install_hw_bp(HW_BP_INFO *info);
int get_hw_bp_hits(HWBP_HIT_ARGS *args);
void clear_all_hw_bps(void);
int enable_hw_bp(pid_t pid, uintptr_t addr);
#endif // _HW_POINT_H_