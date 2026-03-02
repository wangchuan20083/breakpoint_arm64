#include "hw_point.h"
unsigned long util_kallsyms_lookup_name(const char *name);
#define READ_WB_REG_CASE(OFF, N, REG, VAL)	\
	case (OFF + N):				\
		AARCH64_DBG_READ(N, REG, VAL);	\
		break

#define WRITE_WB_REG_CASE(OFF, N, REG, VAL)	\
	case (OFF + N):				\
		AARCH64_DBG_WRITE(N, REG, VAL);	\
		break

#define GEN_READ_WB_REG_CASES(OFF, REG, VAL)	\
	READ_WB_REG_CASE(OFF,  0, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  1, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  2, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  3, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  4, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  5, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  6, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  7, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  8, REG, VAL);	\
	READ_WB_REG_CASE(OFF,  9, REG, VAL);	\
	READ_WB_REG_CASE(OFF, 10, REG, VAL);	\
	READ_WB_REG_CASE(OFF, 11, REG, VAL);	\
	READ_WB_REG_CASE(OFF, 12, REG, VAL);	\
	READ_WB_REG_CASE(OFF, 13, REG, VAL);	\
	READ_WB_REG_CASE(OFF, 14, REG, VAL);	\
	READ_WB_REG_CASE(OFF, 15, REG, VAL)

#define GEN_WRITE_WB_REG_CASES(OFF, REG, VAL)	\
	WRITE_WB_REG_CASE(OFF,  0, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  1, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  2, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  3, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  4, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  5, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  6, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  7, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  8, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF,  9, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF, 10, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF, 11, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF, 12, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF, 13, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF, 14, REG, VAL);	\
	WRITE_WB_REG_CASE(OFF, 15, REG, VAL)
static LIST_HEAD(g_bp_list);
static DEFINE_MUTEX(g_bp_mutex);

typedef struct perf_event *(*register_user_hw_breakpoint_t)(struct perf_event_attr *attr,
                                                         perf_overflow_handler_t triggered,
                                                         void *context,
                                                         struct task_struct *tsk);
typedef void (*unregister_hw_breakpoint_t)(struct perf_event *bp);

static register_user_hw_breakpoint_t _register_user_hw_breakpoint = NULL;
static unregister_hw_breakpoint_t _unregister_hw_breakpoint = NULL;

static int resolve_symbols(void)
{
    if (_register_user_hw_breakpoint && _unregister_hw_breakpoint) return 0;
    
    _register_user_hw_breakpoint = (void *)util_kallsyms_lookup_name("register_user_hw_breakpoint");
    _unregister_hw_breakpoint = (void *)util_kallsyms_lookup_name("unregister_hw_breakpoint");

    if (!_register_user_hw_breakpoint || !_unregister_hw_breakpoint) {
        pr_err("[HWBP] Symbols not found\n");
        return -ENXIO;
    }
    return 0;
}
static int getCpuNumBrps(void) {
	return ((read_cpuid(ID_AA64DFR0_EL1) >> 12) & 0xf) + 1;
}

static int getCpuNumWrps(void) {
	return ((read_cpuid(ID_AA64DFR0_EL1) >> 20) & 0xf) + 1;
}

static uint64_t read_wb_reg(int reg, int n)
{
	uint64_t val = 0;

	switch (reg + n) {
	GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BVR, AARCH64_DBG_REG_NAME_BVR, val);
	GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BCR, AARCH64_DBG_REG_NAME_BCR, val);
	GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WVR, AARCH64_DBG_REG_NAME_WVR, val);
	GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WCR, AARCH64_DBG_REG_NAME_WCR, val);
	default:
		pr_warn("attempt to read from unknown breakpoint register %d\n", n);
	}

	return val;
}

static void write_wb_reg(int reg, int n, uint64_t val)
{
	switch (reg + n) {
	GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_BVR, AARCH64_DBG_REG_NAME_BVR, val);
	GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_BCR, AARCH64_DBG_REG_NAME_BCR, val);
	GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_WVR, AARCH64_DBG_REG_NAME_WVR, val);
	GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_WCR, AARCH64_DBG_REG_NAME_WCR, val);
	default:
		pr_warn("attempt to write to unknown breakpoint register %d\n", n);
	}
	isb();
}

static uint64_t calc_hw_addr(const struct perf_event_attr* attr, bool is_32bit_task) {
	uint64_t alignment_mask, hw_addr;
	if(!attr) {
		return 0;
	}
	if (is_32bit_task) {
		if (attr->bp_len == HW_BREAKPOINT_LEN_8)
			alignment_mask = 0x7;
		else
			alignment_mask = 0x3;
	} else {
		if (attr->type == HW_BREAKPOINT_X)
			alignment_mask = 0x3;
		else
			alignment_mask = 0x7;
	}
	hw_addr = attr->bp_addr;
	hw_addr &= ~alignment_mask;
	return hw_addr;
}

static bool toggle_bp_registers_directly(const struct perf_event_attr * attr, bool is_32bit_task, int enable) {
	int i, max_slots, val_reg, ctrl_reg, cur_slot;
    u32 ctrl;
	uint64_t hw_addr = calc_hw_addr(attr, is_32bit_task);
	if(!attr) {
		return false;
	}

	switch (attr->bp_type)
	{
	case HW_BREAKPOINT_R:
	case HW_BREAKPOINT_W:
	case HW_BREAKPOINT_RW:
		ctrl_reg = AARCH64_DBG_REG_WCR;
		val_reg = AARCH64_DBG_REG_WVR;
		max_slots = getCpuNumWrps();
		break;
	case HW_BREAKPOINT_X:
		ctrl_reg = AARCH64_DBG_REG_BCR;
		val_reg = AARCH64_DBG_REG_BVR;
		max_slots = getCpuNumBrps();
		break;
	default:
		return false;
	}
	cur_slot = -1;

    for (i = 0; i < max_slots; ++i) {
		uint64_t addr = read_wb_reg(val_reg, i);
        if(addr == hw_addr) {
			cur_slot = i;
			break;
		}
    }
	if(cur_slot == -1) {
		return false;
	} 

    ctrl = read_wb_reg(ctrl_reg, cur_slot);
	if (enable)
		ctrl |= 0x1;
	else
		ctrl &= ~0x1;
	write_wb_reg(ctrl_reg, cur_slot, ctrl);
	return true;
}

static void hw_bp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    struct hw_bp_context *ctx = bp->overflow_handler_context;
    struct HWBP_HIT_ITEM *item;
    unsigned long flags;
    bool is_32bit_task = is_compat_thread(task_thread_info(current));
    if (!ctx || !regs) return;

    // 1. 执行寄存器劫持逻辑
    if (ctx->is_write_regs) {
        // 修改通用寄存器 X0-X30
        if (ctx->reg_index >= 0 && ctx->reg_index <= 30) {
            regs->regs[ctx->reg_index] = ctx->reg_value;
        }
        // 修改 SP (31)
        else if (ctx->reg_index == 31) {
            regs->sp = ctx->reg_value;
        }
        // 修改 PC (32)
        else if (ctx->reg_index == 32) {
            regs->pc = ctx->reg_value;
        }
    }

    // ==========================================================
    // 防止死循环
    toggle_bp_registers_directly(&bp->attr, is_32bit_task, 0); // 0 表示禁用

    // 2. 记录命中日志 (原有逻辑)
    spin_lock_irqsave(&ctx->lock, flags);
    
    item = &ctx->hit_records[ctx->head];
    item->task_id = ctx->pid;
    item->hit_addr = regs->pc; // 记录跳过后的地址，或者记录 regs->pc - 4
    item->hit_time = 0; 
    
    memcpy(item->regs_info.regs, regs->regs, sizeof(uint64_t) * 31);
    item->regs_info.sp = regs->sp;
    item->regs_info.pc = regs->pc;
    item->regs_info.pstate = regs->pstate;

    ctx->head = (ctx->head + 1) % MAX_HIT_RECORDS;
    if (ctx->count < MAX_HIT_RECORDS) {
        ctx->count++;
    } else {
        ctx->tail = (ctx->tail + 1) % MAX_HIT_RECORDS;
    }
    spin_unlock_irqrestore(&ctx->lock, flags);
}

// --- 核心修改：接收完整 info 结构指针 ---
int install_hw_bp(HW_BP_INFO *info) {
    struct hw_bp_context *ctx;
    struct perf_event_attr attr;
    struct task_struct *task;
    int ret = 0;

    if (resolve_symbols() != 0) return -ENXIO;

    mutex_lock(&g_bp_mutex);
    // 查重
    list_for_each_entry(ctx, &g_bp_list, list) {
        if (ctx->pid == info->pid && ctx->addr == info->addr) {
            mutex_unlock(&g_bp_mutex);
            return -EEXIST;
        }
    }

    hw_breakpoint_init(&attr);
    attr.bp_addr = info->addr;
    attr.bp_len = info->len;
    
    switch(info->type) {
        case 1: attr.bp_type = HW_BREAKPOINT_R; break;
        case 2: attr.bp_type = HW_BREAKPOINT_W; break;
        case 3: attr.bp_type = HW_BREAKPOINT_RW; break;
        case 4: attr.bp_type = HW_BREAKPOINT_X; break;
        default: attr.bp_type = HW_BREAKPOINT_RW;
    }

    task = get_pid_task(find_vpid(info->pid), PIDTYPE_PID);
    if (!task) { mutex_unlock(&g_bp_mutex); return -ESRCH; }

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx) { put_task_struct(task); mutex_unlock(&g_bp_mutex); return -ENOMEM; }

    // 填充上下文
    ctx->pid = info->pid;
    ctx->addr = info->addr;
    ctx->type = info->type;
    ctx->len = info->len;
    
    // 保存劫持配置
    ctx->is_write_regs = info->is_write_regs;
    ctx->reg_index = info->reg_index;
    ctx->reg_value = info->reg_value;

    spin_lock_init(&ctx->lock);

    ctx->pe = _register_user_hw_breakpoint(&attr, hw_bp_handler, ctx, task);
    put_task_struct(task);

    if (IS_ERR(ctx->pe)) {
        ret = PTR_ERR(ctx->pe);
        kfree(ctx);
        mutex_unlock(&g_bp_mutex);
        return ret;
    }

    list_add(&ctx->list, &g_bp_list);
    mutex_unlock(&g_bp_mutex);
    return 0;
}

int get_hw_bp_hits(HWBP_HIT_ARGS *args) {
    struct hw_bp_context *pos;
    int ret = -ENOENT;
    unsigned long flags;

    mutex_lock(&g_bp_mutex);
    list_for_each_entry(pos, &g_bp_list, list) {
        if (pos->pid == args->pid && pos->addr == args->addr) {
            uint32_t to_copy;
            struct HWBP_HIT_ITEM *temp_buf;

            spin_lock_irqsave(&pos->lock, flags);
            to_copy = (pos->count < args->out_len) ? pos->count : args->out_len;
            
            if (to_copy == 0) {
                spin_unlock_irqrestore(&pos->lock, flags);
                args->real_count = 0;
                ret = 0;
                goto out_unlock;
            }

            temp_buf = kmalloc_array(to_copy, sizeof(struct HWBP_HIT_ITEM), GFP_ATOMIC);
            if (temp_buf) {
                int i;
                for (i = 0; i < to_copy; i++) {
                    temp_buf[i] = pos->hit_records[pos->tail];
                    pos->tail = (pos->tail + 1) % MAX_HIT_RECORDS;
                }
                pos->count -= to_copy;
            }
            spin_unlock_irqrestore(&pos->lock, flags);

            if (temp_buf) {
                if (copy_to_user(args->out_buf, temp_buf, to_copy * sizeof(struct HWBP_HIT_ITEM))) {
                    ret = -EFAULT;
                } else {
                    args->real_count = to_copy;
                    ret = 0;
                }
                kfree(temp_buf);
            } else {
                ret = -ENOMEM;
            }
            goto out_unlock;
        }
    }
out_unlock:
    mutex_unlock(&g_bp_mutex);
    return ret;
}

void clear_all_hw_bps(void) {
    struct hw_bp_context *pos, *n;
    mutex_lock(&g_bp_mutex);
    list_for_each_entry_safe(pos, n, &g_bp_list, list) {
        if (pos->pe) _unregister_hw_breakpoint(pos->pe);
        list_del(&pos->list);
        kfree(pos);
    }
    mutex_unlock(&g_bp_mutex);
}

int enable_hw_bp(pid_t pid, uintptr_t addr) {
    struct hw_bp_context *pos;
    bool is_32bit_task;
    struct task_struct *task;

    mutex_lock(&g_bp_mutex);
    list_for_each_entry(pos, &g_bp_list, list) {
        if (pos->pid == pid && pos->addr == addr) {
            // 找到目标断点
            task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
            if (!task) {
                mutex_unlock(&g_bp_mutex);
                return -ESRCH;
            }
            is_32bit_task = is_compat_thread(task_thread_info(task));
            put_task_struct(task);

            if (!toggle_bp_registers_directly(&pos->pe->attr, is_32bit_task, 1)) {
                mutex_unlock(&g_bp_mutex);
                return -EIO;
            }
            mutex_unlock(&g_bp_mutex);
            return 0;
        }
    }
    mutex_unlock(&g_bp_mutex);
    return -ENOENT;
}