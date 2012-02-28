#ifndef PMIRROR_FAKE_LIBUNWIND_H_
#define PMIRROR_FAKE_LIBUNWIND_H_

#if !defined(__i386__) && !defined(__x86__)
#error "Unsupported architecture for fake libunwind."
#endif

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

#define UNW_TARGET_X86
typedef unsigned long unw_word_t;
typedef void *unw_addr_space_t;
struct {} local_addr_space;
extern unw_addr_space_t unw_local_addr_space;
struct accessors
{
	int (*access_mem) (unw_addr_space_t as, unw_word_t addr, unw_word_t *data, int dir, void *priv);
};
typedef accessors unw_accessors_t;
int access_mem (unw_addr_space_t as, unw_word_t addr, unw_word_t *data,int dir, void *priv)
{
	if (dir == 0) /* 0 means read */
		 *(void**)data = *(void **)addr;
	else if (dir == 1) /* 1 means write */
		*(void **)addr = *(void**)data;
	else return 1;
	return 0;
}
struct accessors local_accessors = { &access_mem };
inline struct accessors *unw_get_accessors(unw_addr_space_t as)
{
	return &local_accessors;
} 

/* core register numbers from libunwind-x86.h */
#if defined(__cplusplus) || defined(c_plusplus)
enum x86_regnum_t
#else
typdef enum
#endif
{
	UNW_X86_EAX,
	UNW_X86_EDX,
	UNW_X86_ECX,
	UNW_X86_EBX,
	UNW_X86_ESI,
	UNW_X86_EDI,
	UNW_X86_EBP,
	UNW_X86_ESP,
	UNW_X86_EIP,
	UNW_X86_EFLAGS,
	UNW_X86_TRAPNO,
#if defined(__cplusplus) || defined(c_plusplus)
};
#else
} x86_regnum_t;
#endif

#define UNW_REG_IP UNW_X86_EIP
#define UNW_REG_SP UNW_X86_ESP
#define UNW_REG_BP UNW_X86_EBP

#if defined(__cplusplus) || defined(c_plusplus)
struct unw_cursor_t
#else
typedef struct 
#endif
{
	unw_word_t frame_esp;
	unw_word_t frame_ebp;
	unw_word_t frame_eip;
#if defined(__cplusplus) || defined(c_plusplus)
};
#else
} unw_cursor_t;
#endif
typedef unw_cursor_t unw_context_t;

inline int unw_get_reg(unw_cursor_t *cursor, enum x86_regnum_t reg, unw_word_t *dest)
{
	switch (reg)
	{
		case UNW_X86_ESP: *(void**)dest = (void*) cursor->frame_esp; return 0;
		case UNW_X86_EBP: *(void**)*dest = (void*) cursor->frame_ebp; return 0;
		case UNW_X86_EIP: *(void**)dest = (void*) cursor->frame_eip; return 0;
		default: return 1;
	}
}
inline int unw_init_local(unw_cursor_t *cursor, unw_context_t *context)
{
	*cursor = *context;
	return 0;
}

/* This is used by fake-libunwind.h only. */
int fake_get_proc_name(void *eip, char *buf, size_t n);
int fake_getcontext(unw_context_t *ucp);
int fake_step(unw_cursor_t *cp);

inline int unw_get_proc_name(unw_cursor_t *cursor, char *buf, size_t n, unw_word_t *FIXME_WHAT_IS_THIS)
{
	return fake_get_proc_name((void*) cursor->frame_eip, buf, n);
}

inline int unw_getcontext(unw_context_t *ucp)
{
	return fake_getcontext(ucp);
}

inline int unw_step(unw_cursor_t *cp)
{
	return fake_step(cp);
}

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif
