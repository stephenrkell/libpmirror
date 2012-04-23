#include "process.hpp"
#include <fstream>
#include <sstream>
#include <cstring>

#include <strings.h>

/* define BEGINNING_OF_STACK  -- note that this is just a sentinel and doesn't have 
 * to be accurate! Let's make sure it's at least as high as the first stack loc though. */
#ifdef UNW_TARGET_X86
#define BEGINNING_OF_STACK 0xbfffffff
#else // assume X86_64 for now
#define BEGINNING_OF_STACK 0x7fffffffffff
#endif

using namespace dwarf;
/*using namespace dwarf::lib;*/ // omitted to remove Elf ambiguity
using std::string;
using std::cerr;
using std::endl;
using std::pair;
using std::make_pair;

using boost::dynamic_pointer_cast;
using boost::shared_ptr;

using dwarf::spec::basic_die;
using dwarf::spec::subprogram_die;
using dwarf::spec::type_die;
using dwarf::spec::variable_die;
using dwarf::spec::with_static_location_die;
using dwarf::spec::compile_unit_die;

#ifdef NO_LIBUNWIND
/* We define some fake libunwind stuff here. */
#include "fake-libunwind.h"
#include "libreflect.hpp"
long local_addr_space;
unw_addr_space_t unw_local_addr_space = &local_addr_space;
struct accessors local_accessors = { &access_mem };

int unw_get_reg(unw_cursor_t *cursor, enum x86_regnum_t reg, unw_word_t *dest)
{
	switch (reg)
	{
		case UNW_X86_ESP: *(void**)dest = (void*) cursor->frame_esp; return 0;
		case UNW_X86_EBP: *(void**)dest = (void*) cursor->frame_ebp; return 0;
		case UNW_X86_EIP: *(void**)dest = (void*) cursor->frame_eip; return 0;
		default: return 1;
	}
}
int unw_init_local(unw_cursor_t *cursor, unw_context_t *context)
{
	*cursor = *context;
	return 0;
}

int unw_get_proc_name(unw_cursor_t *p_cursor, char *buf, size_t n, unw_word_t *offp)
{
	assert(!offp);
	auto found = pmirror::self.find_subprogram_for_absolute_ip(p_cursor->frame_eip);
	if (!found) return 1;
	if (!found->get_name()) return 2;
	else 
	{
		string name = *found->get_name();
		name.copy(buf, n);
		return 0;
	}
}
int unw_getcontext(unw_context_t *ucp)
{
	unw_word_t current_bp, caller_bp, caller_sp;
	unw_word_t current_return_addr;
	current_return_addr = (unw_word_t)
		/*__builtin_extract_return_address( */
			__builtin_return_address(0/*)*/
		);
	__asm__ ("movl %%ebp, %0\n" :"=r"(current_bp));
	/* We get the old break pointer by dereferencing the addr found at 0(%ebp) */
	caller_bp = (unw_word_t) *reinterpret_cast<void **>(current_bp);
	/* We get the caller stack pointer by taking the addr, and adjusting for
	 * the arguments & return addr to this function (two words). */
	caller_sp = (unw_word_t) (reinterpret_cast<void **>(current_bp) + 2);
	*ucp = (unw_context_t){ 
		/* context sp = */ caller_sp, 
		/* context bp = */ caller_bp, 
		/* context ip = */ current_return_addr
	};
	return 0;
}

int unw_step(unw_cursor_t *cp)
{
	/*
       On successful completion, unw_step() returns a positive  value  if  the
       updated  cursor  refers  to  a  valid stack frame, or 0 if the previous
       stack frame was the last frame in the chain.  On  error,  the  negative
       value of one of the error-codes below is returned.
	*/
	
	unw_context_t ctxt = *cp;
	
	// the next-higher ip is the return addr of the frame, i.e. 4(%eip)
	void *return_addr = *(reinterpret_cast<void **>(ctxt.frame_ebp) + 1);
	
	unw_context_t new_ctxt = (unw_context_t) { 
		/* context sp = */ (unw_word_t) (reinterpret_cast<void **>(ctxt.frame_ebp) + 2),
		/* context bp = */ (unw_word_t) *reinterpret_cast<void **>(ctxt.frame_ebp),
		/* context ip = */ (unw_word_t) return_addr
	};
		
	// sanity check the results
	if (new_ctxt.frame_esp >= BEGINNING_OF_STACK
	||  new_ctxt.frame_esp <= end
	||  new_ctxt.frame_ebp >= BEGINNING_OF_STACK
	||  new_ctxt.frame_ebp <= end)
	{
		// looks dodgy -- say we failed
		return -1;
	}
	// otherwise return the number of bytes we stepped up
	else
	{
		*cp = new_ctxt;
		return new_ctxt.frame_esp - ctxt.frame_esp;
	}
}

#endif

namespace pmirror {

boost::shared_ptr<dwarf::spec::with_dynamic_location_die>
process_image::discover_stack_object(
	addr_t addr, 
	addr_t *out_object_start_addr,
	addr_t *out_frame_base,
	addr_t *out_frame_return_addr
	)
{
    if (is_local)
    {
    	/* use the local version */
        return discover_stack_object_local(addr, out_object_start_addr, 
			out_frame_base, out_frame_return_addr);
    }
    else
    {
    	/* use the remote version */
        return discover_stack_object_remote(addr, out_object_start_addr,
			out_frame_base, out_frame_return_addr);
    }
}

boost::shared_ptr<dwarf::spec::with_dynamic_location_die>
process_image::discover_stack_object_local(
	addr_t addr, 
	addr_t *out_object_start_addr,
	addr_t *out_frame_base,
	addr_t *out_frame_return_addr
)
{
	stack_object_discovery_handler_arg arg
     = {addr, boost::shared_ptr<dwarf::spec::with_dynamic_location_die>(), 0, 0, 0};
	walk_stack(NULL, stack_object_discovery_handler, &arg);
    // forward output arguments
    if (out_object_start_addr) *out_object_start_addr = arg.object_start_addr;
	if (out_frame_base) *out_frame_base = arg.frame_base;
	if (out_frame_return_addr) *out_frame_return_addr = arg.frame_return_addr;
    // extract and return return value
	if (!arg.discovered_die) cerr << "Stack object discovery failed for " << (void*)addr << endl;
    return arg.discovered_die;
}

int stack_print_handler(process_image *image,
		unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
		unw_word_t frame_caller_ip,
		unw_word_t frame_callee_ip,
		unw_cursor_t frame_cursor,
		unw_cursor_t frame_callee_cursor,
		void *arg)
{
	std::cerr << "Found a frame, ip=0x" << std::hex << frame_ip
		<< ", sp=0x" << std::hex << frame_sp 
		<< ", bp=0x" << std::hex << frame_caller_sp  << std::dec
		//<< ", return_addr=0x" << std::hex << prevframe_ip
		<< ", name: " << frame_proc_name << std::endl;
	return 0; // should we stop? no, carry on
}

int stack_object_discovery_handler(process_image *image,
		unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
		unw_word_t frame_caller_ip,
		unw_word_t frame_callee_ip,
        unw_cursor_t frame_cursor,
        unw_cursor_t frame_callee_cursor,
        void *arg)
{
	// DEBUG: print the frame
	stack_print_handler(image, frame_sp, frame_ip, frame_proc_name, 
		frame_caller_sp, frame_caller_ip, frame_callee_ip, 
		frame_cursor, frame_callee_cursor,
		0);

	// unpack our argument object 
	struct stack_object_discovery_handler_arg *arg_obj 
	 = reinterpret_cast<stack_object_discovery_handler_arg *>(arg);
	process_image::addr_t addr = arg_obj->addr;

	// now do the stuff
	if (addr <= (frame_caller_sp - sizeof (int))
		&& addr >= frame_sp)
	{
		std::cerr << "Variable at 0x" << std::hex << addr << std::dec
			<< " appears to be in frame " << frame_proc_name 
			<< ", ip=0x" << std::hex << frame_ip << std::dec << std::endl;
	}
	else return 0; // keep going

	/* If a variable "appears to be" in a frame X, it might actually
	 * be an actual parameter of the current *callee* of X, rather than
	 * a local of X.
	 * Actual parameters appear to be in the caller's frame, because they
	 * come before the break pointer (i.e. higher up in memory). To fix this, 
	 * get the debug info for the current ip, and test against the formal
	 * parameters. */
	if (frame_callee_ip != 0)
	{
		auto callee_subp = image->find_subprogram_for_absolute_ip(frame_callee_ip);
		if(!callee_subp)
		{
			std::cerr << "Warning: no debug info at bp=0x"           // HACK: we don't get 
				<< std::hex << frame_sp << std::dec           // the callee sp, so quote
				<< "; object discovery may miss argument objects."   // current sp as callee bp
				<< std::endl;
			// skip the rest of this test
		}
		else
		{
			cerr << "Frame callee is subprogram " << callee_subp->summary() << endl;
			process_image::addr_t dieset_base = image->get_dieset_base(callee_subp->get_ds());
			unw_word_t dieset_relative_ip = frame_callee_ip - dieset_base;
			libunwind_regs my_regs(&frame_callee_cursor); 
			dwarf::lib::Dwarf_Signed frame_base;
			// warn about variadic omission
			if (callee_subp->is_variadic())
			{
				std::cerr << "Warning: unwinding varargs frame at bp=0x" // HACK: we don't get 
					<< std::hex << frame_sp << std::dec				  // the callee sp, so quote
					<< "; object discovery may miss objects in this frame."   // current sp as callee bp
					<< std::endl;
			}
			// HACK: we subtract 1 from the dieset_relative_ip when computing a vaddr, 
			// because before this sibtraction, it will point to the next instruction
			// on return to the frame, whereas we want the actual instruction that is
			// current. Without this adjustment, we are liable to get off-by-one errors
			// when looking up the relevant DWARF location list entry.
			auto ret = callee_subp->contains_addr_as_frame_local_or_argument(
				addr,
				static_cast<dwarf::lib::Dwarf_Off>(dieset_relative_ip) - 1, 
				&frame_base,
				&my_regs);
			if (ret) 
			{
				arg_obj->discovered_die = ret->second;
				// ret.first is the number of bytes that addr was offset into the pointed-to local/arg
				arg_obj->object_start_addr = addr - ret->first;
				arg_obj->frame_base = frame_base;
				arg_obj->frame_return_addr = frame_ip; // because callee is the logical frame
				return 1; // 1 means "can stop now"
			}
			else std::cerr << "Did not match an actual parameter -- must be local variable." << std::endl;
		}
	}
	// if we got here, look for a local of the current frame
	auto frame_subp = image->find_subprogram_for_absolute_ip(frame_ip);
	if (!frame_subp)
	{
		std::cerr << "Warning: no debug info at bp=0x"			// HACK: we don't get 
			<< std::hex << frame_caller_sp << std::dec			// the callee sp, so quote
			<< "; object discovery may miss argument objects."	// current sp as callee bp
			<< std::endl;
		return 0;
	}
    process_image::addr_t dieset_base = image->get_dieset_base(frame_subp->get_ds());
    unw_word_t dieset_relative_ip = frame_ip - dieset_base;
    //unw_word_t dieset_relative_addr = reinterpret_cast<unw_word_t>(addr)
    // - reinterpret_cast<unw_word_t>(dieset_base);
    libunwind_regs my_regs(&frame_cursor); 
    dwarf::lib::Dwarf_Signed frame_base;
	// HACK: subtract 1 below; see comment above
    auto ret = frame_subp->contains_addr_as_frame_local_or_argument(
        addr,
        static_cast<dwarf::lib::Dwarf_Off>(dieset_relative_ip) - 1, 
        &frame_base, 
        &my_regs);
    if (ret) 
    {
        arg_obj->discovered_die = ret->second;
        // ret.first is the number of bytes that addr was offset into the pointed-to local/arg
        arg_obj->object_start_addr = addr - ret->first;
		arg_obj->frame_base = frame_base;
		arg_obj->frame_return_addr = frame_caller_ip; 
        return 1; // 1 means "can stop now"
    }
	else std::cerr << "Did not match a local variable -- giving up." << std::endl;
    return 0;
}

// FIXME: make cross-process-capable, and support multiple stacks        
int process_image::walk_stack(void *stack_handle, stack_frame_cb_t handler, void *handler_arg)
{
	/* We declare all our variables up front, in the hope that we can rely on
	 * the stack pointer not moving between getcontext and the sanity check.
	 * FIXME: better would be to write this function in C90 and compile with
	 * special flags. */
	unw_cursor_t cursor, saved_cursor, prev_saved_cursor;
	unw_word_t higherframe_sp = 0, sp, higherframe_ip = 0, callee_ip;
	int unw_ret;
	unw_word_t check_higherframe_sp;
	
	// sanity check
#ifdef UNW_TARGET_X86
	__asm__ ("movl %%esp, %0\n" :"=r"(check_higherframe_sp));
#else // assume X86_64 for now
	__asm__("movq %%rsp, %0\n" : "=r"(check_higherframe_sp));
#endif
	unw_ret = unw_getcontext(&this->unw_context);
	unw_init_local(&cursor, /*this->unw_as,*/ &this->unw_context);

    unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &higherframe_sp);
    assert(check_higherframe_sp == higherframe_sp);
    std::cerr << "Initial sp=0x" << std::hex << higherframe_sp << std::endl;
    unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &higherframe_ip);
    
    unw_word_t ip = 0;
	int step_ret;
    char name[100];
    
    int ret; // value returned by handler

    do
    {
        callee_ip = ip;
        prev_saved_cursor = saved_cursor;	// prev_saved_cursor is the cursor into the callee's frame 
        									// FIXME: will be garbage if callee_ip == 0
        saved_cursor = cursor; // saved_cursor is the *current* frame's cursor
        	// and cursor, later, becomes the *next* (i.e. caller) frame's cursor
        
    	/* First get the ip, sp and symname of the current stack frame. */
        unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &ip); assert(unw_ret == 0);
        unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &sp); assert(unw_ret == 0); // sp = higherframe_sp
		bzero(name, 100);
        unw_ret = unw_get_proc_name(&cursor, name, 100, NULL); 
        if (unw_ret != 0) strncpy(name, "(no name)", 100);
        /* Now get the sp of the next higher stack frame, 
         * i.e. the bp of the current frame. N
         
         * NOTE: we're still
         * processing the stack frame ending at sp, but we
         * hoist the unw_step call to here so that we can get
         * the bp of the next higher frame (without demanding that
         * libunwind provides bp, e.g. for code compiled with
         * -fomit-frame-pointer -- FIXME: does this work?). 
         * This means "cursor" is no longer current -- use 
         * saved_cursor for the remainder of this iteration!
         * saved_cursor points to the deeper stack frame. */
        int step_ret = unw_step(&cursor);
        if (step_ret > 0)
        {
        	unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &higherframe_sp); assert(unw_ret == 0);
        	unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &higherframe_ip); assert(unw_ret == 0);
        }
        else if (step_ret == 0)
        {
        	higherframe_sp = BEGINNING_OF_STACK;
            higherframe_ip = 0x0;
        }
        else
        {
        	// return value <1 means error
			// We return without calling the handler. This does mean that
			// the very top frame will not get handler'd
			ret = step_ret;
			break;
        }
        
        ret = handler(
		/* process_image *image             */ this,
		/* unw_word_t frame_sp              */ sp,
		/* unw_word_t frame_ip              */ ip,
		/* const char *frame_proc_name      */ name,
		/* unw_word_t frame_caller_sp       */ higherframe_sp,
		/* unw_word_t frame_caller_ip       */ higherframe_ip,
		/* unw_word_t frame_callee_ip       */ callee_ip,
		/* unw_cursor_t frame_cursor        */ saved_cursor,
		/* unw_cursor_t frame_callee_cursor */ prev_saved_cursor,
		/* void *arg                        */ handler_arg
		);
		
        if (ret == 1) break;

        assert(step_ret > 0 || higherframe_sp == BEGINNING_OF_STACK);
    } while (ret == 0 && higherframe_sp != BEGINNING_OF_STACK);
    return ret; //boost::shared_ptr<dwarf::spec::basic_die>();
#undef BEGINNING_OF_STACK
}

// struct find_subprogram_pred_arg
// {
// 	unw_word_t ip;
// };
// 
// static
// bool find_subprogram_pred(boost::shared_ptr<spec::basic_die> p_d, void *pred_arg)
// {
// 	return
//     	p_d->get_tag() == DW_TAG_subprogram
//     &&	boost::dynamic_pointer_cast<spec::subprogram_die>(p_d)->get_low_pc()
//     &&  boost::dynamic_pointer_cast<spec::subprogram_die>(p_d)->get_high_pc()
// }

boost::shared_ptr<dwarf::spec::with_dynamic_location_die>
process_image::discover_stack_object_remote(
	addr_t addr, 
	addr_t *out_object_start_addr,
	addr_t *out_frame_base,
	addr_t *out_frame_return_addr
)
{
	assert(false);
	cerr << "Stack object discovery failed for " << (void*)addr << endl;
	return boost::shared_ptr<dwarf::spec::with_dynamic_location_die>();
}

} // end namespace pmirror
