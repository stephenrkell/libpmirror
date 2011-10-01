#include "process.hpp"
#include <fstream>
#include <sstream>
#include <cstring>

namespace pmirror {

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

boost::shared_ptr<dwarf::spec::with_dynamic_location_die>
process_image::discover_stack_object(addr_t addr, addr_t *out_object_start_addr/*,
	unw_word_t top_frame_sp, unw_word_t top_frame_ip, unw_word_t top_frame_retaddr,
    const char *top_frame_fn_name*/)
{
    if (m_pid == getpid())
    {
    	/* use the local version */
        return discover_stack_object_local(addr, out_object_start_addr);
    }
    else
    {
    	/* use the remote version */
        return discover_stack_object_remote(addr, out_object_start_addr);
    }
}

boost::shared_ptr<dwarf::spec::with_dynamic_location_die>
process_image::discover_stack_object_local(addr_t addr, addr_t *out_object_start_addr)
{
	stack_object_discovery_handler_arg arg
     = {addr, boost::shared_ptr<dwarf::spec::with_dynamic_location_die>(), 0};
	walk_stack(NULL, stack_object_discovery_handler, &arg);
    // forward output argument
    if (out_object_start_addr) *out_object_start_addr = arg.object_start_addr;
    // extract and return return value
    return arg.discovered_die;
}

int stack_print_handler(process_image *image,
		unw_word_t frame_sp, unw_word_t frame_ip, 
		const char *frame_proc_name,
		unw_word_t frame_caller_sp,
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
		unw_word_t frame_callee_ip,
        unw_cursor_t frame_cursor,
        unw_cursor_t frame_callee_cursor,
        void *arg)
{
	// DEBUG: print the frame
	stack_print_handler(image, frame_sp, frame_ip, frame_proc_name, 
    	frame_caller_sp, frame_callee_ip, 
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
        	<< " appears to be in frame " << frame_proc_name << std::endl;
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
        	process_image::addr_t dieset_base = image->get_dieset_base(callee_subp->get_ds());
        	unw_word_t dieset_relative_ip = frame_callee_ip - dieset_base;
        	//unw_word_t dieset_relative_addr = reinterpret_cast<unw_word_t>(addr)
        	// - reinterpret_cast<unw_word_t>(dieset_base);
        	libunwind_regs my_regs(&frame_callee_cursor); 
        	dwarf::lib::Dwarf_Signed frame_base;
        	// warn about variadic omission
        	if (callee_subp->is_variadic())
        	{
				std::cerr << "Warning: unwinding varargs frame at bp=0x" // HACK: we don't get 
					<< std::hex << frame_sp << std::dec                  // the callee sp, so quote
					<< "; object discovery may miss objects in this frame."   // current sp as callee bp
					<< std::endl;
        	}
        	auto ret = callee_subp->contains_addr_as_frame_local_or_argument(
        		addr,
            	static_cast<dwarf::lib::Dwarf_Off>(dieset_relative_ip), 
            	&frame_base,
            	&my_regs);
        	if (ret) 
        	{
        		arg_obj->discovered_die = ret->second;
            	// ret.first is the number of bytes that addr was offset into the pointed-to local/arg
            	arg_obj->object_start_addr = addr - ret->first;
        		return 1; // 1 means "can stop now"
        	}
		}
    }
    // if we got here, look for a local of the current frame
    auto frame_subp = image->find_subprogram_for_absolute_ip(frame_ip);
    if (!frame_subp)
	{
		std::cerr << "Warning: no debug info at bp=0x"           // HACK: we don't get 
			<< std::hex << frame_caller_sp << std::dec           // the callee sp, so quote
			<< "; object discovery may miss argument objects."   // current sp as callee bp
			<< std::endl;
		return 0;
	}
    process_image::addr_t dieset_base = image->get_dieset_base(frame_subp->get_ds());
    unw_word_t dieset_relative_ip = frame_ip - dieset_base;
    //unw_word_t dieset_relative_addr = reinterpret_cast<unw_word_t>(addr)
    // - reinterpret_cast<unw_word_t>(dieset_base);
    libunwind_regs my_regs(&frame_cursor); 
    dwarf::lib::Dwarf_Signed frame_base;
    auto ret = frame_subp->contains_addr_as_frame_local_or_argument(
        addr,
        static_cast<dwarf::lib::Dwarf_Off>(dieset_relative_ip), 
        &frame_base, 
        &my_regs);
    if (ret) 
    {
        arg_obj->discovered_die = ret->second;
        // ret.first is the number of bytes that addr was offset into the pointed-to local/arg
        arg_obj->object_start_addr = addr - ret->first;
        return 1; // 1 means "can stop now"
    }
    return 0;
}
        
int process_image::walk_stack(void *stack_handle, stack_frame_cb_t handler, void *handler_arg)
{
	// FIXME: make cross-process-capable, and support multiple stacks
	unw_cursor_t cursor, saved_cursor, prev_saved_cursor;
    int unw_ret;
    unw_ret = unw_getcontext(&this->unw_context);
    unw_init_local(&cursor, /*this->unw_as,*/ &this->unw_context);
    
	unw_word_t prevframe_sp = 0, sp/*, prevframe_ip = 0*/, callee_ip;
    
	// sanity check
    unw_word_t check_prevframe_sp;
#ifdef UNW_TARGET_X86
    __asm__ ("movl %%esp, %0\n" :"=r"(check_prevframe_sp));
#else // assume X86_64 for now
	__asm__("movq %%rsp, %0\n" : "=r"(check_prevframe_sp));
#endif
    unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &prevframe_sp);
    assert(check_prevframe_sp == prevframe_sp);
    std::cerr << "Initial sp=0x" << std::hex << prevframe_sp << std::endl;
    
    unw_word_t ip = 0;
	int step_ret;
    char name[100];
    
    int ret; // value returned by handler

/* define BEGINNING_OF_STACK  -- note that this is just a sentinel and doesn't have 
 * to be accurate! Let's make sure it's at least as high as the first stack loc though. */
#ifdef UNW_TARGET_X86
#define BEGINNING_OF_STACK 0xbfffffff
#else // assume X86_64 for now
#define BEGINNING_OF_STACK 0x7fffffffffff
#endif
    do
    {
        callee_ip = ip;
        prev_saved_cursor = saved_cursor;	// prev_saved_cursor is the cursor into the callee's frame 
        									// FIXME: will be garbage if callee_ip == 0
        saved_cursor = cursor; // saved_cursor is the *current* frame's cursor
        	// and cursor, later, becomes the *next* (i.e. caller) frame's cursor
        
    	/* First get the ip, sp and symname of the current stack frame. */
        unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &ip); assert(unw_ret == 0);
        unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &sp); assert(unw_ret == 0); // sp = prevframe_sp
        unw_ret = unw_get_proc_name(&cursor, name, 100, NULL); 
        if (unw_ret != 0) strncpy(name, "(no name)", 100);
        /* Now get the sp of the previous stack frame, 
         * i.e. the bp of the current frame. N
         
         * NOTE: we're still
         * processing the stack frame ending at sp, but we
         * hoist the unw_step call to here so that we can get
         * the bp of the previous frame (without demanding that
         * libunwind provides bp, e.g. for code compiled with
         * -fomit-frame-pointer -- FIXME: does this work?). 
         * This means "cursor" is no longer current -- use 
         * saved_cursor for the remainder of this iteration!
         * saved_cursor points to the deeper stack frame. */
        int step_ret = unw_step(&cursor);
        if (step_ret > 0)
        {
        	unw_ret = unw_get_reg(&cursor, UNW_REG_SP, &prevframe_sp); assert(unw_ret == 0);
        	//unw_ret = unw_get_reg(&cursor, UNW_REG_IP, &prevframe_ip); assert(unw_ret == 0);
        }
        else if (step_ret == 0)
        {
        	prevframe_sp = BEGINNING_OF_STACK;
            //prevframe_ip = 0x0;
        }
        else
        {
        	assert(false); // what does a retval < 0 mean?
        }
        
        ret = handler(this, sp, ip, name, prevframe_sp, callee_ip, 
        	saved_cursor, prev_saved_cursor, handler_arg); 
        if (ret == 1) break;
       
        assert(step_ret > 0 || prevframe_sp == BEGINNING_OF_STACK);
    } while (ret == 0 && prevframe_sp != BEGINNING_OF_STACK);
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
process_image::discover_stack_object_remote(addr_t addr, addr_t *out_object_start_addr)
{
	assert(false);
	return boost::shared_ptr<dwarf::spec::with_dynamic_location_die>();
}

} // end namespace pmirror
