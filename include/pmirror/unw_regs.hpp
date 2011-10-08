#ifndef PMIRROR_UNW_REGS_HPP_
#define PMIRROR_UNW_REGS_HPP_

#include <libunwind.h>
#include <libunwind-ptrace.h>

#include <dwarfpp/attr.hpp>
#include <dwarfpp/regs.hpp>

namespace pmirror {

/* Register access implementation using libunwind. Instances may be 
 * passed to dwarf::lib::evaluator. */
class libunwind_regs : public dwarf::lib::regs
{
    unw_cursor_t *c;
public:
    dwarf::lib::Dwarf_Signed get(int i)
    {
        unw_word_t regval;
        switch(i)
        {
#ifdef UNW_TARGET_X86
            case DWARF_X86_EAX: unw_get_reg(c, UNW_X86_EAX, &regval); break;
			case DWARF_X86_EDX: unw_get_reg(c, UNW_X86_EDX, &regval); break;
			case DWARF_X86_ECX: unw_get_reg(c, UNW_X86_ECX, &regval); break;
			case DWARF_X86_EBX: unw_get_reg(c, UNW_X86_EBX, &regval); break;
			case DWARF_X86_ESI: unw_get_reg(c, UNW_X86_ESI, &regval); break;
            case DWARF_X86_EDI: unw_get_reg(c, UNW_X86_EDI, &regval); break;
            case DWARF_X86_EBP: unw_get_reg(c, UNW_X86_EBP, &regval); 
                //std::cerr << "read EBP as 0x" << std::hex << regval << std::endl;
                break;
            case DWARF_X86_ESP: unw_get_reg(c, UNW_X86_ESP, &regval); 
                //std::cerr << "read ESP as 0x" << std::hex << regval << std::endl;                    
                break;
            case DWARF_X86_EIP: unw_get_reg(c, UNW_X86_EIP, &regval); break;
            case DWARF_X86_EFLAGS: unw_get_reg(c, UNW_X86_EFLAGS, &regval); break;
            case DWARF_X86_TRAPNO: unw_get_reg(c, UNW_X86_TRAPNO, &regval); break;
#endif
#ifdef UNW_TARGET_X86_64
			case DWARF_X86_64_RAX: unw_get_reg(c, UNW_X86_64_RAX, &regval); break;
			case DWARF_X86_64_RDX: unw_get_reg(c, UNW_X86_64_RDX, &regval); break;
			case DWARF_X86_64_RCX: unw_get_reg(c, UNW_X86_64_RCX, &regval); break;
			case DWARF_X86_64_RBX: unw_get_reg(c, UNW_X86_64_RBX, &regval); break;
			case DWARF_X86_64_RSI: unw_get_reg(c, UNW_X86_64_RSI, &regval); break;
			case DWARF_X86_64_RDI: unw_get_reg(c, UNW_X86_64_RDI, &regval); break;
			case DWARF_X86_64_RBP: unw_get_reg(c, UNW_X86_64_RBP, &regval); 
                //std::cerr << "read RBP as 0x" << std::hex << regval << std::endl; break;
			case DWARF_X86_64_RSP: unw_get_reg(c, UNW_X86_64_RSP, &regval); 
                //std::cerr << "read RSP as 0x" << std::hex << regval << std::endl; break;
			case DWARF_X86_64_R8: unw_get_reg(c, UNW_X86_64_R8, &regval); break;
			case DWARF_X86_64_R9: unw_get_reg(c, UNW_X86_64_R9, &regval); break;
			case DWARF_X86_64_R10: unw_get_reg(c, UNW_X86_64_R10, &regval); break;
			case DWARF_X86_64_R11: unw_get_reg(c, UNW_X86_64_R11, &regval); break;
			case DWARF_X86_64_R12: unw_get_reg(c, UNW_X86_64_R12, &regval); break;
			case DWARF_X86_64_R13: unw_get_reg(c, UNW_X86_64_R13, &regval); break;
			case DWARF_X86_64_R14: unw_get_reg(c, UNW_X86_64_R14, &regval); break;
			case DWARF_X86_64_R15: unw_get_reg(c, UNW_X86_64_R15, &regval); break;
			case DWARF_X86_64_RIP: unw_get_reg(c, UNW_X86_64_RIP, &regval); break;
#endif
            default:
                throw dwarf::lib::Not_supported("unsupported register number");
        }
        return regval;
    }
    libunwind_regs(unw_cursor_t *c) : c(c) {}
};

}

#endif
