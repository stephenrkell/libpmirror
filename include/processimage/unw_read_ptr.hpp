#ifndef PMIRROR_UNW_READ_PTR_HPP_
#define PMIRROR_UNW_READ_PTR_HPP_

#include <libunwind.h>
#include <libunwind-ptrace.h>


/* This is a pointer-alike type which uses libunwind's memory accessors
 * rather than accessing memory directly. This allows access to a remote
 * process's address space as if it were local. Of course the remote 
 * process's ABI has to be compatible (wrt the type Target) with the local
 * process's ABI. Also, expressions involving multiple pointer hops (like
 * **foo or blah->bar->baz) won't work: you have to instantiate this class
 * around each intermediate pointer in turn. */
template <typename Target>
class unw_read_ptr
{

    unw_addr_space_t as;
    void *priv;
    Target *ptr;
    mutable Target buf;
public:
    typedef unw_read_ptr<Target> self_type;
    unw_read_ptr(unw_addr_space_t as, void *priv, Target *ptr) : as(as), priv(priv), ptr(ptr) {}
    Target operator*() const 
    { 
        Target tmp; 
        // simplifying assumption: either Target has a word-multiple size,
        // or is less than one word in size
        assert(sizeof (Target) < sizeof (unw_word_t)
        	|| sizeof (Target) % sizeof (unw_word_t) == 0); // simplifying assumption
        // tmp_base is just a pointer to tmp, cast to unw_word_t*
        unw_word_t *tmp_base = reinterpret_cast<unw_word_t*>(&tmp);
        
        // Handle the less-than-one-word case specially, for clarity
        if (sizeof (Target) < sizeof (unw_word_t))
        {
        	//std::cerr << "Read of size " << sizeof (Target) 
            //	<< " from unaligned address " << reinterpret_cast<void*>(ptr)
            //    << std::endl;
                
        	unw_word_t word_read;
            /* We can't trust access_mem not to access a whole word, 
             * so read the whole word and then copy it to tmp. */
            unw_word_t aligned_ptr 
            	= reinterpret_cast<unw_word_t>(ptr) & ~(sizeof (unw_word_t) - 1);
        	unw_get_accessors(as)->access_mem(as, 
	            aligned_ptr, // aligned read
                &word_read,
                0, // 0 means read, 1 means write
                priv);
            ptrdiff_t byte_offset = reinterpret_cast<char*>(ptr)
             - reinterpret_cast<char*>(aligned_ptr);
            //std::cerr << "Byte offset is " << byte_offset << std::endl;
            // now write to tmp directly
            tmp = *reinterpret_cast<Target*>(reinterpret_cast<char*>(&word_read) + byte_offset);
             
            return tmp;
        }
        else
        {
            // Now read memory one word at a time from the target address space
            for (unw_word_t *tmp_tgt = tmp_base;
        	    // termination condition: difference, in words,
                tmp_tgt - tmp_base < sizeof (Target) / sizeof (unw_word_t);
                tmp_tgt++)
            {
                off_t byte_offset // offset from ptr to the word we're currently reading
                 = reinterpret_cast<char*>(tmp_tgt) - reinterpret_cast<char*>(tmp_base);
                unw_get_accessors(as)->access_mem(as, 
                    reinterpret_cast<unw_word_t>(reinterpret_cast<char*>(ptr) + byte_offset), 
                    tmp_tgt,
                    0,
                    priv);
		    }            
            return tmp;
	    }	
    }
    // hmm... does this work? FIXME
    Target *operator->() const { this->buf = this->operator*(); return &this->buf; } 
    self_type& operator++() // prefix
    { ptr++; return *this; }
    self_type  operator++(int) // postfix ++
    { Target *tmp; ptr++; return self_type(as, priv, tmp); }
    self_type& operator--() // prefix
    { ptr++; return *this; }
    self_type  operator--(int) // postfix ++
    { Target *tmp; ptr--; return self_type(as, priv, tmp); }
    
    // we have two flavours of equality comparison: against ourselves,
    // and against unadorned pointers (risky, but useful for NULL testing)
    bool operator==(const self_type arg) { 
    	return this->as == arg.as
        && this->priv == arg.priv
        && this->ptr == arg.ptr; 
    }
    bool operator==(void *arg) { return this->ptr == arg; }
    
    bool operator!=(const self_type arg) { return !(*this == arg); }
    bool operator!=(void *arg) { return !(this->ptr == arg); }

	// default operator= and copy constructor work for us
    // but add another: construct from a raw ptr
    self_type& operator=(Target *ptr) { this->ptr = ptr; return *this; }
    self_type& operator+=(int arg) { this->ptr += arg; return *this; }
    self_type& operator-=(int arg) { this->ptr -= arg; return *this; }

    self_type operator+(int arg)
    { return self_type(as, priv, ptr + arg); }

    self_type operator-(int arg)
    { return self_type(as, priv, ptr - arg); }

    ptrdiff_t operator-(const self_type arg)
    { return this->ptr - arg.ptr; }
    
    operator void*() { return ptr; }
    
    /* Make this pointer-like thing also an iterator. */
    typedef std::random_access_iterator_tag iterator_category;
    typedef Target value_type;
    typedef ptrdiff_t difference_type;
    typedef Target *pointer;
    typedef Target& reference;
    

};

#endif
