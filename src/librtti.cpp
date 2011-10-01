#include "librtti.h"
#include "process.hpp"
#include "libreflect.hpp"
#include <set>
#include <cassert>

using namespace pmirror;
using boost::shared_ptr;
using boost::dynamic_pointer_cast;
using boost::optional;
using std::set;
using dwarf::spec::type_die;
using dwarf::spec::subprogram_die;

set<shared_ptr<type_die> > types_keepalive;

/* */
struct rtti *rtti_for_typestr(const char *typestr, void *caller)
{
	process_image::addr_t addr = reinterpret_cast<process_image::addr_t>(caller);
	auto p_cu_die = self.find_compile_unit_for_absolute_ip(addr);
	assert(p_cu_die);
	
	// HACK: need not be toplevel
	auto found = p_cu_die->named_child(typestr); 
	assert(found);
	
	auto p_type_die = dynamic_pointer_cast<type_die>(found);
	assert(p_type_die);
	types_keepalive.insert(p_type_die);
	
	return reinterpret_cast<struct rtti *>(p_type_die.get());
}
static shared_ptr<type_die> die_for_rtti(struct rtti *r)
{
	return dynamic_pointer_cast<type_die>(
		reinterpret_cast<dwarf::spec::type_die*>(r)
			->shared_from_this()
		);
}

/* Type-checking prototypes. */
static _Bool __rtti_is_a_t(void *obj, struct rtti *type, void *caller)
{
	assert(false);
}
_Bool is_a(void *obj, const char *typestr)
{
	void *caller = __builtin_return_address(0);
	return __rtti_is_a_t(obj, rtti_for_typestr(typestr, caller), caller);
}

_Bool is_a_t(void *obj, struct rtti *type)
{
	void *caller = __builtin_return_address(0);
	return __rtti_is_a_t(obj, type, caller);
}

static _Bool __rtti_is_only_a_t(void *obj, struct rtti *type, void *caller)
{
	/* This is the simplest. We can implement it directly.
	 * FIXME: have we actually implemented "is exactly a" semantics? */
	process_image::addr_t caller_addr = reinterpret_cast<process_image::addr_t>(caller);
	process_image::addr_t obj_addr = reinterpret_cast<process_image::addr_t>(obj);
	
	shared_ptr<type_die> t = die_for_rtti(type);
	assert(t);
	
	auto p_caller_cu_die = self.find_compile_unit_for_absolute_ip(caller_addr);
	assert(p_caller_cu_die);
	
	process_image::addr_t obj_start;
	shared_ptr<dwarf::spec::basic_die> discovered_descr
	 = self.discover_object_descr(obj_addr, shared_ptr<type_die>(), &obj_start);
	 
	// we may have got a subprogram. Rule this out
	assert(!dynamic_pointer_cast<subprogram_die>(discovered_descr));
	auto p_type = dynamic_pointer_cast<type_die>(discovered_descr);
	assert(p_type);
	
	bool is_exact_base = (obj_addr == obj_start);
	bool is_rep_compatible = p_type->is_rep_compatible(t);
	bool is_like_named = p_type->get_name() && t->get_name()
		&&  (*p_type->get_name() == *t->get_name());
	
	return is_exact_base && is_rep_compatible && is_like_named;
}
_Bool is_only_a(void *obj, const char *typestr)
{
	void *caller = __builtin_return_address(0);
	return __rtti_is_only_a_t(obj, rtti_for_typestr(typestr, caller), caller);
}
_Bool is_only_a_t(void *obj, struct rtti *type)
{
	void *caller = __builtin_return_address(0);
	return __rtti_is_only_a_t(obj, type, caller);
}

/* ... could have is_no_more_than_a, but seems less useful */

static _Bool 
__rtti_is_type_unifiable_with_t(
	void *obj1, 
	void *obj2, 
	struct rtti *unifier_lowerbound_t, 
	void *caller)
{
	assert(false);
}
_Bool is_type_unifiable_with(void *obj1, void *obj2, const char *unifier_lowerbound)
{
	void *caller = __builtin_return_address(0);
	return __rtti_is_type_unifiable_with_t(obj1, obj2, 
		rtti_for_typestr(unifier_lowerbound, caller), caller);
}
_Bool is_type_unifiable_with_t(void *obj1, void *obj2, struct rtti *unifier_lowerbound_type)
{
	void *caller = __builtin_return_address(0);
	return __rtti_is_type_unifiable_with_t(obj1, obj2, unifier_lowerbound_type, caller);
}

/* Type identification prototypes */
struct rtti *type_of(void *obj)
{
	assert(false);
}
void iterate_types_of(void *obj, void (*called_per_type)(void *, void *), void *arg)
{
	assert(false);
}
void iterate_permitted_adjustments_of(void *obj, 
	void (*called_per_adjustment)(void *, size_t off, struct rtti *t), void *arg)
{
	assert(false);
}

/* Helpers. */
void *allocation_site_of(void *obj)
{
	assert(false);
}
