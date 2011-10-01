#ifdef __cplusplus
#include <cstdlib>
typedef bool _Bool;
extern "C" {
#else
#include <stdlib.h>
#endif

struct rtti; /* opaque */

/* Type-checking prototypes. */
_Bool is_a(void *obj, const char *typestr);
_Bool is_a_t(void *obj, struct rtti *type);

_Bool is_only_a(void *obj, const char *typestr);
_Bool is_only_a_t(void *obj, struct rtti *type);

/* ... could have is_no_more_than_a, but seems less useful */

_Bool is_type_unifiable_with(void *obj1, void *obj2, const char *unifier_lowerbound); 
_Bool is_type_unifiable_with_t(void *obj1, void *obj2, struct rtti *unifier_lowerbound_type);

/* Type identification prototypes */
struct rtti *type_of(void *obj);
void iterate_types_of(void *obj, void (*called_per_type)(void *, void *), void *arg);
void iterate_permitted_adjustments_of(void *obj, 
	void (*called_per_adjustment)(void *, size_t off, struct rtti *t), void *arg);

/* Helpers. */
void *allocation_site_of(void *obj);

#ifdef __cplusplus
} /* end extern "C" */
#endif
