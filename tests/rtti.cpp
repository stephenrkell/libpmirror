#include <assert.h>
#include "librtti.h"

struct blah
{

};

int main(void)
{
	struct blah stack_blah;
	int stack_notblah;
	
	struct blah *p_heap_blah = (struct blah *) malloc(sizeof (struct blah));
	int *p_heap_notblah = (int *) malloc(sizeof (int));
	
	assert(is_only_a(&stack_blah, "blah"));
	assert(!is_only_a(&stack_notblah, "blah"));

	assert(is_only_a(p_heap_blah, "blah"));
	assert(!is_only_a(p_heap_notblah, "blah"));
	
	return 0;
}
