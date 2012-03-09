#include <iostream>

#include <libreflect.hpp>

using pmirror::process_image;

struct foo 
{
	int x;
    double y;
} global;

static int a(foo arg1, int arg2);
static int b(int arg1);
static int c(void *arg);
static int a(foo arg1, int arg2)
{
	struct
    {
    	int xyzzy;
        int plugh;
    } myvar;
    b(arg2);
	return 20;
}

static int b(int arg1)
{
	foo it = {1, 2.0};
    c(&it);
    c(&arg1);
}

static int c(void *arg)
{
	process_image::addr_t out_object_start_addr = 0;
	process_image::addr_t out_frame_base = 0;
	process_image::addr_t out_frame_return_addr = 0;
    	std::cout << "Address of first local variable in c() is " 
		<< &out_object_start_addr
		<< std::endl;
	std::cout << "Discovering object at " << arg << std::endl;// " to have typeinfo at " << 
	auto discovered
	 = pmirror::self.discover_stack_object(
		reinterpret_cast<process_image::addr_t>(arg), 
		&out_object_start_addr,
		&out_frame_base,
		&out_frame_return_addr
	);
	assert(discovered);
	std::cout << *discovered << std::endl;

	return 0;
}

int main(int argc, char **argv);
int main(int argc, char **argv)
{
	pmirror::self.update();
	a(global /* copied */, 42);
    return 0;
}
