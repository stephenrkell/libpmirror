#ifndef LIBPROCESSIMAGE_OBJDISCOVER_H_
#define LIBPROCESSIMAGE_OBJDISCOVER_H_

struct __cake_alloc
{
    void *begin;
    size_t size;
    struct __cake_alloc *next;
};

typedef struct __cake_alloc alloc;

#define ALLOC_LIST_HEAD __cake_alloc_list_head
#define ALLOC_LIST_HEAD_SYM "__cake_alloc_list_head"

extern alloc *ALLOC_LIST_HEAD;
extern unsigned long recs_allocated;
extern int ready; /* ready to call into libprocessimage. */

/* debugging */
void print_head_alloc(void);

/* dynamic points-to debugging */
void print_guessed_region_type(void *img, void *begin, size_t size, const void *caller);

void *get_self_image(void);

#endif
