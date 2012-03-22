#include <libelf/libelf.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

static Elf *elf;
static _Bool check_symbol_table(void);
static Elf_Scn *symtab_section;
static Elf32_Shdr *symtab_shdr;
static _Bool print_symbols(Elf *elf, Elf_Scn *scn, Elf32_Shdr *shdr);

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

int main(int argc, char **argv)
{
	assert(argc > 1); 
	
	char *filename = argv[1];
	
	if (elf_version(EV_CURRENT) == EV_NONE ) {
		/* library out of date */
		fprintf(stderr, "Elf library out of date!n");
		exit(-1);
	}

	int fd = open(argv[1], O_RDONLY);

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL){
        	 /*error*/
	}  

	check_symbol_table() && print_symbols(elf, symtab_section, symtab_shdr);

}
/* Check if Symbol 
Table 
exists */
static _Bool check_symbol_table(void)
{
	Elf_Scn *section = 0;
     int number = 0;
     while ((section = elf_nextscn(elf, section)) != 0) {
        char *name = 0;
        Elf32_Shdr *shdr;
        if ((shdr = elf32_getshdr (section)) != 0) {
                if (shdr->sh_type == SHT_SYMTAB) {
                    /* Change SHT_SYMTAB to SHT_DYNSYM
                     * to access the dynamic symbol table
                     */
                     printf("Found Symbol Table\n");
					 symtab_section = section;
					 symtab_shdr = shdr;
                     /* You can use the function given below to pri nt
                      * out the symbol table
                      * print_symbols(elf, section, shdr);
                      */
                      return TRUE;
                  }
         }
     }
     /* no symtab */
     return FALSE;
}

/* Given Elf header, Elf_Scn, and Elf32_Shdr 
 * print out the symbol table 
 */
static _Bool print_symbols(Elf *elf, Elf_Scn *scn, Elf32_Shdr *shdr)
 {
      Elf_Data *data;
      char *name;
      char *stringName;
      data = 0;
      int number = 0;
      if ((data = elf_getdata(scn, data)) == 0 || data->d_size == 0){
          /* error or no data */
          fprintf(stderr,"Section had no data!\n");
               exit(-1);
      }
      /*now print the symbols*/
      Elf32_Sym *esym = (Elf32_Sym*) data->d_buf;
      Elf32_Sym *lastsym = (Elf32_Sym*) ((char*) data->d_buf + 
		data->d_size);
      /* now loop through the symbol table and print it*/
      for (; esym < lastsym; esym++){
          if ((esym->st_value == 0) ||
                (ELF32_ST_BIND(esym->st_info)== STB_WEAK) ||
                (ELF32_ST_BIND(esym->st_info)== STB_NUM) ||
                (ELF32_ST_TYPE(esym->st_info)!= STT_FUNC)) 
                    continue;
           name = elf_strptr(elf,shdr->sh_link , (size_t)esym->st_name);
           if(!name){
                fprintf(stderr,"%s\n",elf_errmsg(elf_errno()));
                exit(-1);
           }
           printf("%d: %s\n",number++, name);
       }
	   
	   return TRUE;
}

