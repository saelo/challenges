/*
 * Shitty heap allocator implemenation and buggy client code.
 *
 * (c) 2014 Samuel Groß
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

/* ------------------------------ *\
|*              Misc.             *|
\* ------------------------------ */
void die(const char* msg)
{
    perror(msg);
    exit(errno);
}

/* ------------------------------ *\
|*         Data Structures        *|
\* ------------------------------ */
struct chunk {
    size_t size;
    struct chunk* flink;
    struct chunk* blink;
};

typedef struct chunk* chunkptr;

struct chunk freelist = {
    .size  = 0,
    .flink = &freelist,
    .blink = &freelist
};

/* ------------------------------ *\
|*           Allocator            *|
\* ------------------------------ */
/* sizes and alignments */
#define HEAPSIZE        0x10000
#define SIZE_SZ         (sizeof(size_t))
#define MINSIZE         (sizeof(struct chunk))
#define ALIGN_MASK      0xf

/* list operations */
#define frontlink(e, h)                             \
{                                                   \
    (e)->flink = (h)->flink;                        \
    (e)->blink = (h);                               \
    (h)->flink->blink = (e);                        \
    (h)->flink = (e);                               \
}

#define backlink(e, h)                              \
{                                                   \
    (e)->blink = (h)->blink;                        \
    (e)->flink = (h);                               \
    (h)->blink->flink = (e);                        \
    (h)->blink = (e);                               \
}

#define unlink(e)                                   \
{                                                   \
    (e)->blink->flink = (e)->flink;                 \
    (e)->flink->blink = (e)->blink;                 \
}

/* convert chunk pointers to user pointers and vice versa */
#define chunk2user(p)\
    ((void*)((char*)(p) + SIZE_SZ))
#define user2chunk(p)\
    ((chunkptr)((char*)(p) - SIZE_SZ))

/* create a new chunk at an offset from another chunk */
#define chunk_at_offset(p, o)\
    ((chunkptr)((char*)(p) + (o)))

/* calculate the chunk size for the requested size */
#define req2size(req)\
      ((req) + SIZE_SZ <= MINSIZE ?  MINSIZE : \
          (((req) + SIZE_SZ + ALIGN_MASK) & ~(ALIGN_MASK)))


void init_allocator()
{
    chunkptr first;
    void* ptr = mmap((void*)0x31337000, HEAPSIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED)
        die("mmap()");

    first = ptr;
    first->size = HEAPSIZE;
    frontlink(first, &freelist);
}

void* _malloc(size_t size)
{
    size = req2size(size);
    chunkptr leftover, curr = &freelist;
    do {
        if (curr->size >= size) {
            unlink(curr);

            if (curr->size - size >= MINSIZE) {
                /* split the current chunk */
                leftover = chunk_at_offset(curr, size);
                leftover->size = curr->size - size;
                curr->size = size;
                backlink(leftover, &freelist);
            }

            return chunk2user(curr);
        }
    } while ((curr = curr->flink) != &freelist);

    return NULL;
}

void _free(void* ptr)
{
    chunkptr new = user2chunk(ptr);
    /* I don't even Coalescing */
    frontlink(new, &freelist);
}

void* _realloc(void* ptr, size_t size)
{
    size_t origsize = user2chunk(ptr)->size;
    if (origsize >= size)
        return ptr;

    void* new = _malloc(size);
    if (!new)
        return NULL;
    memcpy(new, ptr, origsize);
    _free(ptr);
    return new;
}

/*
 * Do this here so the code above (notable die())
 * still uses the libc malloc.
 */
#define malloc _malloc
#define free _free
#define realloc _realloc

/* ------------------------------ *\
|*          Client Code           *|
\* ------------------------------ */
#define MAX_ANIMALS 1000

/* ----- Data Structures ----- */
struct animal {
    char name[100];
};

struct animal* compounds[MAX_ANIMALS];
int animalcount = 0;

/* ----- Animal related function ----- */
int find_free_compound()
{
    int i;
    for (i = 0; i < MAX_ANIMALS; i++)
        if (!compounds[i])
            return i;
    return -1;
}

struct animal* new_cat()
{
    struct animal* new = malloc(sizeof(struct animal));
    if (!new) {
        fprintf(stderr, "Out of memory!\n");
        exit(-1);
    }
    memset(new, 0, sizeof(struct animal));
    return new;
}

void cat_speak()
{
    puts("meooooowww");
}

void cat_print()
{
    char* cat = ""
                "     )\\._.,--....,'``.      \n"
                "    /;   _.. \\   _\\  (`._ ,.\n"
                "   `----(,_..'--(,_..'`-.;.'\n";
    puts(cat);
}

/* ----- I/O ----- */
char* readline(const char* prompt)
{
    char c;
    size_t i = 0, curr_size = 1024;
    char* input = malloc(1024);

    write(1, prompt, strlen(prompt));

    while ((c = getchar()) != EOF) {
        if (c == '\n') {
            input[i] = 0;
            return input;
        }
        input[i] = c;
        i++;
        if (i+1 >= curr_size) {
            curr_size *= 2;
            char* tmp = realloc(input, curr_size);
            if (!tmp) {
                fprintf(stderr, "Out of memory!");
                exit(-1);
            }
            input = tmp;
        }
    }

    return NULL;
}

/* ----- Handlers ----- */
void do_new(int argc, char** argv)
{
    int compound;
    struct animal* new;

    if (argc < 2)
        return;

    if (animalcount >= MAX_ANIMALS) {
        puts("All compounds filled!");
        return;
    }

    if (strcmp(argv[0], "cat") == 0) {
        new = new_cat();
    } else {
        printf("Unknown animal: %s\n", argv[0]);
        return;
    }

    strcpy(new->name, argv[1]);
    compound = find_free_compound();
    compounds[compound] = new;
    animalcount++;
}

void do_list()
{
    int i;
    for (i = 0; i < MAX_ANIMALS; i++)
        if (compounds[i])
            printf("%i : %s\n", i, compounds[i]->name);
}

void do_set_free(int argc, char** argv)
{
    unsigned int num;
    if (argc < 1)
        return;
    num = strtoul(argv[0], NULL, 10);
    if (num < MAX_ANIMALS && compounds[num]) {
        free(compounds[num]);
        compounds[num] = NULL;
        animalcount--;
    } else {
        puts("There's no animal in that compound");
    }
}

void do_speak(int argc, char** argv)
{
    unsigned int num;
    if (argc < 1)
        return;
    num = strtoul(argv[0], NULL, 10);
    if (num < MAX_ANIMALS && compounds[num]) {
        printf("%s says: ", compounds[num]->name);
        cat_speak();
    } else {
        puts("There's no animal in that compound");
    }
}

void do_print(int argc, char** argv)
{
    unsigned int num;
    if (argc < 1)
        return;
    num = strtoul(argv[0], NULL, 10);
    if (num < MAX_ANIMALS && compounds[num]) {
        printf("%s\n", compounds[num]->name);
        cat_print();
    } else {
        puts("There's no animal in that compound");
    }
}

/* ----- Main Logic ----- */
#define MAX_ARGS 10
void mainloop()
{
    int argc, running = 1;
    char *input, *argv[MAX_ARGS], *sp1, *sp2, *line, cmd;

    while (running) {
        input = readline("> ");
        if (!input)
            break;

        line = strtok_r(input, ";", &sp1);
        while (line) {
            cmd = line[0];
            strtok_r(line, " ", &sp2);

            for (argc = 0; argc < MAX_ARGS; argc++) {
                argv[argc] = strtok_r(NULL, " ", &sp2);
                if (!argv[argc])
                    break;
            }

            switch (cmd) {
            case 'n':
                do_new(argc, argv);
                break;
            case 'f':
                do_set_free(argc, argv);
                break;
            case 's':
                do_speak(argc, argv);
                break;
            case 'p':
                do_print(argc, argv);
                break;
            case 'l':
                do_list();
                break;
            case 'q':
                running = 0;
                break;
            default:
                printf("Unknown command '%c'\n", cmd);
            }
            line = strtok_r(NULL, ";", &sp1);
        }
        free(input);
    }

    exit(0);
}

int main()
{
    init_allocator();

    puts("Welcome to ZooControlCenter v. 0.1!");

    mainloop();

    return 0;
}
