#define M61_DISABLE 1
#include "m61.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>

unsigned long long active_count;	// # active allocations
    unsigned long long active_size;	// # bytes in active allocations
    unsigned long long total_count;	// # total allocations
    unsigned long long total_size;	// # bytes in total allocations
    unsigned long long fail_count;	// # failed allocation attempts
    unsigned long long fail_size;	// # bytes in failed alloc attempts

#define headerhash 42
#define footerhash 10101

typedef struct m61_meta {
  int header;
  size_t size;
  bool inuse;
  const char *file;
  int line;
  bool prev_inuse;
  bool next_inuse;
  struct m61_meta *nxt;
  struct m61_meta *prv;
} m61_meta;

m61_meta *m61_find(void *ptr,m61_meta *m61_meta);

//for boundary checks?
typedef struct m61_footer {
  int footer;
} m61_footer;

struct m61_meta *root;
struct m61_statistics stat;

void *m61_malloc(size_t sz, const char *file, int line) {
    (void) file, (void) line;	// avoid uninitialized variable warnings
    
    char *ptr = NULL;
    unsigned short padding = abs(sz-sizeof(m61_meta));

    if(sizeof(m61_meta) + sz + padding >= sz)
      {
        ptr = malloc(padding + sizeof(m61_meta) + sz + sizeof(m61_footer));
      }

    if(!ptr)
    {
       stat.fail_count++;
       stat.fail_size += sz;
       
       return ptr;
    } else {
       struct m61_meta *meta = (m61_meta*) ((char*) ptr + padding);
       meta->size = sz;
       meta->header = headerhash;
       meta->inuse = true;
       meta->prv = NULL;
       meta->nxt = NULL;
       meta->file = file;
       meta->line = line;
 
      struct m61_footer foot = {0};
       foot.footer = footerhash;
       memmove(ptr + padding + sizeof(m61_meta) +sz, &foot, sizeof(m61_footer));
       
       if(!root)
         {
           root = meta;
           root->nxt = root->prv = NULL;
         }
       else
	 {
           root->nxt = meta;
	   meta->prv = root;
	   //printf("SET Meta %p Prev %p! PrevNext %p\n", meta, meta->prv,meta->prv->nxt);
           root = meta;
	 }
       
       stat.active_count++;
       stat.active_size += sz;
       stat.total_count++;
       stat.total_size += sz;
       return (void*) ((char*) ptr + (sizeof(m61_meta) + padding));
    }
}

void m61_free(void *ptr, const char *file, int line) {
    (void) file, (void) line;	// avoid uninitialized variable warnings
    
    m61_meta *meta = ((struct m61_meta*) ptr - 1);
   
    if(stat.total_count > 0 && !meta->inuse )
      {
	if(meta->header != headerhash)
	  {
            m61_meta *pointer = m61_find(ptr, root);
	    if(stat.active_count == 0||!pointer)
         printf("MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated",                      file, line, ptr); 
            else
            {
	      size_t offt = ((size_t) ptr - (size_t) pointer)-sizeof(m61_meta);
	 printf("MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated\n  %s:%d: %p: %p is %d bytes inside a %zu byte region allocated here", 
		file, line , ptr, pointer->file, pointer->line, pointer, ptr, offt,pointer->size);
            }

          }
        else 
	  {
           printf("MEMORY BUG: %s:%d: double free of pointer %p\n  %s:%d: pointer %p previously freed here", 
		  file, line, ptr, meta->file, meta->line, ptr);
          }
        abort();
      }
    if(stat.active_count == 0 || !ptr)
      {
	printf("MEMORY BUG: %s:%d: invalid free of pointer %p, not in heap", 
               file, line, ptr);
        abort();
      }
 
    if(meta->prv && meta->prv->nxt != meta)
      {
       printf("MEMORY BUG: %s:%d: invalid free of pointer %p, not allocated",                      file, line, ptr); 
       abort();
      }
    
    unsigned short padding = abs(meta->size-sizeof(m61_meta));

    meta->inuse = false;
    meta->file = file;
    meta->line = line;

    m61_footer *foot = ((char*) ptr + (meta->size));
    if(foot->footer != footerhash)
      {
       printf("MEMORY BUG %s:%d: detected wild write during free of pointer %p"
                ,file, line, ptr); 
       abort();
      }

    stat.active_count--;
    stat.active_size -= meta->size;
    
    if( root == meta )
      {
	if( root->prv != NULL )
	  {
            root->prv->nxt = NULL;
            root = root->prv;
	  }
        else
          root = NULL;
      }
    else
      {
        if(meta->nxt) 
	  meta->nxt->prv = meta->prv;
        if(meta->prv)
	  meta->prv->nxt = meta->nxt;
      }
  
    //(m61_meta*) ((char*) ptr + padding);
    free((void*) ((char*) ((struct m61_meta*) ptr - 1) - padding));
    //free((void*) ((char*) ptr - (sizeof(m61_meta) + padding)));
}

m61_meta *m61_find(void *ptr, m61_meta *node) {
  if (!node) return NULL;
  if ((size_t)ptr > (size_t)node)
    { 
      size_t offset = ((size_t) ptr - (size_t) node);
      struct m61_meta *meta = (m61_meta*) ((char *) ptr - offset);
      return meta;
    }
  else
    m61_find (ptr, root->prv);
}

void *m61_realloc(void *ptr, size_t sz, const char *file, int line) {
    (void) file, (void) line;	// avoid uninitialized variable warnings
    // Your code here.
    void *new_ptr = NULL;
    if (sz != 0)
      new_ptr = m61_malloc(sz, file, line);
    if (ptr != NULL && new_ptr !=NULL) {
      size_t old_sz = (*((struct m61_meta*) ptr-1)).size;
      if (old_sz < sz)
	memcpy(new_ptr, ptr, old_sz);
      else
        memcpy(new_ptr, ptr, sz);
    }
    if(ptr != NULL)
      m61_free(ptr, file, line);
    return new_ptr;
}

void *m61_calloc(size_t nmemb, size_t sz, const char *file, int line) {
    (void) file, (void) line;	// avoid uninitialized variable warnings
    // Your code here.
    void *ptr = NULL;
    size_t result_size = sz * nmemb;

    if (result_size >= nmemb) 
      ptr = m61_malloc(result_size, file, line);
    if (ptr != NULL)
      memset(ptr, 0, sz * nmemb);
    else
     {
         stat.fail_count++;
         stat.fail_size += sz * nmemb;
     }

     return ptr;
}

void m61_getstatistics(struct m61_statistics *stats) {
    // Stub: set all statistics to 0
    memset(stats, 0, sizeof(struct m61_statistics));
    // Your code here.
    *stats = stat;
}

void m61_printstatistics(void) {
    struct m61_statistics stats;
    m61_getstatistics(&stats);

    printf("malloc count: active %10llu   total %10llu   fail %10llu\n\
malloc size:  active %10llu   total %10llu   fail %10llu\n",
	   stats.active_count, stats.total_count, stats.fail_count,
	   stats.active_size, stats.total_size, stats.fail_size);
}

void m61_printleakreport(void) {

     m61_meta* temp = root;
     while(temp!=NULL)
     {
       printf("LEAK CHECK: %s:%d: allocated object %p with size %zu\n",
         temp->file, temp->line, temp, temp->size);
       temp = temp->prv;
     };
}
