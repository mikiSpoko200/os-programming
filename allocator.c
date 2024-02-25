/*
 * # Oświadczenia
 *
 * Ja, Mikołaj Depta (328690), oświadczam że całość poniższego kodu została
 * napisana przeze mnie osobiście. Bazując na wiedzy zdobytej na wykładzie,
 * ćwiczeniach oraz wyczytanych z książki "Computer Systems. A Programmer’s
 * Perspective".
 *
 * Reszta pliku opisana jest w języku angielskim.
 *
 * # Brief description
 *
 * My implementation of memory allocator uses Segregated fits algorithm
 * with explicit doubly linked lists and first fit allocation scheme and
 * optimised footer's.
 *
 * # Assumptions
 *
 * 1. Some addresses that belong to the heap may not fit into 32-bit word.
 * 2. Heap is a contiguous chunk of memory with size of at most 4GB.
 * 3. Allocated blocks must be aligned to 16 bytes (ALIGNMENT).
 *
 * # Block layout
 *
 * Each block's size is a multiple of 16 bytes.
 * I use 3 special block formats in my implementation:
 * - Free blocks - free blocks are blocks that used freed and are ready for
 *                 another allocation.
 * - Used blocks - block that is currently in used.
 * - Sentinel block - special type of block that is allocated at the very
 *                    beginning of the heap. It serves dual purpose.
 *                    First, being a special free list node that signifies end /
 * start of the list. Secondly, it has special layout which when allocated at
 * the beginning of the heap will align it.
 *
 * ## Block metadata
 *
 * Common for all block layouts are block header metadata which is always
 * present. Header contains flags that store block's type, size and other
 * information. For more details please see Elaboration in the note below.
 *
 * ## Free block
 *
 * Layout of the free block is as follows. Minimal block consists of 16 bytes.
 * 4 - header metadata
 * 4 - previous list node offset
 * 4 - next list node offset
 * 4 - footer metadata
 *
 * ```
 * |    32 bits      |    32 bits    |    32 bits    |  ...   |      32 bits |
 * | header metadata |   list prev   |   list next   | unused | footer metadata
 * |
 * ```
 *
 * Due to assumption about heaps size free lists use 32-bit unsigned integer
 * offsets from the beginning of the heap instead of full 64-bit pointers.
 * This along with optimised pointers allows for more efficient storage.
 *
 * ## Used block
 *
 * Used block contains metadata and right after that begins 16 byte aligned
 * payload section which is data that is returned to the user.
 *
 * ```
 * |    32 bits      |   ...   |
 * | header metadata | payload |
 * ```
 *
 * ## Sentinel block
 *
 * Memory returned from mmap is guaranteed to be page aligned.
 * Block payload must be 16 bytes aligned, so when metadata is included this
 * means that at the beginning heap must be padded by 12 bytes. That's the
 * reason behind the sentinel's layout.
 *
 * ```
 * |     32 bits     | 32 bits |     32 bits     |
 * | header metadata | unused  | footer metadata |
 * ```
 *
 * # Footnotes
 *
 * One Allocator to rule them all!
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "mm.h"
#include "memlib.h"

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

/* # Elaboration
 *
 * block size - number in bytes which is the sum of sizes of the block's
 * metadata and payload. block metadata - part of block that contains the
 * information needed by the memory manager to organize and interpret the heap.
 * It includes block's header and heap structure information. block header -
 * part of metadata which is always present. It contains the bare essential
 * information needed to handle the block that is:
 *    - block size - size of block divided by 16 bytes.
 *      Blocks are allocated in the multiples of ALIGNMENT.
 *      Based on assumptions 2. and 4. we need 28 bits to represent all possible
 *      block sizes.
 *    - is_used - a bit filed that informs if block is used
 *      (0 - not used, 1 - used)
 *    - is_sentinel - A bit that signifies that a block is a free list sentinel.
 *    - is_prev_free - a bit field - signifies that the previous block is free.
 * block footer - Footers only matter for coalescing with an in memory adjacent
 *  blocks.
 *  I'm using an optimised version of the footer where it is only stored
 *  if the block is free. This is possible due to addition of the `is_prev_free`
 *  field in the header.
 * heap structure associated metadata - aside from the obligatory header and
 *  footer used for coalescing there exists a separate issue of efficient access
 *  and search of free blocks. Again we can store additional information in the
 *  free block's payload that would create some kind of data structure that
 *  would accelerate allocations. We will be using a segregated fit strategy.
 *  That divides block's into classes based on their size and collects free
 *  blocks of the same class into linked lists.
 *  Due to assumption 2. we can only store 4 byte offsets from the beginning
 *  of the heap instead of list node addresses.
 * This in total allows to store all metadata into 16 bytes which is anyway the
 *  minimal block size which provides excellent memory utilization.
 */

/*region --=[ Constants ]=-------------------------------------------------- */
#define BLOCK_SIZE_SHIFT 4
#define METADATA_SIZE ((block_size_t)sizeof(metadata_t))
/* endregion */

/*region --=[ Type definitions ]=------------------------------------------- */

/* Block's offset from the beginning of the heap.
 *
 * Due to assumption that the heap is a contiguous array of size at most 4GB
 * we can use relative offsets from the beginning of the heap to address blocks
 * in explicit free list.
 */
typedef int32_t offset_t;

/* Size of the block. It's assumed that heap is limited by 4GB thus 32-bit
 * integer is good enough. */
typedef int32_t block_size_t;

/* Always present part of block metadata.
 *
 * size - determines the size of the block.
 * is_sentinel - determines if block is a list sentinel.
 * is_prev_free - fixme: finish the docs!
 */
typedef struct metadata_t {
  uint32_t size : 28;
  uint32_t is_sentinel : 1;
  uint32_t is_prev_free : 1;
  uint32_t is_used : 1;
} metadata_t;

/* Common format for all blocks. */
typedef struct block_base_t {
  metadata_t header;
} block_base_t;

/* Layout for the sentinel node.
 *
 * Sentinel node will be used for initial heap alignment.
 */
typedef struct sentinel_block_t {
  block_base_t base;
  uint32_t _unused;
  metadata_t footer;
} sentinel_block_t;

/* Block that is used.
 * Type invariant:
 * - block is not in the free list
 * - header invariant:
 *   - flag `is_used` must be set
 *   - if 'is_prev_free` is set then:
 *     1. prev block must exist (within heap)
 *     2. prev block must be either a free block or reused block
 *
 * note: on the free / reused distinction
 *  blocks that are free are held in the free list.
 *  block is reused when it's taken out of the free list either
 *  in malloc or in free.
 *  Reused block can be converted to the free block if all actions needed to
 *  reuse block have been completed:
 *  1. is_prev_free updated
 *  2.
 */
typedef struct used_block_t {
  block_base_t base;
  uint8_t payload[];
} used_block_t;

/* Layout of the free block for free list that uses boundary tag's.
 *
 * The `is_sentinel` bit field of the `header` is a special value that's used
 * during free list traversal. If this field is set all other fields are
 * invalid.
 */
typedef struct free_block_t {
  block_base_t base;
  offset_t prev;
  offset_t next;
} free_block_t;

/* Block that was freshly allocated by extension of the heap. */
typedef struct new_block_t {
  block_base_t base;
  offset_t prev;
  offset_t next;
} new_block_t;

/* Block that was allocated, used, freed and now is allocated again.
 * Type invariant:
 *   - block used to be in the free list
 *   - block is not in the free list
 *   -
 */
typedef struct reused_block_t {
  block_base_t base;
  offset_t prev;
  offset_t next;
} reused_block_t;

/* Handle to the list of free blocks. */
struct free_list {
  free_block_t *head;
};
typedef struct free_list free_list_t;

/* Classes of block sizes.
 *
 * Each block's size class is the first class which corresponding number is
 * greater than the size of the block. Size classes are used by segregated fit
 * algorithm for selection of free list from which the search for a suitable
 * free block should begin.
 */
enum block_size_class_t {
  BLOCK_SIZE_CLASS_16 = 16,
  BLOCK_SIZE_CLASS_32 = 32,
  BLOCK_SIZE_CLASS_48 = 48,
  BLOCK_SIZE_CLASS_64 = 64,
  BLOCK_SIZE_CLASS_128 = 128,
  BLOCK_SIZE_CLASS_192 = 192,
  BLOCK_SIZE_CLASS_256 = 256,
  BLOCK_SIZE_CLASS_512 = 512,
  BLOCK_SIZE_CLASS_1024 = 1024,
  BLOCK_SIZE_CLASS_2048 = 2048,
  BLOCK_SIZE_CLASS_4096 = 4096,
  BLOCK_SIZE_CLASS_NONE, /* Special invalid value that's used to signify that no
                            higher size class exists. */
};
/* endregion */

/*region --=[ Macros ]=----------------------------------------------------- */

/* Offset pointer `ptr` by `offset` bytes. */
#define MOVE_PTR(ptr, offset) (void *)((long)(ptr) + (long)(offset))

#define LOG_PREFIX_FORMAT "[%s -- %18s -- %4d] : "
#define PANIC_PREFIX_FORMAT "[%s -- %18s -- %4d] # "

/* Common format for all messages terminated with new line character. */
#define FORMAT_STREAM_PREFIXED(stream, prefix, fmt, ...)                       \
  fprintf(stream, prefix fmt, __FILE__, __func__, __LINE__, __VA_ARGS__)

/* Common format for diagnostic messages. */
#define FORMAT_STREAM(stream, fmt, ...)                                        \
  FORMAT_STREAM_PREFIXED(stream, LOG_PREFIX_FORMAT, fmt, __VA_ARGS__)

/* Common format for panic messages. */
#define FORMAT_PANIC(stream, fmt, ...)                                         \
  FORMAT_STREAM_PREFIXED(stream, PANIC_PREFIX_FORMAT, fmt, __VA_ARGS__)

/* Irrecoverable error with formatted input. */
#define PANIC_FMT(fmt, ...)                                                    \
  do {                                                                         \
    FORMAT_PANIC(stdout, fmt, __VA_ARGS__);                                    \
    exit(EXIT_FAILURE);                                                        \
  } while (0)

/* Irrecoverable error with  diagnostic message `msg`. */
#define PANIC(msg) PANIC_FMT("%s", msg)

// #define _DEBUG

/* Display formatted output if in debug mode terminated with new line character.
 */
#ifdef _DEBUG
#define DEBUG_FMT(fmt, ...) FORMAT_STREAM(stdout, fmt "\n", __VA_ARGS__)
#else
#define DEBUG_FMT(fmt, ...)
#endif

/* Display diagnostic message `msg` if in debug mode. */
#define DEBUG(msg) DEBUG_FMT("%s", msg)

#define _DISABLE_ASSERTS_

#ifdef _DISABLE_ASSERTS_
#define ASSERT_FMT(cond, fmt, ...)
#else
#define ASSERT_FMT(cond, fmt, ...)                                             \
  do {                                                                         \
    if (!cond) {                                                               \
      PANIC_FMT(fmt, __VA_ARGS__);                                             \
    }                                                                          \
  } while (0)
#endif

/* Assert that condition `cond` is `true`. */
#ifdef _DISABLE_ASSERTS_
#define ASSERT(cond, ...)
#else
#define ASSERT(cond, ...)                                                      \
  do {                                                                         \
    if (!(cond)) {                                                             \
      PANIC("Assertion failed");                                               \
    }                                                                          \
  } while (0)
#endif

/* Assert that left-hand side operand `lhs` is equal to right-hand size operand
 * `rhs`. */
#define ASSERT_EQ(lhs, rhs) ASSERT((lhs) == (rhs))

/* Assert that left-hand side operand `lhs` is not equal to right-hand size
 * operand `rhs`. */
#define ASSERT_NEQ(lhs, rhs) ASSERT((lhs) != (rhs))

/* Assert that pointer `ptr` is not `NULL`. */
#define ASSERT_PTR(ptr) ASSERT_NEQ(ptr, NULL)
/* endregion */

/* --------=[ Miscellaneous ]=---------------------------------------------- */

/* keyword with multiple, context dependent meanings should be like Barlog
 * at the bridge of Khazad-dum ...
 *            ... It shall not pass.
 */
#define internal static
#define unsafe

/* Some color codes. */
#define COLOR_DEFAULT "\033[0m"
#define COLOR_RED "\033[0;31m"
#define COLOR_GREEN "\033[0;32m"
#define COLOR_CYAN "\033[0;36m"
#define COLOR_YELLOW "\033[0;33m"

#define BLOCK_FMT                                                              \
  " block at: " COLOR_GREEN "%p" COLOR_DEFAULT " with size: %x (%d) "
#define BLOCK_FMT_ARGS(metadata)                                               \
  (&metadata), metadata_get_size(metadata), metadata_get_size(metadata)

/* Round up `size` to ALIGNMENT. */
internal block_size_t round_up_to_alignment(block_size_t size) {
  return (size + ALIGNMENT - 1) & -ALIGNMENT;
}

/* Get address of the first byte outside the heap. */
internal void *mem_heap_end() {
  return mem_heap_hi() + 1;
}
/* endregion */

/* --------=[ Allocator state ]=-------------------------------------------- */
typedef struct {
  free_list_t _16;
  free_list_t _32;
  free_list_t _48;
  free_list_t _64;
  free_list_t _128;
  free_list_t _192;
  free_list_t _256;
  free_list_t _512;
  free_list_t _1024;
  free_list_t _2048;
  free_list_t _4096;
} segregated_fit_buckets_t;

/* Global private allocator state. */
internal struct {
  sentinel_block_t *sentinel;
  block_base_t *last_heap_block;
  segregated_fit_buckets_t buckets;
} mm_state = {
  /* note: sentinel must be on the heap so it can be addressed using offset. */
  .sentinel = NULL,
  .last_heap_block = NULL,
  .buckets = {}};

/* Get reference to a sentinel block. */
internal sentinel_block_t *get_sentinel(void) {
  return mm_state.sentinel;
}
/*endregion*/

/* Get size class for given block size. */
internal enum block_size_class_t get_block_size_class(block_size_t size) {
  if (size <= BLOCK_SIZE_CLASS_16)
    return BLOCK_SIZE_CLASS_16;
  if (size <= BLOCK_SIZE_CLASS_32)
    return BLOCK_SIZE_CLASS_32;
  if (size <= BLOCK_SIZE_CLASS_48)
    return BLOCK_SIZE_CLASS_48;
  if (size <= BLOCK_SIZE_CLASS_64)
    return BLOCK_SIZE_CLASS_64;
  if (size <= BLOCK_SIZE_CLASS_128)
    return BLOCK_SIZE_CLASS_128;
  if (size <= BLOCK_SIZE_CLASS_192)
    return BLOCK_SIZE_CLASS_192;
  if (size <= BLOCK_SIZE_CLASS_256)
    return BLOCK_SIZE_CLASS_256;
  if (size <= BLOCK_SIZE_CLASS_512)
    return BLOCK_SIZE_CLASS_512;
  if (size <= BLOCK_SIZE_CLASS_1024)
    return BLOCK_SIZE_CLASS_1024;
  if (size <= BLOCK_SIZE_CLASS_2048)
    return BLOCK_SIZE_CLASS_2048;
  return BLOCK_SIZE_CLASS_4096;
}

/* Get next bigger size class than current. */
internal enum block_size_class_t
get_next_size_class(enum block_size_class_t current) {
  switch (current) {
    case BLOCK_SIZE_CLASS_16:
      return BLOCK_SIZE_CLASS_32;
    case BLOCK_SIZE_CLASS_32:
      return BLOCK_SIZE_CLASS_48;
    case BLOCK_SIZE_CLASS_48:
      return BLOCK_SIZE_CLASS_64;
    case BLOCK_SIZE_CLASS_64:
      return BLOCK_SIZE_CLASS_128;
    case BLOCK_SIZE_CLASS_128:
      return BLOCK_SIZE_CLASS_192;
    case BLOCK_SIZE_CLASS_192:
      return BLOCK_SIZE_CLASS_256;
    case BLOCK_SIZE_CLASS_256:
      return BLOCK_SIZE_CLASS_512;
    case BLOCK_SIZE_CLASS_512:
      return BLOCK_SIZE_CLASS_1024;
    case BLOCK_SIZE_CLASS_1024:
      return BLOCK_SIZE_CLASS_2048;
    case BLOCK_SIZE_CLASS_2048:
      return BLOCK_SIZE_CLASS_4096;
    default:
      return BLOCK_SIZE_CLASS_NONE;
  }
}

/* Get free list that stores blocks of given size. */
internal free_list_t *get_free_list(enum block_size_class_t class) {
  switch (class) {
    case BLOCK_SIZE_CLASS_16:
      return &mm_state.buckets._16;
    case BLOCK_SIZE_CLASS_32:
      return &mm_state.buckets._32;
    case BLOCK_SIZE_CLASS_48:
      return &mm_state.buckets._48;
    case BLOCK_SIZE_CLASS_64:
      return &mm_state.buckets._64;
    case BLOCK_SIZE_CLASS_128:
      return &mm_state.buckets._128;
    case BLOCK_SIZE_CLASS_192:
      return &mm_state.buckets._192;
    case BLOCK_SIZE_CLASS_256:
      return &mm_state.buckets._256;
    case BLOCK_SIZE_CLASS_512:
      return &mm_state.buckets._512;
    case BLOCK_SIZE_CLASS_1024:
      return &mm_state.buckets._1024;
    case BLOCK_SIZE_CLASS_2048:
      return &mm_state.buckets._2048;
    case BLOCK_SIZE_CLASS_4096:
      return &mm_state.buckets._4096;
    case BLOCK_SIZE_CLASS_NONE:
      PANIC("Invalid size class");
    default:
      PANIC("Unsupported size class");
  }
}

#ifndef _DISABLE_ASSERTS_
/* Check if heap is correctly aligned. */
internal bool heap_aligned() {
  return (long)MOVE_PTR(mem_heap_end(), METADATA_SIZE) % ALIGNMENT == 0;
}

// check if given size is a valid block size
internal bool block_size_is_valid(const block_size_t size) {
  return (size % ALIGNMENT) == 0;
}
#endif

/* Check if given address lies within heap address range. */
internal bool heap_contains_address(const void *const address) {
  ASSERT_PTR(address);
  const bool lower_bound =
    (unsigned long)mem_heap_lo() <= (unsigned long)address;
  const bool upper_bound =
    (unsigned long)mem_heap_end() > (unsigned long)address;
  return lower_bound && upper_bound;
}

#define ENCODE_BLOCK_SIZE(size) ((size) >> BLOCK_SIZE_SHIFT)
#define DECODE_BLOCK_SIZE(size) ((size) << BLOCK_SIZE_SHIFT)

/* Check if block is aligned correctly. */
internal bool header_is_aligned(const metadata_t *const header) {
  ASSERT_PTR(header);
  return ((long)header + sizeof(metadata_t)) % ALIGNMENT == 0;
}

// region metadata
/* # About block metadata
 *
 * The header is always present.
 * It contains the length of the block in the multiples of ALIGNMENT (16 bytes).
 * This means that 4 lower bits of the size are ripe for the taking for use as
 * bit flags.
 *
 * Free blocks are arranged into a way that accelerates the allocation process.
 *
 * To form an explicit free list we will store doubly linked list nodes in the
 * payload section of the block. This allows for quicker allocations as now we
 * have instantaneous access to the free blocks as opposed to implicit lists
 * where we needed to traverse the list of all blocks, even te used ones.
 *
 * Separately from the free block data structure me
 */

/* Types of block. */
enum block_type_t {
  FREE,
  USED,
  SENTINEL,
};

/* Set flags in metadata to reflect given block type. */
internal inline void flags_set(metadata_t *metadata,
                               enum block_type_t block_type) {
  switch (block_type) {
    case FREE: {
      metadata->is_used = 0;
      metadata->is_sentinel = 0;
      metadata->is_prev_free = 0;
    } break;
    case USED: {
      metadata->is_used = 1;
      metadata->is_sentinel = 0;
      metadata->is_prev_free = 0;
    } break;
    case SENTINEL: {
      metadata->is_used = 0;
      metadata->is_sentinel = 1;
      metadata->is_prev_free = 0;
    } break;
    default:
      PANIC("Unsupported block type");
  }
}

/* Check if flags in metadata are valid for given type. */
internal inline bool flags_check(metadata_t metadata,
                                 enum block_type_t block_type) {
  switch (block_type) {
    case FREE:
      return metadata.is_used == 0 && metadata.is_sentinel == 0 &&
             metadata.is_prev_free == 0;
    case USED:
      return metadata.is_used == 1 && metadata.is_sentinel == 0;
    case SENTINEL:
      return metadata.is_used == 0 && metadata.is_sentinel == 1 &&
             metadata.is_prev_free == 0;
    default:
      PANIC("Unsupported block types");
  }
}

/* Check if flags in metadata are valid for a free block. */
internal inline bool flags_check_free(metadata_t metadata) {
  return flags_check(metadata, FREE);
}

#ifndef _DISABLE_ASSERTS_
/* Check if flags in metadata are valid for a used block. */
internal bool flags_check_used(metadata_t metadata) {
  return flags_check(metadata, USED);
}
#endif

/* Check if flags in metadata are valid for a sentinel block. */
internal inline bool flags_check_sentinel(metadata_t metadata) {
  return flags_check(metadata, SENTINEL);
}

/* Compare flags for equality */
internal inline bool flags_eq(metadata_t lhs, metadata_t rhs) {
  return lhs.is_used == rhs.is_used && lhs.is_prev_free == rhs.is_prev_free &&
         lhs.is_sentinel == rhs.is_sentinel;
}

/* Set block size in metadata. */
internal inline void metadata_set_size(metadata_t *metadata,
                                       block_size_t new_size) {
  ASSERT(block_size_is_valid(new_size));
  metadata->size = ENCODE_BLOCK_SIZE(new_size);
}

/* Get block size from metadata. */
internal inline block_size_t metadata_get_size(metadata_t self) {
  return DECODE_BLOCK_SIZE(self.size);
}

/* Create metadata for given type and size. */
internal inline metadata_t make_metadata(block_size_t size,
                                         enum block_type_t block_type) {
  metadata_t result;
  flags_set(&result, block_type);
  metadata_set_size(&result, size);
  return result;
}

/* Compare metadata for equality. */
internal inline bool metadata_eq(metadata_t lhs, metadata_t rhs) {
  return flags_eq(lhs, rhs) && metadata_get_size(lhs) == metadata_get_size(rhs);
}

/* Calculate the offset of the block from the beginning of the heap. */
internal inline offset_t
metadata_offset_from_address(const metadata_t *const header) {
  ASSERT_PTR(header);
  ASSERT(heap_contains_address((void *)header));
  return unsafe(offset_t)((long)header - (long)mem_heap_lo());
}

/* Calculate address of the block with specified `offset`. */
internal inline metadata_t *metadata_address_from_offset(offset_t offset) {
  // ASSERT(offset_is_aligned(offset)); -- sentinel is not aligned!
  return MOVE_PTR(mem_heap_lo(), offset);
}
// endregion

#ifndef _DISABLE_ASSERTS_
internal bool used_block_is_prev_free(const used_block_t *const block) {
  return block->base.header.is_prev_free == 1;
}

internal bool used_block_is_prev_used(const used_block_t *const block) {
  return block->base.header.is_prev_free == 0;
}
#endif

/* Mark that previous in memory adjacent block is free to current used block. */
internal inline void used_block_set_prev_free(used_block_t *block) {
  ASSERT(used_block_is_prev_used(block));
  block->base.header.is_prev_free = 1;
}

/* Mark that previous in memory adjacent block is not free to current used
 * block. */
internal inline void used_block_clear_prev_free(used_block_t *block) {
  ASSERT(used_block_is_prev_free(block));
  block->base.header.is_prev_free = 0;
}

/* Unsafe cast to used block. */
internal inline used_block_t *
unsafe_cast_to_used_block(const metadata_t *const header) {
  return (used_block_t *)header;
}

#ifndef _DISABLE_ASSERTS_
/* Check if block is correctly marked as used. */
internal bool block_is_used(const block_base_t *const base) {
  ASSERT_PTR(base);
  return (base->header.is_sentinel == 0) && (base->header.is_used == 1);
}

internal bool used_block_check(metadata_t *metadata) {
  return heap_contains_address(metadata) && header_is_aligned(metadata) &&
         flags_check_used(*metadata);
}
#endif

/* Safe cast to used pointer that asserts block invariants. */
internal inline used_block_t *safe_cast_to_used_block(metadata_t *metadata) {
  ASSERT(used_block_check(metadata));
  return unsafe_cast_to_used_block(metadata);
}

/* Get the footer of the free block. */
internal inline metadata_t *
free_block_get_footer(const free_block_t *const block) {
  ASSERT_PTR(block);
  return MOVE_PTR(block,
                  metadata_get_size(block->base.header) - sizeof(metadata_t));
}

/* Check if footer of the free block is equal to its header. */
internal inline bool free_block_check_footer(const free_block_t *const self) {
  ASSERT_PTR(self);
  return metadata_eq(*free_block_get_footer(self), self->base.header);
}

/* Raw pointer to pointer cast. */
internal inline unsafe free_block_t *
unsafe_cast_to_free_block(metadata_t *block_metadata) {
  return (free_block_t *)block_metadata;
}

/* Check if layout of the free block is correct. */
internal inline bool free_block_local_check(metadata_t *block_metadata) {
  return heap_contains_address(block_metadata) &&
         header_is_aligned(block_metadata) &&
         flags_check_free(*block_metadata) &&
         free_block_check_footer(unsafe_cast_to_free_block(block_metadata));
}

internal inline free_block_t *
safe_cast_to_free_block(metadata_t *block_metadata) {
  ASSERT(free_block_local_check(block_metadata));
  return unsafe_cast_to_free_block(block_metadata);
}

/* Get next free block from the list. If list end has been reached return NULL.
 */
internal inline free_block_t *free_list_next(free_block_t *current) {
  ASSERT_PTR(current);
  metadata_t *next = metadata_address_from_offset(current->next);
  if (flags_check_sentinel(
        *next)) // if we reached the end of the list return NULL.
    return NULL;
  return safe_cast_to_free_block(next);
}
#ifndef _DISABLE_ASSERTS_
/* Display contents of the free list. */
/* free list contains helper. */
internal free_block_t *free_list_find(free_list_t *list, metadata_t *block) {
  free_block_t *current_block = list->head;
  while (current_block != NULL) {
    if (&current_block->base.header == block) {
      return current_block;
    }
    current_block = free_list_next(current_block);
  }
  return NULL;
}

/* Check if free list contains block at given address. */
internal bool free_list_contains(free_list_t *list, metadata_t *block) {
  return free_list_find(list, block) != NULL;
}
#endif

/* Get address of the next block is it exists. If block does not exist return
 * NULL. */
internal inline metadata_t *adjacent_get_prev(const metadata_t *const self) {
  ASSERT_PTR(self);
  if (self->is_prev_free == 1) {
    metadata_t *prev_footer = unsafe MOVE_PTR(self, -sizeof(metadata_t));
    block_size_t prev_size = metadata_get_size(*prev_footer);
    return unsafe MOVE_PTR(self, -prev_size);
  }
  return NULL;
}

#ifndef _DISABLE_ASSERTS_
/* Calculate the address of the previous in memory adjacent block to self. */
internal free_block_t *adjacent_get_prev_free(const block_base_t *const self) {
  ASSERT_PTR(self);
  if (self->header.is_prev_free == 1) {
    metadata_t *prev_header = adjacent_get_prev(&self->header);
    ASSERT_PTR(prev_header);
    free_block_t *result = safe_cast_to_free_block(prev_header);
    return result;
  }
  return NULL;
}
#endif

/* Calculate the address of next, in memory adjacent, block.
 * If block does not exist return `NULL`.
 */
internal inline metadata_t *adjacent_get_next(const metadata_t *const self) {
  ASSERT_PTR(self);
  metadata_t *next = unsafe MOVE_PTR(self, metadata_get_size(*self));
  if (next != mem_heap_end()) {
    return next;
  }
  return NULL;
}

#ifndef _DISABLE_ASSERTS_
/* Check if free block is valid and its in memory adjacent blocks reflect that
 * correclty. */
internal bool free_block_adjacent_check(metadata_t *metadata) {
  if (!free_block_local_check(metadata)) {
    return false;
  }
  metadata_t *next = adjacent_get_next(metadata);
  if (next != NULL) {
    if (flags_check_used(*next) &&
        used_block_is_prev_used(safe_cast_to_used_block(next))) {
      // is_prev_free should be free
      return false;
    }
    if (flags_check_free(*next)) {
      // next shouldn't be free - merge should have happened
      return false;
    }
  }
  // prev shouldn't be free - merge should have happened
  return adjacent_get_prev_free((block_base_t *)metadata) == NULL;
}

/* Check all invariants of not processes free block. */
internal bool free_block_advanced_check(metadata_t *metadata) {
  return free_block_adjacent_check(metadata) &&
         free_list_contains(&mm_state.free_list, metadata);
}
#endif

/* Push the free block to the front of the list. */
internal inline void free_list_push(free_list_t *self, free_block_t *new) {
  ASSERT_PTR(self);
  free_block_t *target = new;

  offset_t next;
  if (self->head == NULL) {
    next = metadata_offset_from_address(&get_sentinel()->base.header);
  } else {
    next = metadata_offset_from_address(&self->head->base.header);
    self->head->prev = metadata_offset_from_address(&target->base.header);
  }
  target->prev = metadata_offset_from_address(&get_sentinel()->base.header);
  target->next = next;
  self->head = target;
  ASSERT_EQ(target->prev, 0);
}

/* Remove the free block at given address from the list. */
internal inline void free_list_remove(free_list_t *self, free_block_t *target) {
  ASSERT_PTR(self);
  ASSERT_PTR(target);

  metadata_t *prev = metadata_address_from_offset(target->prev);
  metadata_t *next = metadata_address_from_offset(target->next);

  ASSERT(flags_check_sentinel(*prev) || free_block_local_check(prev));
  ASSERT(flags_check_sentinel(*next) || free_block_local_check(next));

  if (flags_check_sentinel(*prev)) {
    self->head =
      flags_check_sentinel(*next) ? NULL : safe_cast_to_free_block(next);
  } else {
    safe_cast_to_free_block(prev)->next = target->next;
  }
  if (!flags_check_sentinel(*next)) {
    safe_cast_to_free_block(next)->prev = target->prev;
  }

  target->prev = 0;
  target->next = 0;
}

/* Create new empty free list. */
internal inline free_list_t free_list_new(void) {
  free_list_t self = {
    .head = NULL,
  };
  return self;
}

/* Initialize a free block with size at given address. */
internal inline unsafe void init_free_block_at(void *const address,
                                               block_size_t size) {
  ASSERT_PTR(address);
  ASSERT(heap_contains_address(address));
  ASSERT(header_is_aligned(address));
  ASSERT(block_size_is_valid(size));

  free_block_t *new = address;
  metadata_t metadata = make_metadata(size, FREE);
  new->base.header = metadata;
  metadata_t *footer = free_block_get_footer(new);
  *footer = metadata;
  new->prev = 0;
  new->next = 0;
  ASSERT(free_block_local_check(&new->base.header));
  ASSERT_EQ(metadata_get_size(new->base.header), size);
}

/* Initialize a sentinel block with size at given address. */
internal inline unsafe void init_sentinel_at(sentinel_block_t *sentinel) {
  const metadata_t metadata = make_metadata(0, SENTINEL);
  sentinel->base.header = metadata;
  sentinel->_unused = 0;
  sentinel->footer = metadata;
}

/* Initialize a used block with size at given address. */
internal inline unsafe void init_used_block_at(void *address,
                                               block_size_t size) {
  ASSERT(heap_contains_address(address));
  ASSERT(header_is_aligned(address));
  ASSERT(block_size_is_valid(size));

  used_block_t *new = address;
  metadata_t metadata = make_metadata(size, USED);
  new->base.header = metadata;
}
// endregion

/* Calculate address of the used block from address of its payload. */
internal inline unsafe used_block_t *used_block_from_payload(void *payload) {
  used_block_t *used_block = MOVE_PTR(payload, -sizeof(block_base_t));
  ASSERT(block_is_used(&used_block->base));
  return used_block;
}

/* First fit search of given free list. */
internal inline free_block_t *first_fit(free_list_t *list, block_size_t size) {
  free_block_t *current_block = list->head;
  while (current_block != NULL &&
         metadata_get_size(current_block->base.header) < size) {
    current_block = free_list_next(current_block);
  }
  if (current_block == NULL) {
    return NULL;
  } else {
    free_list_remove(list, current_block);
    return current_block;
  }
}

/* Best fit search of given list. */
internal inline free_block_t *best_fit(free_list_t *list, block_size_t size) {
  free_block_t *current_block = list->head;
  block_size_t min_difference = size;
  free_block_t *best_fit = NULL;
  while (current_block != NULL) {
    const block_size_t current_size =
      metadata_get_size(current_block->base.header);
    const block_size_t current_difference = current_size - size;
    if (current_size >= size) {
      if (current_difference < min_difference) {
        min_difference = current_difference;
        best_fit = current_block;
      }
    }
    current_block = free_list_next(current_block);
  }
  if (best_fit == NULL) {
    return NULL;
  } else {
    free_list_remove(list, best_fit);
    return best_fit;
  }
}

/* Try allocating a block of size `user_size` in the given free list.
 *
 * If no blocks that are big enough to accommodate the allocation return NULL.
 */
internal inline free_block_t *try_alloc(free_list_t *const free_list,
                                        block_size_t total_block_size) {
  ASSERT_PTR(free_list);
  ASSERT_FMT(block_size_is_valid(total_block_size), "%s", "Block size invalid");
  return first_fit(free_list, total_block_size);
}

/* Extend the heap by allocating a new block of given size. */
internal inline free_block_t *heap_extend(block_size_t total_block_size) {
  ASSERT(heap_aligned());
  ASSERT(block_size_is_valid(total_block_size));
  void *new_block_address = mem_sbrk(total_block_size);
  ASSERT_PTR(new_block_address);
  if (new_block_address == NULL) {
    return NULL;
  }
  ASSERT(heap_aligned());
  init_free_block_at(new_block_address, total_block_size);
  return (free_block_t *)new_block_address;
}

internal inline bool is_last_block(metadata_t *header) {
  return MOVE_PTR(header, metadata_get_size(*header)) == mem_heap_end();
}

/* Merge current free block with next in memory adjacent block.
 * If the next block is not free or does not exist, do nothing.
 * If the next block is free remove it from the free list and
 *   initialize free block at address of the current block.
 */
internal inline free_block_t *merge_next(free_block_t *current,
                                         free_block_t *next) {
  ASSERT_PTR(current);
  ASSERT_PTR(next);
  ASSERT(free_block_advanced_check(&next->base.header));

  const block_size_t current_size = metadata_get_size(current->base.header);
  const block_size_t next_size = metadata_get_size(next->base.header);
  const enum block_size_class_t next_size_class =
    get_block_size_class(next_size);

  free_list_remove(get_free_list(next_size_class), next);
  const block_size_t merged_size = current_size + next_size;
  // merge with last block - last block pointer must be updated
  if (is_last_block(&next->base.header)) {
    mm_state.last_heap_block = &current->base;
  }
  unsafe {
    init_free_block_at((void *)current, merged_size);
  }
  ASSERT(free_block_adjacent_check(&current->base.header));
  return current;
}

/* Merge current free block with previous in memory adjacent block.
 * If the previous block is not free or does not exist, do nothing.
 * If the previous block is free remove it from the free list and
 *   initialize free block at address of the current block.
 */
internal inline free_block_t *merge_prev(free_block_t *current,
                                         free_block_t *prev) {
  ASSERT_PTR(current);
  ASSERT_PTR(prev);
  // ASSERT(free_block_advanced_check(&prev->base.header)); -- we didnt merge
  // yet prev is still free

  const block_size_t current_size = metadata_get_size(current->base.header);
  const block_size_t prev_size = metadata_get_size(prev->base.header);
  const enum block_size_class_t prev_size_class =
    get_block_size_class(prev_size);

  free_list_remove(get_free_list(prev_size_class), prev);
  const block_size_t merged_size = current_size + prev_size;
  // merge with last block - last block pointer must be updated
  if (is_last_block(&current->base.header)) {
    mm_state.last_heap_block = &prev->base;
  }
  unsafe {
    init_free_block_at((void *)prev, merged_size);
  }
  ASSERT(free_block_adjacent_check(&prev->base.header));
  return prev;
}

/* If possible split given block at given offset while preserving block
 * alignment.
 *
 * If split did not occur return NULL.
 */
internal inline free_block_t *split(free_block_t *self,
                                    const offset_t required_size) {
  ASSERT(self);
  ASSERT(!free_list_contains(&mm_state.free_list, &self->base.header));
  ASSERT(metadata_get_size(self->base.header) >= required_size);
  const block_size_t excessive_block_size =
    metadata_get_size(self->base.header) - required_size;
  ASSERT(block_size_is_valid(excessive_block_size));
  if (excessive_block_size > 0) {
    free_block_t *new_block = MOVE_PTR(self, required_size);
#ifndef _DISABLE_ASSERTS_
    const block_size_t old_size = metadata_get_size(self->base.header);
#endif
    // splitting last block on the heap - last block pointer needs to be
    // updated.
    if (is_last_block(&self->base.header)) {
      mm_state.last_heap_block = &new_block->base;
    }

    unsafe {
      init_free_block_at(self, required_size);
      init_free_block_at(new_block, excessive_block_size);
    }
    ASSERT(is_last_block(&mm_state.last_heap_block->header));
    ASSERT(free_block_local_check(&self->base.header));
    ASSERT(!free_list_contains(&mm_state.free_list, &self->base.header));
    ASSERT(free_block_local_check(&new_block->base.header));
    ASSERT(!free_list_contains(&mm_state.free_list, &new_block->base.header));
    ASSERT_EQ(required_size, metadata_get_size(self->base.header));
    ASSERT_EQ(excessive_block_size, metadata_get_size(new_block->base.header));
    ASSERT_EQ(old_size, metadata_get_size(self->base.header) +
                          metadata_get_size(new_block->base.header));
    return new_block;
  } else {
    return NULL;
  }
}

/*
 * mm_init - Called when a new trace starts.
 */
int mm_init(void) {
  /* Pad heap start so first payload is at ALIGNMENT. */
  ASSERT_EQ(mem_heapsize(), 0);
  const uint8_t alignment_overhead = (long)mem_heap_end() % ALIGNMENT;
  if (alignment_overhead != 0) {
    ASSERT_PTR(mem_sbrk(ALIGNMENT - alignment_overhead));
  }
  ASSERT_EQ(ALIGNMENT - METADATA_SIZE, sizeof(sentinel_block_t));

  // allocate and init head sentinel
  sentinel_block_t *head_sentinel = mem_sbrk(sizeof(sentinel_block_t));
  ASSERT_PTR(head_sentinel);
  init_sentinel_at(head_sentinel);

  ASSERT(heap_aligned());
  mm_state.sentinel = head_sentinel;
  mm_state.buckets = (segregated_fit_buckets_t){
    ._16 = free_list_new(),
    ._32 = free_list_new(),
    ._48 = free_list_new(),
    ._64 = free_list_new(),
    ._128 = free_list_new(),
    ._192 = free_list_new(),
    ._256 = free_list_new(),
    ._512 = free_list_new(),
    ._1024 = free_list_new(),
    ._2048 = free_list_new(),
    ._4096 = free_list_new(),
  };
  mm_state.last_heap_block = &head_sentinel->base;
  return 0;
}

/* Allocate a block */
void *malloc(size_t size) {
  // todo: round the size here not in the `try_alloc`.
  ASSERT(size <= UINT32_MAX); // assert assumption 2.

  const block_size_t payload_size = (block_size_t)size;
  // fixme: beware of the overflow!
  const block_size_t block_size = payload_size + METADATA_SIZE;
  const block_size_t total_block_size =
    (block_size_t)round_up_to_alignment(block_size);
  ASSERT(block_size_is_valid(total_block_size));
  bool set_is_prev_free = false;

  // here we implement allocation strategy (segregated fit).
  enum block_size_class_t size_class = get_block_size_class(total_block_size);
  // printf("Block size: %d; size class: %d\n", total_block_size, size_class);
  free_block_t *block = NULL;
  while (block == NULL && size_class != BLOCK_SIZE_CLASS_NONE) {
    // try higher class until you either find one or have to extend the heap
    block =
      try_alloc(get_free_list(size_class), (block_size_t)total_block_size);
    size_class = get_next_size_class(size_class);
  }

  if (block == NULL) {
    // no matching free blocks available - try extending the heap
    block = heap_extend((block_size_t)total_block_size);

    // see if previous last block is free -> then update is prev free field
    // and move mm_state last block pointer.
    // This was such a nasty bug.
    if (free_block_local_check(&mm_state.last_heap_block->header)) {
      set_is_prev_free = true;
    }
    mm_state.last_heap_block = &block->base;
  }

  metadata_t *next = adjacent_get_next(&block->base.header);
#ifndef _DISABLE_ASSERTS_
  metadata_t *prev = adjacent_get_prev(&block->base.header);
#endif

  /* malloc is called on en empty block - thus all in memory adjacent block
   * must be used otherwise they should have been merger when current block was
   * freed the only exception being that block does not exist.
   */
  ASSERT(prev == NULL || used_block_check(prev));
  ASSERT(next == NULL || used_block_check(next));

  if (next != NULL) {
    ASSERT(used_block_check(next));
    ASSERT(used_block_is_prev_free((used_block_t *)next));
    used_block_clear_prev_free(safe_cast_to_used_block(next));
  }
  // now try splitting the chosen block.
  free_block_t *split_leftover = split(block, total_block_size);
  if (split_leftover != NULL) {
    enum block_size_class_t split_leftover_size_class =
      get_block_size_class(metadata_get_size(split_leftover->base.header));
    free_list_push(get_free_list(split_leftover_size_class), split_leftover);
    if (next != NULL) {
      ASSERT(used_block_check(next));
      // we preemptively cleared the flag but now after the split we need to set
      // it once again
      used_block_set_prev_free(safe_cast_to_used_block(next));
    }
  }
  init_used_block_at(block, metadata_get_size(block->base.header));
  used_block_t *result = safe_cast_to_used_block(&block->base.header);
  if (set_is_prev_free) {
    ASSERT_EQ(mm_state.last_heap_block, &result->base);
    ASSERT(used_block_is_prev_used(result));
    used_block_set_prev_free(result);
  }
  return result->payload;
}

/* Free memory that was previously allocated by `malloc`, `realloc` or `calloc`.
 */
void free(void *ptr) {
  if (ptr == NULL) {
    return;
  }
  used_block_t *block_to_free = used_block_from_payload(ptr);
  metadata_t *next = adjacent_get_next(&block_to_free->base.header);
  metadata_t *prev = adjacent_get_prev(&block_to_free->base.header);

  unsafe {
    init_free_block_at(block_to_free,
                       metadata_get_size(block_to_free->base.header));
  }
  free_block_t *current = safe_cast_to_free_block(&block_to_free->base.header);
  if (next != NULL) {
    if (free_block_local_check(next)) {

#ifndef _DISABLE_ASSERTS_
      const block_size_t old_curr_size =
        metadata_get_size(current->base.header);
      const block_size_t old_next_size = metadata_get_size(*next);
#endif
      current = merge_next(current, safe_cast_to_free_block(next));
      ASSERT_EQ(metadata_get_size(current->base.header),
                old_curr_size + old_next_size);
    } else {
      used_block_set_prev_free(safe_cast_to_used_block(next));
    }
  }
  if (prev != NULL) {
    ASSERT(free_block_local_check(prev));

#ifndef _DISABLE_ASSERTS_
    const block_size_t old_curr_size = metadata_get_size(current->base.header);
    const block_size_t old_prev_size = metadata_get_size(*prev);
#endif
    current = merge_prev(current, safe_cast_to_free_block(prev));
    ASSERT_EQ(metadata_get_size(current->base.header),
              old_curr_size + old_prev_size);
  } else {
    ASSERT(!current->base.header.is_prev_free);
  }
  ASSERT(free_block_adjacent_check(&current->base.header));

  enum block_size_class_t freed_block_size =
    get_block_size_class(metadata_get_size(current->base.header));

  free_list_push(get_free_list(freed_block_size), current);
}

/*
 * realloc - Change the size of the block by mallocing a new block,
 *      copying its data, and freeing the old block.
 */
void *realloc(void *old_ptr, size_t size) {
  /* If size == 0 then this is just free, and we return NULL. */

  if (size == 0) {
    free(old_ptr);
    return NULL;
  }

  /* If old_ptr is NULL, then this is just malloc. */
  if (!old_ptr)
    return malloc(size);

  used_block_t *used_old = used_block_from_payload(old_ptr);

  void *new_ptr = malloc(size);

  /* If malloc() fails, the original block is left untouched. */
  if (!new_ptr)
    return NULL;

  used_block_t *used_new = used_block_from_payload(new_ptr);

  ASSERT(used_block_check(&used_old->base.header));
  ASSERT(used_block_check(&used_new->base.header));

  /* Copy the old data. */
  const block_size_t old_block_size = metadata_get_size(used_old->base.header);
  const block_size_t new_block_size = metadata_get_size(used_new->base.header);
  block_size_t copy_range = old_block_size;
  if (new_block_size < old_block_size) {
    copy_range = new_block_size;
  }
  memcpy(&used_new->payload, &used_old->payload,
         copy_range - sizeof(metadata_t));

  /* Free the old block. */
  free(old_ptr);

  return new_ptr;
}

/*
 * calloc - Allocate the block and set it to zero.
 */
void *calloc(size_t nmemb, size_t size) {
  size_t bytes = nmemb * size;
  void *new_ptr = malloc(bytes);

  /* If malloc() fails, skip zeroing out the memory. */
  if (new_ptr)
    memset(new_ptr, 0, bytes);

  return new_ptr;
}

void mm_checkheap(int verbose) {
  // I decided to write many small functions that each test very specific
  // part of the program's state.
  // This way I could write code like
  //
  // ```c=
  // foo(&bar);
  // ASSERT(something(&bar));
  // ```
  // This makes reasoning about the program much easier in my opinion.
}
