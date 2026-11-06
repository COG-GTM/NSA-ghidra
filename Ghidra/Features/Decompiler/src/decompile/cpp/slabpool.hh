/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file slabpool.hh
/// \brief Fixed-size object storage for function-local banks
#ifndef __SLABPOOL_HH__
#define __SLABPOOL_HH__

#include <cstddef>
#include <new>
#include <vector>

#if defined(__SANITIZE_ADDRESS__)
#define GHIDRA_SLAB_ASAN
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define GHIDRA_SLAB_ASAN
#endif
#endif
#ifdef GHIDRA_SLAB_ASAN
#include <sanitizer/asan_interface.h>
#endif

namespace ghidra {

/// \brief Reusable raw storage; callers manage object construction and destruction
template<class T> class SlabPool {
  struct FreeSlot { FreeSlot *next; };
  static const std::size_t slabSize = 1024;
  std::vector<void *> slabs;
  std::size_t used;
  FreeSlot *freeList;
  SlabPool(const SlabPool &) = delete;
  SlabPool &operator=(const SlabPool &) = delete;
public:
  SlabPool(void) : used(slabSize), freeList(nullptr) {
    static_assert(sizeof(T) >= sizeof(FreeSlot), "Object too small for free list");
    static_assert(alignof(T) >= alignof(FreeSlot), "Object alignment too small for free list");
  }
  ~SlabPool(void) { reset(); }
  void *allocate(void) {
    if (freeList != nullptr) {
      FreeSlot *slot = freeList;
#ifdef GHIDRA_SLAB_ASAN
      ASAN_UNPOISON_MEMORY_REGION(slot, sizeof(T));
#endif
      freeList = slot->next;
      return slot;
    }
    if (used == slabSize) {
      void *slab = ::operator new(slabSize * sizeof(T));
      try {
        slabs.push_back(slab);
      } catch (...) {
        ::operator delete(slab);
        throw;
      }
#ifdef GHIDRA_SLAB_ASAN
      ASAN_POISON_MEMORY_REGION(slab, slabSize * sizeof(T));
#endif
      used = 0;
    }
    void *slot = static_cast<char *>(slabs.back()) + used++ * sizeof(T);
#ifdef GHIDRA_SLAB_ASAN
    ASAN_UNPOISON_MEMORY_REGION(slot, sizeof(T));
#endif
    return slot;
  }
  void release(void *p) {
    FreeSlot *slot = new(p) FreeSlot;
    slot->next = freeList;
    freeList = slot;
#ifdef GHIDRA_SLAB_ASAN
    ASAN_POISON_MEMORY_REGION(slot, sizeof(T));
#endif
  }
  void reset(void) {
    for(void *slab : slabs) {
#ifdef GHIDRA_SLAB_ASAN
      ASAN_UNPOISON_MEMORY_REGION(slab, slabSize * sizeof(T));
#endif
      ::operator delete(slab);
    }
    slabs.clear();
    used = slabSize;
    freeList = nullptr;
  }
};

} // End namespace ghidra
#endif
