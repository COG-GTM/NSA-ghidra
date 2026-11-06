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
  struct Slab { void *storage; std::size_t capacity; };
  static const std::size_t slabSize = 1024;
  std::vector<Slab> slabs;
  std::size_t capacity;
  std::size_t used;
  FreeSlot *freeList;
  SlabPool(const SlabPool &) = delete;
  SlabPool &operator=(const SlabPool &) = delete;
public:
  SlabPool(void) : capacity(32), used(32), freeList(nullptr) {
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
    if (used == capacity) {
      std::size_t nextCapacity = slabs.empty() ? 32 : (capacity < slabSize ? capacity * 2 : slabSize);
      void *slab = ::operator new(nextCapacity * sizeof(T));
      try {
        slabs.push_back(Slab{slab, nextCapacity});
      } catch (...) {
        ::operator delete(slab);
        throw;
      }
#ifdef GHIDRA_SLAB_ASAN
      ASAN_POISON_MEMORY_REGION(slab, nextCapacity * sizeof(T));
#endif
      capacity = nextCapacity;
      used = 0;
    }
    void *slot = static_cast<char *>(slabs.back().storage) + used++ * sizeof(T);
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
    for(const Slab &slab : slabs) {
#ifdef GHIDRA_SLAB_ASAN
      ASAN_UNPOISON_MEMORY_REGION(slab.storage, slab.capacity * sizeof(T));
#endif
      ::operator delete(slab.storage);
    }
    slabs.clear();
    capacity = 32;
    used = capacity;
    freeList = nullptr;
  }
};

} // End namespace ghidra
#endif
