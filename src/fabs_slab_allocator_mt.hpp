#ifndef FABS_SLAB_ALLOCATOR_MT
#define FABS_SLAB_ALLOCATOR_MT

/*
 * This allocator is MT-safe.
 */

#include <new>
#include <limits>

#include <stdlib.h>

#include "slab.hpp"
#include "fabs_rtm_lock.hpp"

template <typename T>
class fabs_slab_allocator_mt {
public:
    typedef T         value_type;
    typedef size_t    size_type;
    typedef ptrdiff_t difference_type;
    typedef T*        pointer;
    typedef const T*  const_pointer;
    typedef T&        reference;
    typedef const T&  const_reference;

    template <typename U> struct rebind { typedef fabs_slab_allocator_mt<U> other; };
    fabs_slab_allocator_mt() throw()
    {
        fabs_rtm_transaction lock(m_rtm_lock);

        if (fabs_slab_allocator_mt<T>::m_refcnt == 0)
            slab_init(&m_slab, sizeof(T));

        fabs_slab_allocator_mt<T>::m_refcnt++;
    }
    fabs_slab_allocator_mt(const fabs_slab_allocator_mt&) throw()
    {
        fabs_rtm_transaction lock(m_rtm_lock);

        if (fabs_slab_allocator_mt<T>::m_refcnt == 0)
            slab_init(&m_slab, sizeof(T));

        fabs_slab_allocator_mt<T>::m_refcnt++;
    }

    template <typename U> fabs_slab_allocator_mt(const fabs_slab_allocator_mt<U>&) throw()
    {
        fabs_rtm_transaction lock(m_rtm_lock);

        if (fabs_slab_allocator_mt<U>::m_refcnt == 0)
            slab_init(&fabs_slab_allocator_mt<U>::m_slab, sizeof(U));

        fabs_slab_allocator_mt<U>::m_refcnt++;
    }

    ~fabs_slab_allocator_mt() throw() {
        fabs_rtm_transaction lock(m_rtm_lock);

        m_refcnt--;

        if (m_refcnt == 0)
            slab_destroy(&m_slab);
    }

    pointer address(reference x) const { return &x; }
    const_pointer address(const_reference x) const { return &x; }

    pointer allocate(size_type s, void const * = 0) {
        if (s == 1) {
            fabs_rtm_transaction lock(m_rtm_lock);
            return (pointer)slab_alloc(&m_slab);
        } else if (s >= 1) {
            pointer temp = (pointer)malloc(sizeof(void*) + s * sizeof(T));
            if (temp == nullptr)
                return nullptr;

            void **vp = (void**)temp;
            *vp = (void*)~(uint64_t)0;

            return (pointer)((char*)temp + sizeof(void*));
        } else {
            return nullptr;
        }
    }

    void deallocate(pointer p, size_type) {
        void **vp = (void**)((char*)p - sizeof(void*));

        if (*vp == (void*)~(uint64_t)0) {
            free(vp);
        } else {
            fabs_rtm_transaction lock(m_rtm_lock);
            slab_free(&m_slab, p);
        }
    }

    size_type max_size() const throw() {
        return std::numeric_limits<size_t>::max() / sizeof(T);
    }

    void construct(pointer p, const T& val) {
        new((void *)p) T(val);
    }

    void destroy(pointer p) {
        p->~T();
    }

    static fabs_rtm_lock   m_rtm_lock;
    static uint64_t        m_refcnt;
    static slab_chain      m_slab;
};

template <typename T> fabs_rtm_lock   fabs_slab_allocator_mt<T>::m_rtm_lock;
template <typename T> uint64_t        fabs_slab_allocator_mt<T>::m_refcnt = 0;
template <typename T> slab_chain      fabs_slab_allocator_mt<T>::m_slab;

#endif // FABS_SLAB_ALLOCATOR_MT