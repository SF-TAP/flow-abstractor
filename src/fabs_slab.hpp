#ifndef FABS_SLAB_HPP
#define FABS_SLAB_HPP

#include "fabs_spin_lock.hpp"

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <immintrin.h>
#include <smmintrin.h>

#define POWEROF2(x) ((x) != 0 && ((x) & ((x) - 1)) == 0)

#define TZCNTQ(DST, SRC)        \
    do {                        \
        asm (                   \
            "tzcntq %1, %0;"    \
            : "=r" (DST)        \
            : "r" (SRC)         \
            );                  \
    } while (0)

inline uint64_t
tzcntq(uint64_t num)
{
#ifdef __x86_64__
    uint64_t ret;
    TZCNTQ(ret, num);
    return ret;
#else
    return __builtin_ctzll(num);
#endif // __x86_64__
}

template <typename T>
class fabs_slab {
    struct slab {
        uint64_t  m_full[4];
        uint64_t  m_mask_tier1[4];
        uint64_t  m_mask_tier2[64 * 4];
        T        *m_ptr;
        slab     *m_prev;
        slab     *m_next;

        slab() : m_prev(nullptr), m_next(nullptr)
        {
            for (int i = 0; i < 4; i++)
                m_full[i] = -1;

            for (int i = 0; i < 4; i++)
                m_mask_tier1[i] = 0;

            for (int i = 0; i < 64 * 4; i++)
                m_mask_tier2[i] = 0;

            m_ptr = (T*)(new char[64 * 64 * 4 * sizeof(T)]);
        }

        ~slab()
        {
            delete[] (char*)m_ptr;
        }

        T* allocate()
        {
            uint64_t idx1 = get_idx_tier1();

            if (idx1 == 4) {
                if (m_next == nullptr) {
                    m_next = new slab;
                    m_next->m_prev = this;
                }

                return m_next->allocate();
            }

            uint64_t idx2 = get_idx_tier2(idx1);
            uint64_t idx3 = get_idx_tier3(idx1, idx2);

            auto idx = idx1 * 64 + idx2;
            m_mask_tier2[idx] |= ((uint64_t)1 << idx3);

            if (m_mask_tier2[idx] == (uint64_t)-1) {
                m_mask_tier1[idx1] |= ((uint64_t)1 << idx2);
            }

            return &m_ptr[idx1 * 64 * 64 + idx2 * 64 + idx3];
        }

        void deallocate(T *ptr)
        {
            static int shift1 = tzcntq(64 * 64);
            static int shift2 = tzcntq(64);
            static int shift3 = tzcntq(sizeof(T));
            static uint64_t mask1 = 64 * sizeof(T) - 1;
            static uint64_t mask2 = sizeof(T) - 1;

            if (m_ptr <= ptr && ptr < m_ptr + 64 * 64 * 4) {
                auto diff = ptr - m_ptr;

                uint64_t idx1 = diff >> shift1;
                uint64_t idx2 = (diff >> shift2) & ((uint64_t)64 - 1);
                uint64_t idx3 = diff & ((uint64_t)64 - 1);

                m_mask_tier1[idx1] &= ~((uint64_t)1 << idx2);
                m_mask_tier2[idx1 * 64 + idx2] &= ~((uint64_t)1 << idx3);
            } else {
                if (m_next)
                    m_next->deallocate(ptr);
            }
        }

        void print(int chain = 0)
        {
            printf("chan = %d\n", chain);
            printf("T1:     %016llx %016llx %016llx %016llx\n", m_mask_tier1[3], m_mask_tier1[2], m_mask_tier1[1], m_mask_tier1[0]);
            printf("---------------------------------------------------------------------------\n");

            for (int i = 63; i >= 0; i--) {
                printf("T2[%02d]: %016llx %016llx %016llx %016llx\n", i,
                    m_mask_tier2[i * 4 + 3], m_mask_tier2[i * 4 + 2],
                    m_mask_tier2[i * 4 + 1], m_mask_tier2[i * 4]);
            }

            if (m_next)
                m_next->print(chain + 1);
        }

    private:
        uint64_t get_idx_tier1()
        {
            __m256i full = _mm256_lddqu_si256((__m256i const *)&m_full[0]);
            __m256i mask = _mm256_lddqu_si256((__m256i const *)&m_mask_tier1[0]);
            __m256i cmp  = _mm256_cmpeq_epi64(full, mask);
            int     bits = _mm256_movemask_pd(cmp);

            return tzcntq(~bits);
        }

        uint64_t get_idx_tier2(uint64_t idx)
        {
            return tzcntq(~m_mask_tier1[idx]);
        }

        uint64_t get_idx_tier3(uint64_t idx1, uint64_t idx2)
        {
            return tzcntq(~m_mask_tier2[idx1 * 64 + idx2]);
        }
    };

public:
    fabs_slab()
    {
        assert(POWEROF2(sizeof(T)));
    }

    ~fabs_slab()
    {

    }

    T* allocate()
    {
        //fabs_spin_lock_ac lock(m_lock);
        return m_slab.allocate();
    }

    void deallocate(T *ptr)
    {
        //fabs_spin_lock_ac lock(m_lock);
        m_slab.deallocate(ptr);
    }

    void print()
    {
        m_slab.print();
    }

private:
    fabs_spin_lock m_lock;
    slab           m_slab;
};

#endif // FABS_SALB_HPP