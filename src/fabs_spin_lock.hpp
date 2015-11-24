#ifndef FABS_SPIN_LOCK_HPP
#define FABS_SPIN_LOCK_HPP

#if defined(__x86_64__) || defined(__i686__)
  #include <xmmintrin.h>
  #define _MM_PAUSE _mm_pause
#else
  #define _MM_PAUSE
#endif // __x86_64__ || __i386__

class fabs_spin_lock_ac;

class fabs_spin_lock {
public:
    fabs_spin_lock() : m_lock(0) { }
    ~fabs_spin_lock() { }

private:
    volatile int m_lock;

    friend class fabs_spin_lock_ac;
};

class fabs_spin_lock_ac {
public:
    fabs_spin_lock_ac(fabs_spin_lock &lock) : m_lock(lock)
    {
        while (__sync_lock_test_and_set(&lock.m_lock, 1)) {
            while (lock.m_lock) _MM_PAUSE(); // busy-wait
        }
    }

    ~fabs_spin_lock_ac()
    {
        __sync_lock_release(&m_lock.m_lock);
    }

private:
    fabs_spin_lock &m_lock;
};

#endif // FABS_SPIN_LOCK_HPP
