#ifndef FABS_SPIN_RWLOCK_HPP
#define FABS_SPIN_RWLOCK_HPP

#include <pthread.h>

#if defined(__x86_64__) || defined(__i686__)
  #include <xmmintrin.h>
  #define _MM_PAUSE _mm_pause()
#else
  #define _MM_PAUSE
#endif // __x86_64__ || __i386__

class fabs_spin_rwlock_read;
class fabs_spin_rwlock_write;

class fabs_spin_rwlock {
public:
    fabs_spin_rwlock() : m_read_count(0), m_write_count(0)
    {
        pthread_mutex_init(&m_read_mutex, nullptr);
        pthread_mutex_init(&m_write_mutex, nullptr);
        pthread_cond_init(&m_read_cond, nullptr);
    }

private:
    volatile int    m_read_count;
    volatile int    m_write_count;
    pthread_mutex_t m_read_mutex;
    pthread_mutex_t m_write_mutex;
    pthread_cond_t  m_read_cond;

    friend class fabs_spin_rwlock_read;
    friend class fabs_spin_rwlock_write;
};

class fabs_spin_rwlock_read {
public:
    fabs_spin_rwlock_read(fabs_spin_rwlock &lock) : m_lock(lock) {
        while (lock.m_write_count) {
            pthread_mutex_lock(&lock.m_read_mutex);
            timespec tspec = {0, 1000};
            pthread_cond_timedwait(&lock.m_read_cond, &lock.m_read_mutex, &tspec);
            pthread_mutex_unlock(&lock.m_read_mutex);
        }

        __sync_fetch_and_add(&lock.m_read_count, 1);
    }

    ~fabs_spin_rwlock_read() {
        unlock();
    }

    void unlock() {
        __sync_fetch_and_sub(&m_lock.m_read_count, 1);
    }

private:
    fabs_spin_rwlock &m_lock;
};

class fabs_spin_rwlock_write {
public:
    fabs_spin_rwlock_write(fabs_spin_rwlock &lock) : m_lock(lock) {
        __sync_fetch_and_add(&lock.m_write_count, 1);

        while(lock.m_read_count) _MM_PAUSE;

        pthread_mutex_lock(&lock.m_write_mutex);
    }

    ~fabs_spin_rwlock_write() {
        unlock();
    }

    void unlock() {
        pthread_mutex_unlock(&m_lock.m_write_mutex);
        __sync_fetch_and_sub(&m_lock.m_write_count, 1);

        if (m_lock.m_write_count == 0) {
            pthread_mutex_lock(&m_lock.m_read_mutex);
            pthread_cond_broadcast(&m_lock.m_read_cond);
        }
    }

private:
    fabs_spin_rwlock &m_lock;
};

#endif // FABS_SPIN_RWLOCK_HPP
