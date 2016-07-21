#ifndef FABS_RWLOCK_HPP
#define FABS_RWLOCK_HPP

#include <pthread.h>

class fabs_rwlock_read;
class fabs_rwlock_write;

class fabs_rwlock {
public:
    fabs_rwlock() : m_lock(PTHREAD_RWLOCK_INITIALIZER) { }

private:
    pthread_rwlock_t m_lock;

    friend class fabs_rwlock_read;
    friend class fabs_rwlock_write;
};

class fabs_rwlock_read {
public:
    fabs_rwlock_read(fabs_rwlock &lock) : m_lock(lock) {
        pthread_rwlock_rdlock(&lock.m_lock);
    }

    ~fabs_rwlock_read() {
        pthread_rwlock_unlock(&m_lock.m_lock);
    }

private:
    fabs_rwlock &m_lock;
};

class fabs_rwlock_write {
public:
    fabs_rwlock_write(fabs_rwlock &lock) : m_lock(lock) {
        pthread_rwlock_wrlock(&lock.m_lock);
    }

    ~fabs_rwlock_write() {
        pthread_rwlock_unlock(&m_lock.m_lock);
    }

private:
    fabs_rwlock &m_lock;
};

#endif // FABS_RWLOCK_HPP