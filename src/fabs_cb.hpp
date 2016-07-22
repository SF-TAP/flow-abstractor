#ifndef FABS_CB_HPP
#define FABS_CB_HPP

#include "fabs_spin_lock.hpp"

#include <iostream>

#define QNUM (1024 * 10)

// multiple writers and single reader
template <typename T>
class fabs_cb {
public:
    fabs_cb() : m_max_len(QNUM),
                m_len(0),
                m_buf(new T[m_max_len]),
                m_buf_end(m_buf + m_max_len),
                m_head(m_buf),
                m_tail(m_buf) { }
    virtual ~fabs_cb() { delete[] m_buf; }

    bool pop(T *p);
    bool push(T &val);
    int  get_len() { return m_len; }

private:
    int m_max_len;
    volatile int m_len;
    T *m_buf;
    T *m_buf_end;

    T *m_head;
    T *m_tail;

    fabs_spin_lock m_lock;
};

template <typename T>
inline bool fabs_cb<T>::pop(T *p)
{
    if (m_len == 0) {
        return false;
    }

    *p = *m_head;

    {
        fabs_spin_lock_ac lock(m_lock);
        m_len--;
    }

    m_head++;

    if (m_head == m_buf_end) {
        m_head = m_buf;
    }

    return true;
}

template <typename T>
inline bool fabs_cb<T>::push(T &val)
{
    if (m_len == m_max_len) {
        return false;
    }

    fabs_spin_lock_ac lock(m_lock);

    *m_tail = val;
    m_len++;
    m_tail++;

    if (m_tail == m_buf_end) {
        m_tail = m_buf;
    }

    return true;
}


template <>
inline bool fabs_cb<ptr_fabs_bytes>::pop(ptr_fabs_bytes *p)
{
    if (m_len == 0) {
        return false;
    }

    *p = std::move(*m_head);

    {
        fabs_spin_lock_ac lock(m_lock);
        m_len--;
    }

    m_head++;

    if (m_head == m_buf_end) {
        m_head = m_buf;
    }

    return true;
}

template <>
inline bool fabs_cb<ptr_fabs_bytes>::push(ptr_fabs_bytes &val)
{
    if (m_len == m_max_len) {
        return false;
    }

    fabs_spin_lock_ac lock(m_lock);

    *m_tail = std::move(val);
    m_len++;
    m_tail++;

    if (m_tail == m_buf_end) {
        m_tail = m_buf;
    }

    return true;
}

#endif // FABS_CB_HPP
