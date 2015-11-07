#ifndef FABS_EXCLUSIVE_PTR
#define FABS_EXCLUSIVE_PTR

template <typename T>
class fabs_exclusive_ptr {
public:
    fabs_exclusive_ptr() : m_ptr(nullptr) { }
    fabs_exclusive_ptr(T *ptr) : m_ptr(ptr) { }
    fabs_exclusive_ptr(const fabs_exclusive_ptr &rhs)
    {
        m_ptr = rhs.m_ptr;
        const_cast<fabs_exclusive_ptr*>(&rhs)->m_ptr = nullptr;
    }
    virtual ~fabs_exclusive_ptr() { delete m_ptr; }

    fabs_exclusive_ptr<T>&
    operator=(fabs_exclusive_ptr<T> &rhs)
    {
        delete m_ptr;

        m_ptr = rhs.m_ptr;
        rhs.m_ptr = nullptr;

        return *this;
    }

    volatile fabs_exclusive_ptr<T>&
    operator=(fabs_exclusive_ptr<T> &rhs) volatile
    {
        delete m_ptr;
        
        m_ptr = rhs.m_ptr;
        rhs.m_ptr = nullptr;

        return *this;
    }

    T* operator->() { return m_ptr; }

    T* get() { return m_ptr; }

private:
    T *m_ptr;
};

#endif // FABS_EXCLUSIVE_PTR
