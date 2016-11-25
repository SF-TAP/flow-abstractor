#ifndef FABS_DLCAP_HPP
#define FABS_DLCAP_HPP

#ifdef USE_PERF
    #include <time.h>
#endif // USE_PERF

class fabs_dlcap {
public:
    fabs_dlcap() { }
    virtual ~fabs_dlcap() { }

    virtual void print_stat() const = 0;

#ifdef USE_PERF
    fabs_dlcap(time_t t) {
        m_time_end = time(nullptr) + t;
    }

    bool is_time_to_end() {
        return time(nullptr) > m_time_end;
    }

private:
    time_t m_time_end;
#endif // USE_PERF

};

#endif // FABS_DLCAP_HPP
