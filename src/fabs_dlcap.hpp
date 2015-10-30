#ifndef FABS_DLCAP_HPP
#define FABS_DLCAP_HPP

class fabs_dlcap {
public:
    fabs_dlcap() { }
    virtual ~fabs_dlcap() { }

    virtual void print_stat() const = 0;
};

#endif // FABS_DLCAP_HPP
