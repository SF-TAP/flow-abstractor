#ifndef FABS_CONF_HPP
#define FABS_CONF_HPP

#include "fabs_common.hpp"

#include <map>
#include <string>

class fabs_conf {
public:
    fabs_conf();
    virtual ~fabs_conf();

    bool read_conf(std::string conf);

    std::map<std::string, std::map<std::string, std::string> > m_conf;

};

#endif // FABS_CONF_HPP
