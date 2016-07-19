#include "fabs_conf.hpp"
#include "fabs_bytes.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include <yaml-cpp/yaml.h>

using namespace std;

fabs_conf::fabs_conf()
{

}

fabs_conf::~fabs_conf()
{

}

bool
fabs_conf::read_conf(string conf)
{
    try {
        YAML::Node config = YAML::LoadFile(conf);

        for (YAML::const_iterator it = config.begin(); it != config.end(); ++it) {
            std::string key = it->first.as<std::string>();
            for (YAML::const_iterator itc = it->second.begin();
                itc != it->second.end(); ++itc) {
                std::string keyc = itc->first.as<std::string>();
                std::string val  = itc->second.as<std::string>();
                m_conf[key][keyc] = val;
            }
        }
    } catch (YAML::BadFile e) {
        std::cerr << "warning: could not read config file" << std::endl;
    }

    return true;
}
