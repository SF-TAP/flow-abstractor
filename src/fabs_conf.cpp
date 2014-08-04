#include "fabs_conf.hpp"
#include "fabs_bytes.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

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
    ifstream   ifs(conf);
    string     section;

    enum {
        SECTION,
        KEY_VALUE,
    } state = SECTION;

    while (ifs) {
        int n = 1;
        string line, line2;
        std::getline(ifs, line);

        line2 = trim(line);
        if (line2.size() > 0 && line2[0] == '#')
            continue;

        stringstream s1(line);
        std::getline(s1, line, '#');

        if (line.size() == 0)
            continue;

    sec:
        switch (state) {
        case SECTION:
        {
            stringstream s2(line);
            std::getline(s2, line, ':');

            line = trim(line);

            section = line;

            state = KEY_VALUE;

            break;
        }
        case KEY_VALUE:
        {
            stringstream s3(line);
            char c;

            c = (char)s3.peek();

            if (c != ' ') {
                state = SECTION;
                goto sec;
            } else {
                for (int i = 0; i < 4; i++) {
                    s3.get(c);

                    if (c != ' ') {
                        cerr << "An error occurred while reading config file \""
                             << conf << ":" << n
                             << "\". The indent must be 4 bytes white space."
                             << endl;
                        return false;
                    }
                }

                string key, value;
                std::getline(s3, key, '=');
                std::getline(s3, value);

                key   = trim(key);
                value = trim(value);


                m_conf[section][key] = value;
            }

            break;
        }
        }
    }

    return true;
}
