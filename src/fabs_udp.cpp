#include "fabs_udp.hpp"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <iostream>
#include <sstream>
#include <string>

using namespace std;

fabs_udp::fabs_udp()
{

}

fabs_udp::~fabs_udp()
{

}

void
fabs_udp::input_udp(fabs_id &id, fabs_direction dir, fabs_bytes *buf)
{
    // TODO: checksum
    fabs_id_dir id_dir;

    id_dir.m_id  = id;
    id_dir.m_dir = dir;

    if (buf->skip(sizeof(udphdr))) {
        m_appif->in_event(STREAM_DATA, id_dir, buf);
    }
}
