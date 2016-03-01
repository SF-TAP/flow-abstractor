#include "fabs_callback.hpp"

#include "fabs_id.hpp"

#include <netinet/in.h>

using namespace std;

fabs_callback::fabs_callback()
{

}

void
fabs_callback::operator() (int idx, ptr_fabs_bytes buf) {
    fabs_direction dir;
    fabs_id        id;
    char          *l4hdr;
    int            len; // payload length

    dir = id.set_iph(buf->get_head(), &l4hdr, &len);

    if (l4hdr == NULL || dir == FROM_NONE) {
        return;
    }

    if (! buf->skip(l4hdr - buf->get_head()))
        return;

    if (len < buf->get_len()) {
        if (! buf->skip_tail(buf->get_len() - len)) { // skip ethernet padding
            return;
        }
    }

    switch (id.get_l4_proto()) {
    case IPPROTO_TCP:
        m_tcp[idx].input_tcp(id, dir, buf);
        break;
    case IPPROTO_UDP:
        m_udp.input_udp(id, dir, buf);
        break;
    default:
        ;
    }
}
