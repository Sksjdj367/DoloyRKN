// SPDX-License-Identifier: GPL-3.0-or-later

#include <errno.h>
#include <netinet/in.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#include "util/log.hpp"
#include "net/l3.hpp"
#include "net/l4.hpp"

#include "platform/linux/netfilter_util.hpp"

using namespace logs;

namespace Platform
{
using namespace logs;
[[nodiscard]]
bool fillPacketInfo(NetfilterPacketInfo* packetInfo, nfq_data* nfad)
{
    auto nfqnlHdr = nfq_get_msg_packet_hdr(nfad);
    if (!nfqnlHdr)
    {
        pr_errno(errno, "Cannot get nfqnl packet header\n");
        return 0;
    }

    packetInfo->id = ntohl(nfqnlHdr->packet_id);

    if (packetInfo->id == 0)
    {
        pr_errno(errno, "Cannot get packet id (id=0)\n");
        return 0;
    }

    int payload_len = nfq_get_payload(nfad, &packetInfo->data);
    if (payload_len < 0)
    {
        pr_errno(errno, "Cannot get packet content from nfad\n");
        return 0;
    }
    packetInfo->data_len = static_cast<uint32_t>(payload_len);

    packetInfo->mark = nfq_get_nfmark(nfad);

    return 1;
}
} // namespace Platform
