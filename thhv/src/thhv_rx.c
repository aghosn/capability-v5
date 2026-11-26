// SPDX-License-Identifier: GPL-2.0
/* DomainComm receive dispatch shared by VP returns and deferred IRQ work. */

#include <linux/errno.h>

#include "thhv_internal.h"

void thhv_drain_domcomm_rx(struct thhv_partition *part)
{
	struct domcomm_ring *rx = &thhv_domcomm.rx;
	struct domcomm_doorbell_event event;
	u32 msg_type, payload_size;
	int ret;

	mutex_lock(&thhv_domcomm_lock);
	for (;;) {
		ret = domcomm_rx_dequeue(rx, &event, sizeof(event),
					 &msg_type, &payload_size);
		if (ret == -EAGAIN)
			break;
		if (ret == -ENOSPC) {
			u32 drop_type = 0, drop_size = 0;
			int dret = domcomm_rx_discard(rx, &drop_type, &drop_size);

			if (dret < 0) {
				pr_warn_ratelimited("thhv: domcomm RX discard failed: %d\n",
						    dret);
				break;
			}
			pr_warn_ratelimited("thhv: dropped oversized RX msg type=%u size=%u\n",
					    drop_type, drop_size);
			continue;
		}
		if (ret < 0) {
			pr_warn_ratelimited("thhv: domcomm RX dequeue error: %d\n", ret);
			break;
		}
		if (msg_type == DOMCOMM_MSG_DOORBELL_EVENT)
			thhv_dispatch_doorbell_event(&event, payload_size);
		else if (msg_type != DOMCOMM_MSG_GROW_ACK)
			pr_debug("thhv: domcomm RX: unhandled msg_type %#x (size %u)\n",
				 msg_type, payload_size);
	}
	mutex_unlock(&thhv_domcomm_lock);
}
