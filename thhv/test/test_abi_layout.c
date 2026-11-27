/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <stdio.h>

#include "thhv.h"

#define CHECK_FIELD(type, field, rust_offset) \
	_Static_assert(offsetof(struct type, field) == (rust_offset), #type "." #field)
#define CHECK_SIZE(type, rust_size) \
	_Static_assert(sizeof(struct type) == (rust_size), #type " size")

_Static_assert((~PV_KNOWN_SERVICES & (1ULL << 63)) != 0,
	       "C service mask must reject unknown high bits");

CHECK_FIELD(domcomm_header, version_major, DOMCOMM_VERSION);
CHECK_FIELD(domcomm_header, total_pages, DOMCOMM_TOTAL_PAGES);
CHECK_FIELD(domcomm_header, rx.head, DOMCOMM_RX_HEAD);
CHECK_FIELD(domcomm_header, rx.tail, DOMCOMM_RX_TAIL);
CHECK_FIELD(domcomm_header, rx.page_offset, DOMCOMM_RX_PAGE_OFFSET);
CHECK_FIELD(domcomm_header, rx.page_count, DOMCOMM_RX_PAGE_COUNT);
CHECK_SIZE(domcomm_msg_header, DOMCOMM_MSG_HDR_SIZE);
CHECK_FIELD(domcomm_msg_header, message_type, DOMCOMM_MSG_TYPE);
CHECK_FIELD(domcomm_msg_header, total_size, DOMCOMM_MSG_SIZE);
CHECK_SIZE(domcomm_attest_report, ATTEST_HEADER_SIZE);
CHECK_SIZE(domcomm_signed_envelope, ATTEST_SIGNED_ENVELOPE_SIZE);
CHECK_FIELD(domcomm_attest_report, domain_id, ATTEST_DOMAIN_ID);
CHECK_FIELD(domcomm_attest_report, flags, ATTEST_FLAGS);
CHECK_FIELD(domcomm_attest_report, nr_mem_caps, ATTEST_NUM_MEM_CAPS);
CHECK_FIELD(domcomm_attest_report, nr_dom_caps, ATTEST_NUM_DOM_CAPS);
CHECK_FIELD(domcomm_attest_report, nr_pa_entries, ATTEST_NUM_PA_ENTRIES);
CHECK_FIELD(domcomm_attest_report, nr_doorbells, ATTEST_NUM_DOORBELLS);
CHECK_SIZE(domcomm_mem_cap_entry, ATTEST_MEM_CAP_SIZE);
CHECK_SIZE(domcomm_dom_cap_entry, ATTEST_DOM_CAP_SIZE);
CHECK_SIZE(domcomm_pa_map_entry, ATTEST_PA_MAP_SIZE);
CHECK_SIZE(domcomm_doorbell_entry, ATTEST_DOORBELL_SIZE);
CHECK_FIELD(domcomm_doorbell_entry, recipient, ATTEST_DOORBELL_RECIPIENT);
CHECK_FIELD(domcomm_doorbell_entry, port, ATTEST_DOORBELL_PORT);
CHECK_FIELD(domcomm_doorbell_entry, handle, ATTEST_DOORBELL_HANDLE);
CHECK_FIELD(domcomm_doorbell_entry, vp, ATTEST_DOORBELL_VP);
CHECK_FIELD(domcomm_doorbell_entry, kind, ATTEST_DOORBELL_KIND);
CHECK_FIELD(domcomm_doorbell_entry, reserved, ATTEST_DOORBELL_RESERVED);

int main(void)
{
	puts("PASS: C DomainComm layouts match the Rust-generated ABI");
	return 0;
}
