// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/can_socketcan.hpp"

namespace conduitscope {

CanSocketcanFrame parse_socketcan_frame(ByteSpan frame) {
    // 8-byte fixed header: 4-byte big-endian CAN ID + flags, 1-byte Payload Length, 1-byte FD
    // Flags, 2 reserved bytes -- see this file's header comment. Fewer than 8 bytes present means
    // there isn't even a complete header to read; ParseError propagates to Decoder::decode's
    // existing outer catch, same as an undersized Ethernet frame from parse_ethernet.
    Cursor c(frame);
    CanSocketcanFrame f;
    f.can_id_raw = c.u32be();
    f.eff = (f.can_id_raw & CAN_EFF_FLAG) != 0;
    f.rtr = (f.can_id_raw & CAN_RTR_FLAG) != 0;
    f.err = (f.can_id_raw & CAN_ERR_FLAG) != 0;
    f.id = f.can_id_raw & (f.eff ? CAN_EFF_MASK : CAN_SFF_MASK);

    f.payload_length_declared = c.u8();
    f.fd_flags = c.u8();
    f.fd = (f.fd_flags & CANFD_FDF_FLAG) != 0;
    c.skip(2);  // two reserved bytes -- see file header comment, never surfaced

    // Truncation handling -- see this file's header comment's "Truncation handling" paragraph.
    // The header itself is already fully consumed at this point (8 bytes read above), so a short
    // payload is handled tolerantly rather than thrown: clamp to whatever is actually present.
    size_t available = c.remaining();
    size_t take = static_cast<size_t>(f.payload_length_declared);
    if (take > available) {
        f.truncated = true;
        f.notes.push_back("Payload Length declares " + std::to_string(f.payload_length_declared) +
                           " byte(s) but only " + std::to_string(available) +
                           " byte(s) remain in the captured record -- payload clamped to what was "
                           "actually captured");
        take = available;
    }
    f.payload = c.bytes(take);
    return f;
}

}  // namespace conduitscope
