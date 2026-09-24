#include "dwarf_types.h"

extern "C" __attribute__((noinline)) double dwarf_scale(DwarfPayload *payload,
                                                        double factor) {
  const double scaled = static_cast<double>(payload->total) * factor;
  return scaled + payload->tag;
}
