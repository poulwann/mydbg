#include "dwarf_types.h"

extern "C" __attribute__((used)) inline DwarfCount
dwarf_inherited(DwarfCount input) {
  return input + 23;
}

extern "C" __attribute__((noinline)) DwarfCount
dwarf_secondary(DwarfPayload *payload, DwarfCount increment) {
  return payload->total + increment + dwarf_inherited(increment);
}
