#include "dwarf_types.h"

volatile DwarfPayload dwarf_total{4, 19, {.word = 1}};

__attribute__((always_inline)) inline DwarfCount
dwarf_inline(DwarfCount value) {
  volatile DwarfCount inline_seed = value ^ 5;
  return inline_seed + 2;
}

extern "C" __attribute__((noinline)) DwarfCount
dwarf_compute(DwarfPayload *payload, int bias, DwarfMode mode) {
  DwarfCount adjusted = dwarf_inline(payload->total) + bias;
  if (mode == DwarfDouble) {
    volatile DwarfCount correction = dwarf_total.total;
    adjusted += correction;
  }
  return adjusted + payload->choice.word + payload->tag;
}

int main() {
  DwarfPayload payload{2, 17, {.word = 11}};
  const auto result = dwarf_compute(&payload, 3, DwarfDouble);
  return static_cast<int>(result + dwarf_secondary(&payload, 4) +
                          dwarf_scale(&payload, 1.5)) == 0;
}
