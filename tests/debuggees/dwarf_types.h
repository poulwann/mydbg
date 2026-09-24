#pragma once

using DwarfCount = long;
enum DwarfMode : unsigned char { DwarfKeep = 3, DwarfDouble = 7 };
union DwarfChoice {
  unsigned int word;
  float fraction;
};
struct DwarfPayload {
  unsigned char tag;
  DwarfCount total;
  DwarfChoice choice;
};

extern "C" {
extern volatile DwarfPayload dwarf_total;
DwarfCount dwarf_compute(DwarfPayload *payload, int bias, DwarfMode mode);
DwarfCount dwarf_secondary(DwarfPayload *payload, DwarfCount increment);
double dwarf_scale(DwarfPayload *payload, double factor);
}
