#include <rz_analysis.h>
#include <stdio.h>
#include <stdlib.h>

static void append_piece(RzAnalysisVarStorage *storage, ut64 offset) {
  RzAnalysisVarStorage *piece = calloc(1, sizeof(*piece));
  if (!piece)
    abort();
  rz_analysis_var_storage_init_stack(piece, 8);
  RzAnalysisVarStoragePiece description = {
      .offset_in_bits = offset, .size_in_bits = 32, .storage = piece};
  if (!rz_vector_push(storage->composite, &description))
    abort();
}

int main(void) {
  RzAnalysisVarStorage shorter = {0}, longer = {0};
  rz_analysis_var_storage_init_composite(&shorter);
  rz_analysis_var_storage_init_composite(&longer);
  if (!shorter.composite || !longer.composite)
    abort();
  append_piece(&shorter, 0);
  append_piece(&longer, 0);
  append_piece(&longer, 32);
  const bool distinct = !rz_analysis_var_storage_equals(&shorter, &longer) &&
                        !rz_analysis_var_storage_equals(&longer, &shorter);
  rz_analysis_var_storage_fini(&shorter);
  rz_analysis_var_storage_fini(&longer);

  RzAnalysisVarStorage low = {0}, high = {0};
  rz_analysis_var_storage_init_stack(&low, 0);
  rz_analysis_var_storage_init_stack(&high, (st64)1 << 40);
  if (!distinct || rz_analysis_var_storage_equals(&low, &high) ||
      rz_analysis_var_storage_equals(&high, &low)) {
    fputs("Distinct DWARF locations compared equal\n", stderr);
    return 1;
  }
  return 0;
}
