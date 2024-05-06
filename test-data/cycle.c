#include "ckb_syscalls.h"
// #include "secp256k1_helper.h"
#define CKB_SUCCESS 0
///************************************************************************************************
// #include "secp256k1_lock.h"
// #include "blake2b.h"
#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SCRIPT_TOO_LONG -21
///************************************************************************************************
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768

#define ERROR_WITNESS_SIZE -22

#define         MolReader_WitnessArgs_get_lock(s)               mol_table_slice_by_index(s, 0)

int read_args(uint64_t *loop)
{
  int ret;
  /* Load witness of first input */
  uint64_t witness_len = 8;
  ret = ckb_load_witness(loop, &witness_len, 0, 0,
                         CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > 8) {
    return MAX_WITNESS_SIZE;
  }

  return CKB_SUCCESS;
}

int main()
{
    int ret;
    /* read script args */
    uint64_t cnt = 0;
    ret = read_args(&cnt);
    // printf("cnt: %lu\n", cnt);
    if (ret != CKB_SUCCESS)
    {
        return ret;
    }
    uint64_t sum = 0;
    for (uint64_t i = 0; i < cnt; ++i)
    {
        sum |= i;
    }
    return cnt <= 1 || sum > 0 ? CKB_SUCCESS : 127;
}
