#include "blake2b.h"
#include "blockchain.h"
#include "ckb_syscalls.h"
#include "secp256k1_helper.h"
#include "secp256k1_lock.h"
#define SCRIPT_SIZE 32768

int read_args(uint64_t *loop)
{
    int ret;
    uint64_t len = 0;
//    char buf[4096];

    /* Load args */
    unsigned char script[SCRIPT_SIZE];
    len = SCRIPT_SIZE;
    ret = ckb_load_script(script, &len, 0);
    if (ret != CKB_SUCCESS)
    {
        return ERROR_SYSCALL;
    }
    if (len > SCRIPT_SIZE)
    {
        return ERROR_SCRIPT_TOO_LONG;
    }
    mol_seg_t script_seg;
    script_seg.ptr = (uint8_t *)script;
    script_seg.size = len;

    if (MolReader_Script_verify(&script_seg, false) != MOL_OK)
    {
        return ERROR_ENCODING;
    }

    mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
    mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
    if (args_bytes_seg.size != 8)
    {
        return ERROR_ARGUMENTS_LEN;
    }

    *loop = *(uint64_t*)args_bytes_seg.ptr;
    // memcpy(loop, args_bytes_seg.ptr, 8);
    // sprintf_(buf, "loop times is %lu", *loop);
    // ckb_debug(buf);
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
