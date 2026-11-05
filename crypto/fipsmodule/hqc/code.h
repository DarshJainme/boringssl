#ifndef OPENSSL_HEADER_CRYPTO_FIPSMODULE_HQC_CODE_H
#define OPENSSL_HEADER_CRYPTO_FIPSMODULE_HQC_CODE_H

/**
 * @file code.h
 * @brief Header file of code.cc.inc
 */

#include "params.h"
#include <stddef.h>
#include <stdint.h>

namespace bssl {

void code_encode(uint64_t *codeword, const uint64_t *message);
void code_decode(uint64_t *message, const uint64_t *vector);

}  // namespace bssl

#endif  // OPENSSL_HEADER_CRYPTO_FIPSMODULE_HQC_CODE_H