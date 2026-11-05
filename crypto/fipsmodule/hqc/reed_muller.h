#ifndef OPENSSL_HEADER_CRYPTO_FIPSMODULE_HQC_REED_MULLER_H
#define OPENSSL_HEADER_CRYPTO_FIPSMODULE_HQC_REED_MULLER_H

/**
 * @file reed_muller.h
 * @brief Header file of reed_muller.cc.inc
 */

#include "params.h"
#include <stddef.h>
#include <stdint.h>

namespace bssl {

void reed_muller_encode(uint64_t *cdw, const uint64_t *msg);
void reed_muller_decode(uint64_t *msg, const uint64_t *cdw);

}  // namespace bssl

#endif  // OPENSSL_HEADER_CRYPTO_FIPSMODULE_HQC_REED_MULLER_H