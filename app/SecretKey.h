#ifndef SECRET_KEY_H
#define SECRET_KEY_H

#include "core.h"
#include "bls_BLS12381.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "big_B384_58.h"

struct SecretKey {
    B384_58::BIG x_prime;
};

#endif