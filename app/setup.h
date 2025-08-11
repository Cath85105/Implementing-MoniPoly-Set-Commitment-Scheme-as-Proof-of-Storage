#ifndef SETUP_H
#define SETUP_H

#include "PublicKey.h"
#include "SecretKey.h"

#include <utility>    
#include "core.h"
#include "bls_BLS12381.h"
#include "pair_BLS12381.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "big_B384_58.h"
#include "randapi.h" //for csprng

using namespace BLS12381;
using namespace B384_58;  // For BIG
using namespace core;     // For csprng and octet


/**
 * @param n The maximum number of attributes the scheme will support.
 * @param RNG A reference to an initialized cryptographic random number generator.
 * @return A std::pair containing the generated PublicKey and SecretKey.
 */
std::pair<PublicKey, SecretKey> Setup(int n, csprng& RNG);


#endif