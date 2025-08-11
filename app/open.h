#ifndef OPEN_H
#define OPEN_H

#include <vector>
#include <iostream>

#include "core.h"
#include "bls_BLS12381.h"
#include "ecp_BLS12381.h"   
#include "ecp2_BLS12381.h"
#include "big_B384_58.h"    
#include "PublicKey.h" 

using namespace std;
using namespace B384_58;
using namespace BLS12381;

bool Open(
    const PublicKey& pk,
    const BLS12381::ECP& C_commitment_to_check,
    const std::vector<B384_58::BIG*>& A_attributes,
    const B384_58::BIG* o_opening_value
);

#endif 