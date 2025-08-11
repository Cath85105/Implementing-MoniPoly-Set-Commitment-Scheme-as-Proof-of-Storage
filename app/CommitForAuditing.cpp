#include "CommitForAuditing.h"
#include "mpencode.h"
#include <vector>
#include <cstdlib>  
#include <iostream>
#include <algorithm>

/** 
#include "core.h"
#include "bls_BLS12381.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "big_B384_58.h"
#include "arch.h" 
*/

#include "monipoly.h" 

using namespace std;
using namespace B384_58;
using namespace BLS12381;


ECP CommitForAuditing(
    const std::vector<BIG*>& attributes_A,
    const std::vector<ECP>& a_list
) {
    // 1. Create the fixed, public opening value o = 1.
    BIG o_public;
    BIG_one(o_public);

    // 2. Form the set for commit = attributes_A ∪ {o=1}
    std::vector<BIG*> set_to_encode = attributes_A;
    set_to_encode.push_back(&o_public);

    // 3. Compute coefficients: {m_j} = MPEncode(S_for_commit)
    std::vector<BIG*> coeffs_for_C = MPEncode(set_to_encode);

    if (coeffs_for_C.empty() && !set_to_encode.empty()) {
        std::cerr << "Error: MPEncode returned empty coefficients in CommitForAuditing." << std::endl;
        ECP error_C; 
        ECP_inf(&error_C);
        return error_C; // Return point at infinity on error
    }

    // 4. Compute the MoniPoly Commitment C = Σ a_j * m_j
    ECP C;
    ECP_inf(&C); // Initialize C to the point at infinity

    if (a_list.size() < coeffs_for_C.size()) {
        std::cerr << "Error: Public key 'a_list' is too small for the number of coefficients." << std::endl;
        for (BIG* c_coeff : coeffs_for_C) { if (c_coeff) free(c_coeff); }
        return C; // Return point at infinity on error
    }

    for (size_t i = 0; i < coeffs_for_C.size(); i++) {
        if (coeffs_for_C[i] == nullptr) {
            std::cerr << "Warning: Null coefficient at index " << i << std::endl;
            continue;
        }
        ECP temp_term;
        ECP_copy(&temp_term, const_cast<ECP*>(&a_list[i]));
        ECP_mul(&temp_term, *coeffs_for_C[i]);
        ECP_add(&C, &temp_term);
    }

    // 5. Cleanup for the coefficients allocated by MPEncode
    for (BIG* c_coeff : coeffs_for_C) {
        if (c_coeff) free(c_coeff);
    }

    // 6. Return the resulting commitment.
    return C;
}



