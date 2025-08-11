#include "verify_difference.h"
#include "monipoly.h"
#include "mpencode.h"
#include "big_util.h"
#include "PublicKey.h"

#include "core.h"
#include "bls_BLS12381.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "big_B384_58.h"
#include "pair_BLS12381.h" 
#include "fp12_BLS12381.h"

#include <iostream> 

using namespace std;
using namespace core;
using namespace BLS12381;
using namespace B384_58;

//new version, original version stored in github


/** 
// Sanity Check function 
void PerformSanityMallocCheck_in_VerifyDiff(const std::string& context_msg) {
    std::cout << "--- VerifyDifference: Sanity Malloc Check (" << context_msg << ") ---" << std::endl;
    B384_58::BIG* sanity_big = (B384_58::BIG*)malloc(sizeof(B384_58::BIG));
    if (sanity_big) {
        std::cout << "  Sanity Malloc Addr (VD - " << context_msg << "): " << (void*)sanity_big << std::endl;
        free(sanity_big);
    } else {
        std::cout << "  Sanity Malloc FAILED! (VD - " << context_msg << ")" << std::endl;
    }
}
*/

bool VerifyDifference(
    const PublicKey& pk,
    const BLS12381::ECP& C,
    const std::vector<B384_58::BIG*>& d_coeffs,
    const BLS12381::ECP& W,
    const std::vector<B384_58::BIG*>& r_coeffs
) {
    // --- Safety Checks (no change here) ---
    if (r_coeffs.size() > pk.a_list.size() || d_coeffs.size() > pk.X_list.size()) {
        std::cerr << "[VERIFY_DIFF] FATAL ERROR: Proof's coefficient size exceeds public key size." << std::endl;
        return false;
    }

    // --- Prepare G1 Arguments for Multi-Pairing ---

    // 1. Calculate Cr = Commit(R(x))
    BLS12381::ECP commitment_r = compute_g1_product_sum(pk.a_list, r_coeffs);
    if (ECP_isinf(&commitment_r)) {
        std::cerr << "[VERIFY_DIFF] Error: Remainder commitment is the identity element. Invalid proof." << std::endl;
        return false;
    }

    // 2. Calculate the first G1 argument: C * Cr^{-1}
    BLS12381::ECP P1; // First point for the pairing
    ECP_copy(&P1, const_cast<BLS12381::ECP*>(&C));
    ECP_neg(&commitment_r);
    ECP_add(&P1, &commitment_r);

    // 3. The second G1 argument is just the Witness, W.
    // The C++ compiler is smart enough to use the `W` parameter directly.
    
    // --- Prepare G2 Arguments for Multi-Pairing ---

    // 4. The first G2 argument is X_0 from the public key.
    const BLS12381::ECP2& Q1 = pk.X_list[0];

    // 5. Calculate the second G2 argument: C_D = Commit(D(x)) and negate it.
    BLS12381::ECP2 Q2; // Second point for the pairing
    Q2 = compute_g2_product_sum(pk.X_list, d_coeffs);
    ECP2_neg(&Q2);

    // --- Perform the Atomic Multi-Pairing Operation ---
    // This calculates e(P1, Q1) * e(W, Q2) and returns the result.
    BLS12381::FP12 final_result;
    PAIR_double_ate(&final_result,
                    const_cast<BLS12381::ECP2*>(&Q1), &P1,
                    &Q2, const_cast<BLS12381::ECP*>(&W));
    PAIR_fexp(&final_result);

    // --- Final Check ---
    // For the equation to hold, the result of the multi-pairing must be 1.
    bool is_valid = FP12_isunity(&final_result);

    if (!is_valid) {
        std::cout << "❌ VerifyDifference: Multi-pairing result is not 1. Validation FAILED." << std::endl;
    } else {
        std::cout << "✅ VerifyDifference: Proof is VALID!" << std::endl;
    }

    return is_valid;
}