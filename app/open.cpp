#include "open.h"
#include "mpencode.h"
#include "PublicKey.h"
#include "core.h"
#include "bls_BLS12381.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "big_B384_58.h"

#include <vector>
#include <iostream>

using namespace std;
using namespace B384_58;
using namespace BLS12381;

bool Open(
    const PublicKey& pk,
    const ECP& C_commitment_to_check, // The commitment C
    const std::vector<BIG*>& A_attributes, // The set A
    const BIG* o_opening_value        // The opening value o
){
    // 1. Form the set S_for_check = A_attributes ∪ {o_opening_value}
    std::vector<BIG*> set_to_encode = A_attributes;
    // Here Ensure o_opening_value is not null
    if (o_opening_value == nullptr) {
        std::cerr << "Error: Null opening value provided to Open_MoniPoly_Verify." << std::endl;
        return false;
    }
    set_to_encode.push_back(const_cast<BIG*>(o_opening_value)); // Add o

    // 2. Compute coefficients: {expected_m_j} = MPEncode(S_for_check)
    std::vector<BIG*> expected_coeffs = MPEncode(set_to_encode);

    if (expected_coeffs.empty() && !set_to_encode.empty()) {
        std::cerr << "Error: MPEncode returned empty for non-empty set in Open_MoniPoly_Verify." << std::endl;
        // Cleanup for expected_coeffs if MPEncode allocated them
        for (BIG* coeff : expected_coeffs) { if (coeff) free(coeff); }
        return false;
    }

    // 3. Re-compute the commitment C_expected = Π pk.a_list[j]^{expected_m_j}
    ECP C_expected;
    ECP_inf(&C_expected);

    if (pk.a_list.size() < expected_coeffs.size()) {
        std::cerr << "Error: pk.a_list is too small in Open_MoniPoly_Verify." << std::endl;
        // Cleanup for expected_coeffs
        for (BIG* coeff : expected_coeffs) { if (coeff) free(coeff); }
        return false;
    }

    for (size_t i = 0; i < expected_coeffs.size(); ++i) {
        if (expected_coeffs[i] == nullptr) {
            std::cerr << "Warning: Null coefficient from MPEncode in Open_MoniPoly_Verify at index " << i << std::endl;
            continue; //or can handle as error
        }
        ECP term;
        ECP_copy(&term, const_cast<ECP*>(&pk.a_list[i]));
        ECP_mul(&term, *expected_coeffs[i]);
        ECP_add(&C_expected, &term);
    }

    // Cleanup for expected_coeffs (since MPEncode allocates new BIGs for its output)
    for (BIG* coeff : expected_coeffs) {
        if (coeff != nullptr) {
            free(coeff);
        }
    }

    // 4. Compare C_commitment_to_check with C_expected
    // ECP_equals will return 1 if equal, 0 if not.
    if (ECP_equals(const_cast<ECP*>(&C_commitment_to_check), &C_expected) == 1) {
        return true; // Verification successful
    } else {
        return false; // Verification failed
    }
}