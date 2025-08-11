#ifndef OPEN_DIFFERENCE_H
#define OPEN_DIFFERENCE_H

#include <vector>
#include <string>
#include <tuple>  // For returning multiple values

#include "core.h"
#include "bls_BLS12381.h"
#include "big_B384_58.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "PublicKey.h" 
#include "monipoly.h"

using namespace BLS12381;
using namespace B384_58;


// Structure to hold result of polynomial division
struct PolynomialDivisionResult {
    std::vector<B384_58::BIG*> quotient_coeffs;    // q(x')
    std::vector<B384_58::BIG*> remainder_coeffs;   // r(x')
    bool remainder_is_identically_zero;           // True if r(x') = 0
    std::string error_message;                    // For any errors during division

    // Constructor
    PolynomialDivisionResult() : remainder_is_identically_zero(true) {} // Default to error state

    // To prevent double free (if vectors are moved from)
    PolynomialDivisionResult(PolynomialDivisionResult&& other) noexcept
        : quotient_coeffs(std::move(other.quotient_coeffs)),
          remainder_coeffs(std::move(other.remainder_coeffs)),
          remainder_is_identically_zero(other.remainder_is_identically_zero),
          error_message(std::move(other.error_message)) {
    }
    PolynomialDivisionResult& operator=(PolynomialDivisionResult&& other) noexcept {
        if (this != &other) {
            for (B384_58::BIG* b : quotient_coeffs) { if (b) free(b); }
            for (B384_58::BIG* b : remainder_coeffs) { if (b) free(b); }
            quotient_coeffs = std::move(other.quotient_coeffs);
            remainder_coeffs = std::move(other.remainder_coeffs);
            remainder_is_identically_zero = other.remainder_is_identically_zero;
            error_message = std::move(other.error_message);
        }
        return *this;
    }
    // Delete copy constructor and assignment to enforce move semantics if this struct owns memory
    PolynomialDivisionResult(const PolynomialDivisionResult&) = delete;
    PolynomialDivisionResult& operator=(const PolynomialDivisionResult&) = delete;
};

// Declaration for PolynomialLongDivision (full implementation in open_difference.cpp)
PolynomialDivisionResult PolynomialLongDivision(
    const std::vector<B384_58::BIG*>& numerator_coeffs,
    const std::vector<B384_58::BIG*>& denominator_coeffs,
    const B384_58::BIG& modulus
);

std::tuple<BLS12381::ECP, std::vector<B384_58::BIG*>, std::vector<B384_58::BIG*>, std::string>
OpenDifference(
    const PublicKey& pk,
    const std::vector<B384_58::BIG*>& A_private_attrs, // original set A
    const B384_58::BIG* o_monipoly_opening,           // opening for A
    const std::vector<B384_58::BIG*>& D_set_chosen_by_prover
);


#endif 