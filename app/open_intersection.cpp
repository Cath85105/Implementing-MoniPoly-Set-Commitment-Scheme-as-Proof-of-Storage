#include "open_intersection.h"
#include "monipoly.h"
#include "mpencode.h"
#include "commit.h"
//#include "CommitForAuditing.h"
#include "big_util.h"
#include <algorithm>
#include <iostream>
#include "core.h"
#include "bls_BLS12381.h"
#include "big_B384_58.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"

using namespace std;
using namespace B384_58;
using namespace BLS12381;


pair<vector<BIG*>, ECP> OpenIntersection(
    const vector<BIG*>& A,
    const BIG* o,
    const vector<BIG*>& A_prime,
    int l,
    const vector<ECP>& a_list
) {
    vector<BIG*> I;

    // Step 1: Compute I = A ∩ A′
    for (BIG* m : A) {
        for (BIG* q : A_prime) {
            if (BIG_equal(m, q)) {
                I.push_back(m);
                break;
            }
        }
    }

    // Step 2: Check size
    if (I.size() < (size_t)l) {
        cout << "Intersection too small." << endl;
        ECP inf_point;
        ECP_inf(&inf_point);
        return std::make_pair(vector<BIG*>(), inf_point);
    }

    // Step 3: Compute rest = (A ∪ {o}) \ I
    vector<BIG*> A_with_o = A;
    A_with_o.push_back(const_cast<BIG*>(o));

    vector<BIG*> rest;
    for (BIG* m : A_with_o) {
        bool in_I = false;
        for (BIG* i : I) {
            if (BIG_equal(m, i)) {
                in_I = true;
                break;
            }
        }
        if (!in_I) rest.push_back(m);
    }

    // Step 4: Encode polynomial over rest
    //  MPEncode must return vector of NEWLY MALLOC'D BIG*s
    vector<BIG*> coeffs_for_W = MPEncode(rest);

    if (coeffs_for_W.empty() && !rest.empty()){
        std::cerr << "Error: MPEncode returned empty coefficients for non-empty 'rest' set in OpenIntersection." << std::endl;
        // Cleanup coeffs_for_W if any were allocated before error
        for(BIG* c_coeff : coeffs_for_W) if(c_coeff) free(c_coeff);
        ECP inf_point; ECP_inf(&inf_point);
        return std::make_pair(I, inf_point); // Return computed I, but error W
    }


    // Step 5: Commit to coeffs using a_list
    
    ECP W;

    ECP_inf(&W);
    if (a_list.size() < coeffs_for_W.size()) {
        std::cerr << "Error: a_list_pk size is too small for witness coefficients in OpenIntersection." << std::endl;
        for(BIG* c_coeff : coeffs_for_W) if(c_coeff) free(c_coeff); // Cleanup
        ECP_inf(&W); // Set W to infinity on error
    } else {
        for (size_t i = 0; i < coeffs_for_W.size(); i++) {
            if (coeffs_for_W[i] == nullptr) {
                std::cerr << "Warning: Null coefficient for W at index " << i << " in OpenIntersection." << std::endl;
                continue;
            }
            ECP temp_term;
            ECP_copy(&temp_term, const_cast<ECP*>(&a_list[i]));
            ECP_mul(&temp_term, *coeffs_for_W[i]);
            ECP_add(&W, &temp_term);
        }
    }

    // Cleanup coeffs_for_W (ASSUMING MPEncode allocates new BIG*s)
    for (BIG* c_coeff : coeffs_for_W) {
        if (c_coeff != nullptr) {
            free(c_coeff);
        }
    }
    coeffs_for_W.clear();

    return std::make_pair(I, W);
}
