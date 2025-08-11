// monipoly.h - The Public API for entire Crypto Library
#pragma once
#include "SecretKey.h"
#include "PublicKey.h"
#include <algorithm>
#include <iostream>
#include <tuple>

#include "setup.h"
#include "mpencode.h"
#include "CommitForAuditing.h"
#include "open.h"
#include "open_intersection.h"
#include "verify_intersection.h"
#include "open_difference.h"
#include "big_util.h"
#include "verify_difference.h"

#include "core.h"
#include "bls_BLS12381.h"
#include "pair_BLS12381.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "big_B384_58.h"
#include "randapi.h"
#include "config_big_B384_58.h"


using namespace std;
using namespace core;
using namespace B384_58;
using namespace BLS12381;


// From setup.cpp
std::pair<PublicKey, SecretKey> Setup(int n, csprng& RNG);

// From CommitForAuditing.cpp
ECP CommitForAuditing(const std::vector<BIG*>& attributes_A, const PublicKey& pk);

// From mpencode.cpp
std::vector<BIG*> MPEncode(const std::vector<BIG*>& set_to_encode);

// From open_intersection.cpp
std::pair<std::vector<B384_58::BIG*>, BLS12381::ECP> OpenIntersection(
    const std::vector<B384_58::BIG*>& A,
    const B384_58::BIG* o,
    const std::vector<B384_58::BIG*>& A_prime,
    int l,  
    const std::vector<BLS12381::ECP>& a_list
);

// From verify_intersection.cpp
bool VerifyIntersection(
    const PublicKey& pk,
    const BLS12381::ECP& C,
    const std::vector<B384_58::BIG*>& A_prime,
    const std::vector<B384_58::BIG*>& I,
    const BLS12381::ECP& W,
    int l
);

// From OpenDifference.cpp
std::tuple<BLS12381::ECP, std::vector<B384_58::BIG*>, std::vector<B384_58::BIG*>, std::string>
OpenDifference(
    const PublicKey& pk,
    const std::vector<B384_58::BIG*>& A_private_attrs, // Prover's private set A
    const B384_58::BIG* o_monipoly_opening,           // Prover's opening for A
    const std::vector<B384_58::BIG*>& D_set_chosen_by_prover 
);


// From VerifyDifference.cpp
bool VerifyDifference(
    const PublicKey& pk,
    const BLS12381::ECP& C,
    const std::vector<B384_58::BIG*>& d_coeffs_from_proof,
    const BLS12381::ECP& W,
    const std::vector<B384_58::BIG*>& r_coeffs
);

