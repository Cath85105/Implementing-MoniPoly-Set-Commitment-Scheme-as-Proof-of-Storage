#include <vector>
#include <iostream>
#include "core.h"
#include "bls_BLS12381.h"
#include "pair_BLS12381.h"
#include "ecp_BLS12381.h"
#include "ecp2_BLS12381.h"
#include "big_B384_58.h"
#include "randapi.h"

#include "setup.h"
#include "monipoly.h"

using namespace BLS12381;
using namespace B384_58;  // For BIG
using namespace core;     // For csprng and octet


// --- Setup Function ---
pair<PublicKey, SecretKey> Setup(int n, csprng& RNG) {
    PublicKey pk;
    SecretKey sk;

    // Get generators for G1 and G2
    ECP g1;
    ECP_generator(&g1);

    ECP2 g2;
    ECP2_generator(&g2);

    pk.g1 = g1;
    pk.g2 = g2;

    // Get group order
    BIG order;
    BIG_copy(order, const_cast<chunk *>(CURVE_Order));  // Same for ECP2 

    // Generate random x′ ∈ Zp
    BIG x_prime;
    
    BIG_randomnum(x_prime, order, &RNG); // Generate x_prime in [0, order-1]
    BIG_copy(sk.x_prime, x_prime); // Store in secret key

    // Precompute x′^i mod p
    vector<BIG> powers(n + 1);
    BIG one;
    BIG_one(one);
    BIG_copy(powers[0], one);

    for (int i = 1; i <= n; i++) {
        BIG_modmul(powers[i], powers[i - 1], x_prime, order);  // powers[i] = x′^i mod p
    }

    // Compute aᵢ = g1^(x′^i) and Xᵢ = g2^(x′^i)
    for (int i = 0; i <= n; i++) {
        ECP a_i;
        ECP_copy(&a_i, &g1);
        ECP_mul(&a_i, powers[i]);
        pk.a_list.push_back(a_i);

        ECP2 X_i;
        ECP2_copy(&X_i, &g2);
        ECP2_mul(&X_i, powers[i]);
        pk.X_list.push_back(X_i);
    }

    return {pk, sk};
}