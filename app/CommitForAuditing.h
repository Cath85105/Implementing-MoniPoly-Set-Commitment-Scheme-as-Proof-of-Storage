#pragma once

#include "monipoly.h"

// It does not need an RNG because 'o' is fixed
ECP CommitForAuditing(
    const std::vector<BIG*>& attributes_A,
    const std::vector<ECP>& a_list
);