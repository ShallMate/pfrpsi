// Copyright 2024 Guowei Ling.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <vector>

#include "examples/pfrpsi/okvs/baxos.h"

#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/utils/parallel.h"
#include <fstream>

using namespace yacl::crypto;
using namespace std;

namespace VOLEPFRPSI{

std::vector<int32_t> PRFPSIRecv(
  const std::shared_ptr<yacl::link::Context>& ctx,
  std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
  std::vector<uint128_t>& A,
  std::vector<uint128_t>& C1); 

void PRFPSISend(const std::shared_ptr<yacl::link::Context>& ctx,
                 std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
                 std::vector<uint128_t>& B,
                 std::vector<uint128_t>& C2);

}; 