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

#include <cstddef>
#include <cstring>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/utils/parallel.h"

inline uint64_t GetHash(size_t idx, uint128_t code) {
  uint64_t aligned_u64;
  memcpy(&aligned_u64, reinterpret_cast<const uint8_t*>(&code) + idx * 2,
         sizeof(aligned_u64));
  return aligned_u64;
}

class CuckooHash {
 public:
  explicit CuckooHash(int cuckoosize)
      : cuckoosize_(cuckoosize),
        cuckoolen_(static_cast<uint32_t>(cuckoosize_ * 1.27)) {
    if (cuckoosize_ <= 0) {
      throw std::invalid_argument("cuckoosize must be positive");
    }
    bins_.resize(cuckoolen_);  // 初始化值为0
  }

  void Insert(std::vector<uint128_t> inputs) {
    if (cuckoosize_ != inputs.size()) {
      throw std::invalid_argument("cuckoosize must be positive");
    }
    hash_index_.resize(cuckoolen_, 0);
    for (size_t i = 0; i < cuckoosize_; ++i) {
      // std::cout<<i<<std::endl;
      uint8_t old_hash_id = 1;
      size_t j = 0;
      for (; j < maxiter_; ++j) {
        uint64_t h = GetHash(old_hash_id, inputs[i]) % cuckoolen_;
        uint8_t* hash_id_address = &hash_index_[h];
        uint128_t* key_index_address = &bins_[h];
        if (*hash_id_address == empty_) {
          *hash_id_address = old_hash_id;
          *key_index_address = inputs[i];
          break;
        } else {
          std::swap(inputs[i], *key_index_address);
          std::swap(old_hash_id, *hash_id_address);
          old_hash_id = old_hash_id % 3 + 1;
        }
      }
      if (j == maxiter_) {
        throw std::runtime_error("insert failed, " + std::to_string(i));
      }
    }
  }

  void FillRandom() {
    yacl::parallel_for(0, bins_.size(), [&](int64_t begin, int64_t end) {
      for (int64_t idx = begin; idx < end; ++idx) {
        if (bins_[idx] == 0 && hash_index_[idx] == 0) {
          bins_[idx] = yacl::crypto::FastRandU128();
        }
      }
    });
  }

  std::vector<uint128_t> bins_;
  std::vector<uint8_t> hash_index_;
  size_t cuckoosize_;
  uint32_t cuckoolen_;

 private:
  const uint8_t empty_ = 0;
  const size_t maxiter_ = 500;
};