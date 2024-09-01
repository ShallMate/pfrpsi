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

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>
#include <future>

#include "examples/pfrpsi/okvs/baxos.h"

#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/utils/parallel.h"
#include <fstream>

namespace VOLEPFRPSI{

using namespace yacl::crypto;
using namespace std;

inline std::vector<int32_t> GetIntersectionIdx(
    const std::vector<uint128_t> &x, const std::vector<uint128_t> &y) {

  std::set<uint128_t> set(x.begin(), x.end());
  std::vector<int32_t> ret(y.size(), -1);  // 初始化为 -1

  yacl::parallel_for(0, y.size(), [&](size_t start, size_t end) {
    for (size_t i = start; i < end; ++i) {
      if (set.count(y[i]) != 0) {
        ret[i] = i; 
      }
    }
  });

  // 清除所有值为 -1 的元素
  ret.erase(std::remove(ret.begin(), ret.end(), -1), ret.end());
  
  return ret;
}

std::vector<int32_t> PRFPSIRecv(
  const std::shared_ptr<yacl::link::Context>& ctx,
  std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
  std::vector<uint128_t>& A,
  std::vector<uint128_t>& C1) {
  
  std::ifstream file("receivershare");  // 打开文件
  if (!file.is_open()) {           // 检查文件是否成功打开
      throw std::runtime_error("cannot open receivershare file");
  }

  std::vector<int> receivershares;  // 存储整数的向量
  std::copy_n(std::istream_iterator<int>(file), elem_hashes.size(), std::back_inserter(receivershares));
  file.close();  // 关闭文件
  //std::cout << "文件中有 " << receivershares.size() << " 个元素。" << std::endl;
  std::vector<uint128_t> E(elem_hashes.size());

  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      E[idx] = C1[idx] ^ yacl::crypto::Blake3_128(std::to_string(receivershares[idx]));
    }
  });
  ctx->SendAsync(
    ctx->NextRank(),
    yacl::ByteContainerView(E.data(), E.size() * sizeof(uint128_t)),
    "Send E");

  uint128_t okvssize = baxos.size();

  // VOLE
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(okvssize),
                 "baxos.size");
  // VOLE
  const auto codetype = yacl::crypto::CodeType::Silver5;
  std::vector<uint128_t> a(okvssize);
  std::vector<uint128_t> c(okvssize);
  auto volereceiver = std::async([&] {
    auto sv_receiver = yacl::crypto::SilentVoleReceiver(codetype);
    sv_receiver.Recv(ctx, absl::MakeSpan(a), absl::MakeSpan(c));
  });

  // Encode
  std::vector<uint128_t> p(okvssize);
  baxos.Solve(absl::MakeSpan(elem_hashes), absl::MakeSpan(elem_hashes),
              absl::MakeSpan(p), nullptr, 8);
  std::vector<uint128_t> aprime(okvssize);
  yacl::parallel_for(0, aprime.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aprime[idx] = a[idx] ^ p[idx];
    }
  });
  volereceiver.get();
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(aprime.data(), aprime.size() * sizeof(uint128_t)),
      "Send A' = P+A");
  std::vector<uint128_t> receivermasks(elem_hashes.size());
  baxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(receivermasks),
               absl::MakeSpan(c), 8);

    yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      receivermasks[idx] = receivermasks[idx] ^ A[idx];
    }
  });
  std::vector<uint128_t> sendermasks(elem_hashes.size());
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");
  YACL_ENFORCE(buf.size() == int64_t(elem_hashes.size() * sizeof(uint128_t)));
  std::memcpy(sendermasks.data(), buf.data(), buf.size());
  auto z = GetIntersectionIdx(sendermasks, receivermasks);
  return z;
}

void PRFPSISend(const std::shared_ptr<yacl::link::Context>& ctx,
                 std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos,
                 std::vector<uint128_t>& B,
                 std::vector<uint128_t>& C2) {

  std::ifstream file("sendershare");  // 打开文件
  if (!file.is_open()) {           // 检查文件是否成功打开
      throw std::runtime_error("cannot open sendershare file");
  }

  std::vector<int> sendershares;  // 存储整数的向量
  std::copy_n(std::istream_iterator<int>(file), elem_hashes.size(), std::back_inserter(sendershares));
  file.close();  // 关闭文件
  //std::cout << "文件中有 " << sendershares.size() << " 个元素。" << std::endl;
  std::vector<uint128_t> E(elem_hashes.size());
  std::vector<uint128_t> A(elem_hashes.size());
  auto ebuf = ctx->Recv(ctx->PrevRank(), "Receive E");
  YACL_ENFORCE(ebuf.size() == int64_t(elem_hashes.size() * sizeof(uint128_t)));
  std::memcpy(E.data(), ebuf.data(), ebuf.size());
    yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      okvs::Galois128 b_gf128(B[idx]);
      okvs::Galois128 inv = b_gf128.Inv();
      okvs::Galois128 res(E[idx]^yacl::crypto::Blake3_128(std::to_string(sendershares[idx]))^C2[idx]);
      A[idx] = (res*inv).get<uint128_t>(0);
    }
  });
  size_t okvssize =
      DeserializeUint128(ctx->Recv(ctx->PrevRank(), "baxos.size"));
  const auto codetype = yacl::crypto::CodeType::Silver5;
  std::vector<uint128_t> b(okvssize);
  uint128_t delta = 0;
  auto volesender = std::async([&] {
    auto sv_sender = yacl::crypto::SilentVoleSender(codetype);
    sv_sender.Send(ctx, absl::MakeSpan(b));
    delta = sv_sender.GetDelta();
  });
  volesender.get();
  std::vector<uint128_t> aprime(okvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive A' = P+A");
  YACL_ENFORCE(buf.size() == int64_t(okvssize * sizeof(uint128_t)));
  std::memcpy(aprime.data(), buf.data(), buf.size());
  okvs::Galois128 delta_gf128(delta);
  std::vector<uint128_t> k(okvssize);
  yacl::parallel_for(0, okvssize, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      k[idx] = b[idx] ^ (delta_gf128 * aprime[idx]).get<uint128_t>(0);
    }
  });
  std::vector<uint128_t> sendermasks(elem_hashes.size());
  baxos.Decode(absl::MakeSpan(elem_hashes), absl::MakeSpan(sendermasks),
               absl::MakeSpan(k), 8);
  yacl::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] =
          sendermasks[idx] ^ (delta_gf128 * elem_hashes[idx]).get<uint128_t>(0)^A[idx];
    }
  });
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(sendermasks.data(),
                              sendermasks.size() * sizeof(uint128_t)),
      "Send masks of sender");
}
};