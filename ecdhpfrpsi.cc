// Copyright 2024 Guowei LING.
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

#include "examples/pfrpsi/ecdhpfrpsi.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <random>
#include <vector>
#include "examples/pfrpsi/cuckoohash.h"

#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"

inline std::vector<uint32_t> GetIntersectionIdx(
    const std::vector<std::string> &x, const std::vector<std::string> &y) {
  std::set<std::string> set(x.begin(), x.end());
  std::vector<uint32_t> ret;
  for (size_t i = 0; i < y.size(); ++i) {
    if (set.count(y[i]) != 0) {
      ret.push_back(i);
    }
  }
  return ret;
}

std::vector<uint32_t> EcdhPsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                 std::vector<uint128_t>& x,size_t size_y){
  EcdhPsi alice;
  size_t cuckoosize = static_cast<uint32_t>(size_y*(1.3));
  std::ifstream file("receivershare");  // 打开文件
  if (!file.is_open()) {           // 检查文件是否成功打开
      throw std::runtime_error("cannot open receivershare file");
  }

  std::vector<int> receivershares;  // 存储整数的向量
  std::copy_n(std::istream_iterator<int>(file),cuckoosize,std::back_inserter(receivershares));
  file.close();  // 关闭文件

  size_t size_x = x.size()*3;
  std::vector<yc::EcPoint> x_points(size_x);
  alice.MaskUint128s_Recv(absl::MakeSpan(x),absl::MakeSpan(receivershares),absl::MakeSpan(x_points),cuckoosize);

   //Send H(id)^a 
  uint64_t max_point_length = alice.ec_->GetSerializeLength(); // 获取点的最大序列化长度
  uint64_t total_length_x = max_point_length*size_x;
  
  std::vector<uint8_t> xbuffer(total_length_x);
  alice.PointstoBuffer(absl::MakeSpan(x_points), absl::MakeSpan(xbuffer));
  ctx->SendAsync(
    ctx->NextRank(),
    yacl::ByteContainerView(xbuffer.data(), total_length_x * sizeof(uint8_t)),
    "Send H(id)^a");

  //Receive H(id)^b
  uint64_t total_length_y = max_point_length*cuckoosize; 
  std::vector<uint8_t> ybuffer(total_length_y);
  std::vector<yc::EcPoint> y_points(cuckoosize);
  auto bufypoints = ctx->Recv(ctx->PrevRank(), "Receive H(id)^b");
  YACL_ENFORCE(bufypoints.size() == int64_t(total_length_y * sizeof(uint8_t)));
  std::memcpy(ybuffer.data(), bufypoints.data(), bufypoints.size());  
  alice.BuffertoPoints(absl::MakeSpan(y_points), absl::MakeSpan(ybuffer));


  std::vector<yc::EcPoint> y_mask(cuckoosize);
  // y_str = y_points ^ {alice_sk}
  alice.MaskEcPoints(absl::MakeSpan(y_points), absl::MakeSpan(y_mask));
  std::vector<uint8_t> maskbuffer(total_length_y);
  alice.PointstoBuffer(absl::MakeSpan(y_mask), absl::MakeSpan(maskbuffer));

  ctx->SendAsync(
    ctx->NextRank(),
    yacl::ByteContainerView(maskbuffer.data(), maskbuffer.size() * sizeof(uint8_t)),
    "Send y_mask");
  
  uint32_t inter_size;  
  // 接收数据长度的值
  auto sizebuffer = ctx->Recv(ctx->PrevRank(), "Receive the number of intersection");
  std::memcpy(&inter_size, sizebuffer.data(), sizeof(uint32_t));
  size_t total_size_z =  inter_size* sizeof(uint32_t);
  std::vector<uint32_t> z(inter_size);
  auto bufz = ctx->Recv(ctx->PrevRank(), "Receive the index of intersection");
  std::memcpy(bufz.data(), z.data(), total_size_z);
  return z;
}

void EcdhPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                 std::vector<uint128_t>& y,size_t size_x,size_t cuckoosize){
  EcdhPsi bob;
  std::vector<yc::EcPoint> y_points(cuckoosize);
  std::ifstream file("sendershare");  // 打开文件
  if (!file.is_open()) {           // 检查文件是否成功打开
      throw std::runtime_error("cannot open sendershare file");
  }
  size_x = size_x*3;
  std::vector<int> sendershares;  // 存储整数的向量
  std::copy_n(std::istream_iterator<int>(file), cuckoosize, std::back_inserter(sendershares));
  file.close();  // 关闭文件
  // y_points = H(y) ^ {bob_sk}
  CuckooHash cuckooHash(y.size());
   // 插入数据到哈希表中
  cuckooHash.Insert(y);
   // 打印插入后的哈希表数据
  cuckooHash.FillRandom();
  bob.MaskUint128s_Sender(absl::MakeSpan(cuckooHash.bins_), absl::MakeSpan(sendershares),absl::MakeSpan(y_points));
  uint64_t max_point_length = bob.ec_->GetSerializeLength(); // 获取点的最大序列化长度
  
  //Receive H(id)^a 
  uint64_t total_length_x =size_x  * max_point_length;
  std::vector<uint8_t> buffer(total_length_x);
  std::vector<yc::EcPoint> x_points(size_x);
  auto bufxpoints = ctx->Recv(ctx->PrevRank(), "Receive H(id)^a");
  YACL_ENFORCE(bufxpoints.size() == int64_t(total_length_x * sizeof(uint8_t)));
  std::memcpy(buffer.data(), bufxpoints.data(), bufxpoints.size());
  bob.BuffertoPoints(absl::MakeSpan(x_points), absl::MakeSpan(buffer));
    
  //Send H(id)^b
  uint64_t total_length_y =cuckoosize  * max_point_length; 
  std::vector<uint8_t> ybuffer(total_length_y);
  bob.PointstoBuffer(absl::MakeSpan(y_points), absl::MakeSpan(ybuffer));
  ctx->SendAsync(
    ctx->NextRank(),
    yacl::ByteContainerView(ybuffer.data(), total_length_y * sizeof(uint8_t)),
    "Send H(id)^b");

  std::vector<std::string> x_str(size_x);
  // x_str = x_points ^ {bob_sk}
  bob.MaskEcPointsD(absl::MakeSpan(x_points), absl::MakeSpan(x_str));

  std::vector<std::string> y_str(cuckoosize);
  
  auto bufy_str = ctx->Recv(ctx->PrevRank(), "Receive y_str");
  YACL_ENFORCE(bufy_str.size() == int64_t(total_length_y * sizeof(uint8_t)));
  std::vector<uint8_t> maskbuffer(total_length_y);
  std::memcpy(maskbuffer.data(), bufy_str.data(), bufy_str.size());  
  yacl::parallel_for(0, cuckoosize, [&](size_t begin, size_t end) {
  for (size_t idx = begin; idx < end; ++idx) {
    uint64_t offset = idx*max_point_length;
    y_str[idx] = std::string(reinterpret_cast<const char*>(maskbuffer.data() + offset), max_point_length);
  }
  });  
  auto z = GetIntersectionIdx(x_str, y_str);
  uint32_t num_intersize = z.size();
  uint32_t z_size = num_intersize * sizeof(z[0]);
  // 创建缓冲区
  std::vector<uint8_t> bufferz(z_size);
  
  // 序列化：将 vector 的内容复制到缓冲区
  std::memcpy(bufferz.data(), z.data(), z_size);
  // 发送数据
  ctx->SendAsync(
    ctx->NextRank(),
    yacl::ByteContainerView(reinterpret_cast<const uint8_t*>(&num_intersize), sizeof(num_intersize)),
    "Send the number of intersection");

  ctx->SendAsync(
    ctx->NextRank(),
    yacl::ByteContainerView(bufferz.data(), z_size * sizeof(uint8_t)),
    "Send the index of intersection");

}

void EcdhPsi::MaskStrings(absl::Span<std::string> in,
                          absl::Span<yc::EcPoint> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      out[idx] = ec_->HashToCurve(yc::HashToCurveStrategy::Autonomous, in[idx]);
      ec_->MulInplace(&out[idx], sk_);
    }
  });
}

void EcdhPsi::MaskUint128s_Sender(absl::Span<uint128_t> in,
                          absl::Span<int> shares,
                          absl::Span<yc::EcPoint> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      std::stringstream ss;
      ss << in[idx] << shares[idx];
      std::string ssstring = ss.str();
      out[idx] = ec_->HashToCurve(yc::HashToCurveStrategy::Autonomous, ssstring);
      ec_->MulInplace(&out[idx], sk_);
    }
  });
}

void EcdhPsi::MaskUint128s_Recv(absl::Span<uint128_t> in,
                          absl::Span<int> shares,
                          absl::Span<yc::EcPoint> out,
                          size_t cuckoosize) {
  YACL_ENFORCE(in.size()*3 == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      for(int i = 1;i<=3;i++){
        std::stringstream ss;
        uint64_t h = GetHash(i,in[idx]) % cuckoosize;
        ss << in[idx] << shares[h];
        std::string ssstring = ss.str();
        int index = idx*3+i-1;
        out[index] = ec_->HashToCurve(yc::HashToCurveStrategy::Autonomous, ssstring);
        ec_->MulInplace(&out[index], sk_);
      }
    }
  });
}

void EcdhPsi::MaskEcPoints(absl::Span<yc::EcPoint> in,
                           absl::Span<yc::EcPoint> out) {
  YACL_ENFORCE(in.size() == out.size());
    yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
        out[idx] = ec_->Mul(in[idx], sk_);
    }
  });
}

void EcdhPsi::MaskEcPointsD(absl::Span<yc::EcPoint> in,
                           absl::Span<std::string> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
        out[idx] = ec_->SerializePoint(ec_->Mul(in[idx], sk_));
    }
  });
}

void EcdhPsi::PointstoBuffer(absl::Span<yc::EcPoint> in,
                           absl::Span<std::uint8_t> buffer){
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx*32;
      ec_->SerializePoint(in[idx], buffer.data() + offset,32);
    }
  });  
}

void EcdhPsi::BuffertoPoints(absl::Span<yc::EcPoint> in, absl::Span<std::uint8_t> buffer){
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
  for (size_t idx = begin; idx < end; ++idx) {
    uint64_t offset = idx*32;
    in[idx] = ec_->DeserializePoint(absl::MakeSpan(buffer.data() + offset, 32)); 
  }
  });  
}
