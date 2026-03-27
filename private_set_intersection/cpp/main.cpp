#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>
#include "private_set_intersection/cpp/psi_client.h"
#include "private_set_intersection/cpp/psi_server.h"
#include "absl/strings/str_cat.h"

std::string BytesToHexString(const std::vector<uint8_t>& bytes) {
  std::stringstream ss;
  ss << std::hex << std::uppercase << std::setfill('0');
  for (unsigned char c : bytes) {
    ss << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
  }
  return ss.str();
}

struct ECGroupPtr {
  EC_GROUP* g;
  ECGroupPtr(EC_GROUP* p = nullptr) : g(p) {}
  ~ECGroupPtr() {
    if (g) EC_GROUP_free(g);
  }
};

struct ECPointPtr {
  EC_POINT* p;
  ECPointPtr(EC_POINT* q = nullptr) : p(q) {}
  ~ECPointPtr() {
    if (p) EC_POINT_free(p);
  }
};

static std::vector<uint8_t> PointToOctets(const EC_GROUP* group,
                                          const EC_POINT* pt) {
  size_t len = EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED,
                                  NULL, 0, NULL);
  if (len == 0) return {};
  std::vector<uint8_t> out(len);
  size_t r = EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED,
                                out.data(), out.size(), NULL);
  if (r == 0) return {};
  return out;
}

static bool HashToCurveSM2(const EC_GROUP* group, const uint8_t* dst,
                           size_t dst_len, const uint8_t* msg, size_t msg_len,
                           std::vector<uint8_t>& out_octets) {
  // Create EC_POINT
  EC_POINT* pt = EC_POINT_new(group);
  if (!pt) {
    std::cout << "EC_POINT_new failed\n";
    return false;
  }
  ECPointPtr pt_guard(pt);

  // Call the exported EC wrapper function (exists in the implementation file)
  int ok = EC_hash_to_curve_sm2p256v1_xmd_sm3_sswu(group, pt, dst, dst_len, msg,
                                                   msg_len);
  if (!ok) {
    return false;
  }

  // Validate not at infinity and on curve
  if (EC_POINT_is_at_infinity(group, pt)) return false;
  if (EC_POINT_is_on_curve(group, pt, NULL) != 1) return false;

  out_octets = PointToOctets(group, pt);
  return !out_octets.empty();
}

int T_hash_to_curve() {
  ECGroupPtr group(EC_GROUP_new_by_curve_name(NID_sm2));
  if (group.g == nullptr) {
    std::cout << "不支持sm2p256v1曲线\n";
    return -1;
  }

  const std::string dst = "TEST_DST_SM3_SSWU";
  const std::string msg = "sample message for hash-to-curve";

  std::vector<uint8_t> out1, out2;
  if (HashToCurveSM2(group.g, (const uint8_t*)dst.data(), dst.size(),
                     (const uint8_t*)msg.data(), msg.size(), out1) == false) {
    std::cout << "HashToCurveSM2 failed\n";
  }
  std::cout << BytesToHexString(out1)<<std::endl;
  return 0;
}

int process(){
  using namespace private_set_intersection;
  
  double fpr = 1. / (10000);
  std::cout<<"fpr="<<fpr<<"\n";
  
  bool reveal_intersection = true;
  std::cout<<"展示元素:"<<(reveal_intersection?"是":"否")<<"\n";
  
  auto server = PsiServer::CreateWithNewKey(reveal_intersection).value();
  std::cout<<"服务端初始化密钥\n";
  auto client = PsiClient::CreateWithNewKey(reveal_intersection).value();
  std::cout<<"客户端初始化密钥\n";
  

  std::vector<std::string> server_inputs = {
    "Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Wilson"
  };
  std::vector<std::string> client_inputs = {
    "Smith", "Johnson","Wilson","Brown","Garcia","ele"
  };
  int num_server_inputs = server_inputs.size();
  int num_client_inputs = client_inputs.size();
  std::cout<<"服务端元素:"<<server_inputs.size()<<std::endl;
  for(auto s:server_inputs){
    std::cout<<s<<",";
  }
  std::cout<<"\n";
  std::cout<<"客户端元素:"<<client_inputs.size()<<std::endl;
  for(auto s:client_inputs){
    std::cout<<s<<",";
  }
  std::cout<<"\n";


  DataStructure ds = DataStructure::Raw;
  psi_proto::ServerSetup setup =
      server->CreateSetupMessage(fpr, num_server_inputs, server_inputs, ds).value();
  std::cout<<"服务端初始化\n";
  psi_proto::Request request = client->CreateRequest(client_inputs).value();
  std::cout<<"客户端发送含inputs的请求request\n";
  psi_proto::Response response = server->ProcessRequest(request).value();
  std::cout<<"服务端处理客户端的请求request并回反馈处理结果response\n";
  auto intersection = client->GetIntersection(setup, response).value();
  std::cout<<"客户端接收服务端给出的response\n";

  auto sz = static_cast<int64_t>(intersection.size());
  std::cout<<"交集:";
  std::cout<<sz<<std::endl;
  for(auto x:intersection){
    std::cout<<client_inputs[x]<<",";
  }
  std::cout<<"\n";
  return 0;
}

int mprocess(int num_server_inputs, int num_client_inputs){
  using namespace private_set_intersection;
  using namespace std::chrono; // 命名空间别名，方便使用

  // 记录总开始时间
  auto total_start = high_resolution_clock::now();
  
  double fpr = 1. / (10000);
  std::cout << "fpr=" << fpr << "\n";
  
  bool reveal_intersection = true;
  std::cout << "展示元素:" << (reveal_intersection ? "是" : "否") << "\n";
  
  // 1. 计时：服务端初始化密钥
  auto step_start = high_resolution_clock::now();
  auto server = PsiServer::CreateWithNewKey(reveal_intersection).value();
  auto step_end = high_resolution_clock::now();
  std::cout << "[计时] 服务端初始化密钥时间: " 
            << duration_cast<milliseconds>(step_end - step_start).count() << " ms\n";

  // 2. 计时：客户端初始化密钥
  step_start = high_resolution_clock::now();
  auto client = PsiClient::CreateWithNewKey(reveal_intersection).value();
  step_end = high_resolution_clock::now();
  std::cout << "[计时] 客户端初始化密钥时间: " 
            << duration_cast<milliseconds>(step_end - step_start).count() << " ms\n";
  
  // 构造数据
  std::vector<std::string> server_inputs(num_server_inputs);
  for (int i = 0; i < num_server_inputs; i++) {
    server_inputs[i] = absl::StrCat("Element", i);
  }
  std::vector<std::string> client_inputs(num_client_inputs);
  for (int i = 0; i < num_client_inputs; i++){
    client_inputs[i] = absl::StrCat("Element", i * 2);
  }

  DataStructure ds = DataStructure::Raw;
  
  // 3. 计时：服务端创建 Setup Message (通常是最耗时的步骤之一)
  step_start = high_resolution_clock::now();
  psi_proto::ServerSetup setup =
      server->CreateSetupMessage(fpr, num_server_inputs, server_inputs, ds).value();
  step_end = high_resolution_clock::now();
  std::cout << "[计时] 服务端创建Setup Message时间: " 
            << duration_cast<milliseconds>(step_end - step_start).count() << " ms\n";

  // 4. 计时：客户端创建 Request
  step_start = high_resolution_clock::now();
  psi_proto::Request request = client->CreateRequest(client_inputs).value();
  step_end = high_resolution_clock::now();
  std::cout << "[计时] 客户端创建Request时间: " 
            << duration_cast<milliseconds>(step_end - step_start).count() << " ms\n";

  // 5. 计时：服务端处理 Request
  step_start = high_resolution_clock::now();
  psi_proto::Response response = server->ProcessRequest(request).value();
  step_end = high_resolution_clock::now();
  std::cout << "[计时] 服务端处理Request时间: " 
            << duration_cast<milliseconds>(step_end - step_start).count() << " ms\n";

  // 6. 计时：客户端计算交集
  step_start = high_resolution_clock::now();
  auto intersection = client->GetIntersection(setup, response).value();
  step_end = high_resolution_clock::now();
  std::cout << "[计时] 客户端计算交集时间: " 
            << duration_cast<milliseconds>(step_end - step_start).count() << " ms\n";

  // 总耗时
  auto total_end = high_resolution_clock::now();
  std::cout << ">>> [总计] 本次PSI流程总耗时: " 
            << duration_cast<milliseconds>(total_end - total_start).count() << " ms <<<\n";

  auto sz = static_cast<int64_t>(intersection.size());
  std::cout << "交集大小:" << sz << std::endl;
  
  return 0;
}

int main() { 
  // 
  // T_hash_to_curve(); 
  // process();

  std::cout << "开始性能测试，数据规模从 1 到 1,000,000 (10^6)...\n";

  for(int i = 1; i <= 1000000; i *= 10){
    for(int j = 1; j <= 1000000; j *= 10){
      std::cout << "\n==================================================\n";
      std::cout << "测试规模: 服务端(Server) = " << i << ", 客户端(Client) = " << j << "\n";
      std::cout << "==================================================\n";
      
      mprocess(i, j);
      
    }
  }
  return 0;
}