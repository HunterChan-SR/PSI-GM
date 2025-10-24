#include<iostream>
#include"openssl/sm3.h"
#include"private_join_and_compute/crypto/context.h"
void test_sm3(std::string data){
    std::cout<<"test_sm3\n";
    std::cout<<"sm3("<<data<<")=";
    auto context = private_join_and_compute::Context(); 
    // std::cout<<;
    for(auto c:context.Sm3String(data)){
        std::cout<<std::hex<<(static_cast<int>(c)&0xff);
    }
    std::cout<<"\n";
}

int main(){
    test_sm3("hello"); //BECBBFAAE6548B8BF0CFCAD5A27183CD1BE6093B1CCECCC303D9C61D0A645268
    test_sm3("你好"); //78E5C78C5322CA174089E58DC7790ACF8CE9D542BEE6AE4A5A0797D5E356BE61
    test_sm3("ABCDE"); //3D3C180892E9F4B1F0A311F30AEDDA636B3C1D8EACA4EB76A158117A729898AC

    return 0;
}