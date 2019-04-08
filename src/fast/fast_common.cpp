//
//  sophos_common.cpp
//  SSE_Schemes
//
//  Created by Raphael Bost on 04/10/2017.
//  Copyright © 2017 Raphael Bost. All rights reserved.
//

//
// Forward Private Searchable Symmetric Encryption with Optimized I/O Efficiency
//      
//      FAST - by Xiangfu Song
//      bintasong@gmail.com
//

#include "fast_common.hpp"


#include <sse/crypto/prf.hpp>

#include <cstring>

namespace sse {
    namespace fast {
        
        void gen_update_token_masks(const std::string &deriv_key,
                                    const std::string search_token,
                                    update_token_type &update_token,
                                    std::array<uint8_t, kUpdateTokenSize> &mask)
        {
            auto derivation_prf = crypto::Prf<kUpdateTokenSize>(deriv_key);
           
            update_token = derivation_prf.prf_string(search_token + '0').erase(kUpdateTokenSize);
                                  
            mask = derivation_prf.prf(search_token + '1');
        }
  

int TRsearch(std::string * a,Node *p1,int count,int left,int right)
{
    if(p1 !=NULL)
    {
    if(p1->left == left && p1->right == right)
    {    
        a[count]=p1->name;
       count++;
        std::cout<<p1->name<<count<<std::endl;
    }
    else
    {     
    
    
    if(left <= p1->leftchild->right )
   {
       if(right <= p1->leftchild->right)
       TRsearch(a,p1->leftchild,count,left,right);
       else
       {
           TRsearch(a,p1->leftchild,count,left,p1->leftchild->right);
           TRsearch(a,p1->rightchilid,count,p1->rightchilid->left,right);

       }
       
   }
   else
   {
       TRsearch(a,p1->rightchilid,count,left,right);
   }
    }
    }
   
    
    
    return count;
}
std::vector<std::string> split(const std::string &s, const std::string &seperator){
  std::vector<std::string> result;
  typedef std::string::size_type string_size;
  string_size i = 0;
  
  while(i != s.size()){
    //找到字符串中首个不等于分隔符的字母；
    int flag = 0;
    while(i != s.size() && flag == 0){
      flag = 1;
      for(string_size x = 0; x < seperator.size(); ++x)
    if(s[i] == seperator[x]){
    ++i;
    flag = 0;
     break;
    }
    }
    
    //找到又一个分隔符，将两个分隔符之间的字符串取出；
    flag = 0;
    string_size j = i;
    while(j != s.size() && flag == 0){
      for(string_size x = 0; x < seperator.size(); ++x)
    if(s[j] == seperator[x]){
    flag = 1;
    break;
    }
      if(flag == 0) 
    ++j;
    }
    if(i != j){
      result.push_back(s.substr(i, j-i));
      i = j;
    }
  }
  return result;
}
        
    }
}
