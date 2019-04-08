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
// spirt
// add by dongyinq94@github.com 

#include "spirt_common.hpp"


#include <sse/crypto/prf.hpp>

#include <cstring>

namespace sse {
    namespace spirt {
   
        
        void gen_update_token_masks(const std::string &deriv_key,
                                    const std::string search_token,
                                    const int up_counter,
                                    const int key_counter,
                                    update_token_type &update_token,
                                    std::string &mask1,
                                    std::string &mask2)
        {
            auto derivation_prf = crypto::Prf<kUpdateTokenSize>(deriv_key);
           
            update_token = derivation_prf.prf_string(search_token + '0'+std::to_string(up_counter)).erase(kUpdateTokenSize);
                                
            mask1 += derivation_prf.prf_string(deriv_key + '1'+'a'+'b'+std::to_string(key_counter)).erase(kUpdateTokenSize);
           
                                
            mask2 += derivation_prf.prf_string(deriv_key + '1'+'a'+'b'+std::to_string(key_counter+1)).erase(kUpdateTokenSize);
          
        }
        void get_cache_db_masks(const std::string &deriv_key,
                                const std::string search_token,
                                const int up_counter,update_token_type &update_token)
        {
            auto derivation_prf = crypto::Prf<kUpdateTokenSize>(deriv_key);
           
            update_token = derivation_prf.prf_string(search_token + '0'+std::to_string(up_counter)).erase(kUpdateTokenSize);

        }

        void gen_search_key_masks(const std::string &deriv_key,
                                    const std::string search_token,
                                    const int key_counter,
                                    std::string &mask1,
                                    std::string &mask2)
        {
            auto derivation_prf = crypto::Prf<kUpdateTokenSize>(deriv_key);
                                  
            mask1 += derivation_prf.prf_string(deriv_key + '1'+'a'+'b'+std::to_string(1)).erase(kUpdateTokenSize);
            
                               
            mask2 += derivation_prf.prf_string(deriv_key + '1'+'a'+'b'+std::to_string(key_counter+1)).erase(kUpdateTokenSize);
           
        }
std::string sxor_mask(const std::string a, const std::string  b)
{
    std::string res="";
    for(size_t i=0;i<a.size();i++)
    {
        res += a[i]^b[i];
    }
    return res;    
}
     std::string ybytetobit(char a)
{
    int aab= int(a);
    std::string b="";
    for(int i=7;i>=0;i--)
    {
        if(aab%2==0)
        {
            b=std::to_string(0)+b;
            
        }
        else
        {
            b=std::to_string(1)+b;
            
        }
        aab=aab/2;
        
    }
    return b;

}
//add by dongyinq94
std::string m_bytetobit( std::string a)
{
    std::string b="";

    for(int i=0;i<a.size();i++)
    {

        b+=ybytetobit(a[i]);
    }
    return b;
}
//add by dongyinq94
std::string ybittobyte(std::string a)
{
    std::string b;
    int count=1;
    int result=0;
    char c;
    for(int i=7;i>=0;i--)
    {
        if (a[i] =='1')
        {
            result +=count;
        }
        count = count*2;
    }
    b=char(result);
    
    return b;
}
std::string m_bittobyte(std::string a)
{
    std::string b;
    std::string sub;
    for(int i=0;i<a.size();i=i+8)
    {
        sub=a.substr(i,8);
        b+=ybittobyte(sub);
    }
    return b;
}
//add by dongyin
        
  

int TRsearch(std::string* a,long lnode,long rnode,long lvalue,long rvalue,int & count)
{
    if(lnode == lvalue && rnode == rvalue)
    {
        std::cout<<std::to_string(lvalue)+"to"+std::to_string(rvalue)<<std::endl;
        a[count]=std::to_string(lvalue)+"to"+std::to_string(rvalue);
        count++;
        std::cout<<count<<std::endl;
    }
    else
    {
        long leftright=(lnode+rnode+1)/2-1;
        //std::cout<<"leftright"<<leftright<<std::endl;
        long rightleft=(lnode+rnode+1)/2;
        //std::cout<<"rightleft"<<rightleft<<std::endl;

        if(lvalue<=leftright)
        {
            if(rvalue<=leftright)
            {
                //std::cout<<"search"<<lnode<<","<<leftright<<","<<lvalue<<","<<rvalue<<std::endl;
                TRsearch(a,lnode,leftright,lvalue,rvalue,count);
                
            }
            else
            {
                //std::cout<<"search"<<lnode<<","<<leftright<<","<<lvalue<<","<<leftright<<std::endl;
                TRsearch(a,lnode,leftright,lvalue,leftright,count);
                //std::cout<<"search"<<rightleft<<","<<rnode<<","<<rightleft<<","<<rvalue<<std::endl;
                TRsearch(a,rightleft,rnode,rightleft,rvalue,count);
            }
            

        } 
        else
        {
             //std::cout<<"search"<<rightleft<<","<<rnode<<","<<lvalue<<","<<rvalue<<std::endl;
            TRsearch(a,rightleft,rnode,lvalue,rvalue,count);
        }
              
    }
    
    return count;
}
 int TRupdate(long lnode,long rnode,int v,const std::string & ind,std::function<void(const std::string &, const std::string &)> callback)
        {   if (lnode == v && rnode ==v )
        callback(std::to_string(lnode)+"to"+std::to_string(rnode), ind);
        //std::cout<<std::to_string(lnode)+"to"+std::to_string(rnode)<<std::endl;
        else 
        {
         //std::cout<<std::to_string(lnode)+"to"+std::to_string(rnode)<<std::endl;
         callback(std::to_string(lnode)+"to"+std::to_string(rnode), ind);
         long lr=(lnode+rnode+1)/2-1;
   // std::cout<<"leftright"<<lr<<std::endl;
         long rl=(lnode+rnode+1)/2;
   // std::cout<<"rightleft"<<rl<<std::endl;
          if(lr >= v)
          TRupdate(lnode,lr,v,ind,callback);
          else
          TRupdate(rl,rnode,v,ind,callback);
    
    
}
    return 0;
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
