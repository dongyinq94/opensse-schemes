//
// Sophos - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of Sophos.
//
// Sophos is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// Sophos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Sophos.  If not, see <http://www.gnu.org/licenses/>.
//

//
// Forward Private Searchable Symmetric Encryption with Optimized I/O Efficiency
//      
//      FAST - by Xiangfu Song
//      bintasong@gmail.com
//


//spirt add by dongyin
//dongyinq94 github.com

#include "spirt_server.hpp"


#include "utils/utils.hpp"
#include "utils/logger.hpp"
#include "utils/thread_pool.hpp"

#include <iostream>
#include <algorithm>

namespace sse {
namespace spirt {
    

SpirtServer::SpirtServer(const std::string& db_path,const std::string& cache_path) :
edb_(db_path),cache_(cache_path)
{
    
}

SpirtServer::SpirtServer(const std::string& db_path,const std::string& cache_path,const size_t tm_setup_size) :
edb_(db_path),cache_(cache_path)
{
    
}


std::list<index_type> SpirtServer::search(const SearchRequest& req)
{
    std::list<index_type> resultstring;
    std::string results="";
    
    search_token_type st = req.token;

    if (logger::severity() <= logger::DBG) {

        logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;
    
        logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
    }
    bool success = edb_.get(req.derivation_key,results);
    if(!success)
    {
        for(int i=0;i<16;i++)
        {
            results+="00000000";//8*8*16=1024bits.
        }

    }
    //if nor success, there haven't a  search query.
    
    for (size_t i = 0; i < req.add_count; i++) {
        // std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
        index_type r;
        // search_token_type pre_st;
        update_token_type ut;
       get_cache_db_masks(req.derivation_key,st,i,ut);   
  
        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Derived token: " << hex_string(ut) << std::endl;
        }

        bool found = cache_.get(ut,r);
        std::cout<<"zhelizhaodaole r"<<std::endl;
        
        if (found) {
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
            }
            
            results = sxor_mask(results,r);
    
        }else{
            logger::log(logger::ERROR) << "sync, i = "<< i << ", We were supposed to find something!" << std::endl;        }
    }
    success = edb_.remove_and_put(req.derivation_key,results);
    results=sxor_mask(req.key,results);
    for(int i=0 ;i<1024;i++)
    {
        if (results[i]==0) {
            resultstring.push_back(std::to_string(i));
        }
        
    }
    return resultstring;
}

    void SpirtServer::search_callback(const SearchRequest& req, std::function<void(index_type)> post_callback)
    {
       std::string results;
      // std::cout<<"searchbegin";
    
    search_token_type st = req.token;
   // std::cout<<"serversearchtoken"<<req.token<<std::endl;

    if (logger::severity() <= logger::DBG) {

        logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;
    
        logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
    }
    bool success = edb_.get(req.derivation_key,results);
    if(!success)
    {
        for(int i=0;i<16;i++)
        {
            results+=char(0);//8*8*2=128its.
        }

    }
   // std::cout<<results<<"thisisedbresults;"<<std::endl;
    //if nor success, there haven't a  search query.
    
    for (size_t i = 1; i < req.add_count+1; i++) {
        // std::string st_string(reinterpret_cast<char*>(st.data()), st.size());
        index_type r;
        // search_token_type pre_st;
        update_token_type ut;
       get_cache_db_masks(req.derivation_key,st,i,ut);   
  
        if (logger::severity() <= logger::DBG) {
            logger::log(logger::DBG) << "Derived token: " << hex_string(ut) << std::endl;
        }

        bool found = cache_.get(ut,r);
        //bool found1= cache_.remove(ut);
        if(!found1)
        {
            std::cout<<"deleted cache db failed"<<std::endl;
        }
        
        if (found) {
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
            }
            
            results = sxor_mask(r,results);
    
        }else{
            logger::log(logger::ERROR) << "sync, i = "<< i << ", We were supposed to find something!" << std::endl;        }
    }
   // std::cout<<"nodecryptededbstring"<<m_bytetobit(results)<<std::endl;
    success = edb_.remove_and_put(req.derivation_key,results);
   // std::cout<<"thisisserverdecryptkey"<<m_bytetobit(req.key)<<std::endl;
    results=sxor_mask(req.key,results);
    results=m_bytetobit(results);
   // std::cout<<results<<"thisis final result";
    for(int i=0 ;i<128;i++)
    {
        if (results[i]=='1') {
            post_callback(std::to_string(i));
        }
        
    }
    }

    void SpirtServer::Rsearch_callback(const std::vector<SearchRequest> & reqlist, std::function<void(index_type)> post_callback)
            {
                //std::cout<<"Rsearch"<<std::endl;
                for(const auto& req: reqlist)
                {
                  //  std::cout<<req.add_count<<" searchrequest"<<std::endl;
                    SpirtServer::search_callback(req,post_callback);
                }

            }
    

// std::list<index_type> FastServer::search_parallel_full(const SearchRequest& req)
// {
//     std::list<index_type> results;
    
//     search_token_type st = req.token;
    
//     auto derivation_prf = crypto::Prf<kUpdateTokenSize>(req.derivation_key);

//     if (logger::severity() <= logger::DBG) {
//         logger::log(logger::DBG) << "Search token: " << hex_string(req.token) << std::endl;
    
//         logger::log(logger::DBG) << "Derivation key: " << hex_string(req.derivation_key) << std::endl;
//     }

//     // ThreadPool prf_pool(1);
//     ThreadPool token_map_pool(1);
//     ThreadPool decrypt_pool(1);

//     auto decrypt_job = [&derivation_prf, &results](const index_type r, const std::string& st_string)
//     {
//         index_type v = xor_mask(r, derivation_prf.prf(st_string + '1'));
//         results.push_back(v);
//     };

//     auto lookup_job = [&derivation_prf, &decrypt_pool, &decrypt_job, this](const std::string& st_string, const update_token_type& token)
//     {
//         index_type r;
        
//         if (logger::severity() <= logger::DBG) {
//             logger::log(logger::DBG) << "Derived token: " << hex_string(token) << std::endl;
//         }
        
//         bool found = edb_.get(token,r);
        
//         if (found) {
//             if (logger::severity() <= logger::DBG) {
//                 logger::log(logger::DBG) << "Found: " << std::hex << r << std::endl;
//             }
            
//             decrypt_pool.enqueue(decrypt_job, r, st_string);

//         }else{
//             logger::log(logger::ERROR) << "We were supposed to find something!" << std::endl;
//         }

//     };

//     for (uint8_t i = 0; i < req.add_count; i++) {

//         update_token_type ut = derivation_prf.prf_string(req.token + '0').erase(kUpdateTokenSize - kIndexSize);
        
//         token_map_pool.enqueue(lookup_job, req.token, ut);
//     }

//     decrypt_pool.join();
//     token_map_pool.join();
    
//     return results;
// }

void SpirtServer::update(const UpdateRequest& req)
{
    if (logger::severity() <= logger::DBG) {
        logger::log(logger::DBG) << "Update: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
    }

//    edb_.add(req.token, req.index);
    cache_.remove_and_put(req.token, req.index);
    //std::cout<<"updateindex"<<sse::spirt::m_bytetobit(req.index)<<std::endl;
    //std::cout<<"updatetoken"<<sse::spirt::m_bytetobit(req.token)<<std::endl;
    //std::cout<<"zheliyijingcunhaole "<<req.token<<"token "<<req.index<<"index"<<std::endl;
}

std::ostream& SpirtServer::print_stats(std::ostream& out) const
{
//    out << "Number of tokens: " << edb_.size();
//    out << "; Load: " << edb_.load();
//    out << "; Overflow bucket size: " << edb_.overflow_size() << std::endl;
    
    return out;
}

} // namespace fast
} // namespace sse
