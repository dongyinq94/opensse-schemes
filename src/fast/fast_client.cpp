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


#include "fast_client.hpp"


#include "utils/utils.hpp"
#include "utils/logger.hpp"
#include "utils/thread_pool.hpp"

#include <iostream>
#include <algorithm>

namespace sse {
    namespace fast {
        
        const std::string FastClient::derivation_key_file__ = "derivation_master.key"; 
        const std::string FastClient::state_key_file__ = "state_master.key";       
        const std::string FastClient::counter_map_file__ = "counters.dat";
        
        std::unique_ptr<FastClient> FastClient::construct_from_directory(const std::string& dir_path)
        { // 如果存在该目录，密钥文件已经存在，执行初始化
            // try to initialize everything from this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string master_key_path = dir_path + "/" + derivation_key_file__;
            std::string state_key_path = dir_path + "/" + state_key_file__;
            std::string counter_map_path = dir_path + "/" + counter_map_file__;
            
            if (!is_file(master_key_path)) {
                // error, the derivation key file is not there
                throw std::runtime_error("Missing master derivation key file");
            }

            if (!is_file(state_key_path)) {
                // error, the state key file is not there
                throw std::runtime_error("Missing state derivation key file");
            }

            if (!is_directory(counter_map_path)) {
                // error, the token map data is not there
                throw std::runtime_error("Missing token data");
            }
            
            std::ifstream master_key_in(master_key_path.c_str()), state_key_in(state_key_path.c_str());
            std::stringstream master_key_buf, state_key_buf;

            master_key_buf << master_key_in.rdbuf();
            state_key_buf << state_key_in.rdbuf();

            return std::unique_ptr<FastClient>(new FastClient(counter_map_path, master_key_buf.str(), state_key_buf.str() ));
        }
        
        std::unique_ptr<FastClient> FastClient::init_in_directory(const std::string& dir_path, uint32_t n_keywords)
        { // 在文件夹下执行初始化，文件夹中没有密钥文件
            // try to initialize everything in this directory
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string counter_map_path = dir_path + "/" + counter_map_file__;
            
            auto c_ptr =  std::unique_ptr<FastClient>(new FastClient(counter_map_path, n_keywords));
            c_ptr->write_keys(dir_path); // keys are chose randomly from class PRFBase !
            
            return c_ptr;
        }
        
        FastClient::FastClient(const std::string& token_map_path, const size_t tm_setup_size) :
        k_prf_(), s_prf_(), counter_map_(token_map_path)
        {
            
        }

        FastClient::FastClient(const std::string& token_map_path, const std::string& derivation_master_key, const std::string& state_master_key) :
        k_prf_(derivation_master_key), s_prf_(state_master_key), counter_map_(token_map_path)
        {
            
        }      
        
        FastClient::~FastClient()
        {
            
        }
        
        size_t FastClient::keyword_count() const
        {
            return counter_map_.approximate_size();
        }
             
        const std::string FastClient::master_derivation_key() const
        {
            return std::string(k_prf_.key().begin(), k_prf_.key().end());
        }

        const std::string FastClient::state_derivation_key() const
        {
            return std::string(s_prf_.key().begin(), s_prf_.key().end());
        }
        
        const crypto::Prf<kDerivationKeySize>& FastClient::derivation_prf() const
        {
            return k_prf_;
        }

        const crypto::Prf<kStateKeySize>& FastClient::state_prf() const
        {// used for state evaluation
            return s_prf_;
        }
        
        std::string FastClient::get_keyword_index(const std::string &kw) const
        {   // 对关键字进行哈希，得到一个索引
            std::string hash_string = crypto::Hash::hash(kw);
            return hash_string.erase(kKeywordIndexSize); // erasing content from kKeywordIndexSize to the end
        }
        
        SearchRequest FastClient::search_request(const std::string &keyword) const
        {
            uint32_t kw_counter;
            bool found;
            SearchRequest req;
            req.add_count = 0;

            std::string seed = get_keyword_index(keyword);
            
            found = counter_map_.get(keyword, kw_counter);
            
            if(!found)
            {
                logger::log(logger::INFO) << "No matching counter found for keyword " << keyword << " (index " << keyword << ")" << std::endl;
            }else{
                // generate search token, derivation key and counter
                req.token = state_prf().prf_string(seed + std::to_string(kw_counter));
                req.derivation_key = derivation_prf().prf_string(seed);
                req.add_count = kw_counter + 1;
            }
            
            logger::log(logger::INFO) << "counter: " << kw_counter << std::endl;

            return req;
        }
        
        
        UpdateRequest FastClient::update_request(const std::string &keyword, const index_type index)
        {
            UpdateRequest req;
            search_token_type st, pre_st;
            
            // get (and possibly construct) the keyword index
            std::string seed = get_keyword_index(keyword);

            // retrieve the counter
            uint32_t kw_counter;
            
            bool success = counter_map_.get_and_increment(keyword, kw_counter);
            
            // if (keyword == "Group-10^1_0_0") {
            //     logger::log(logger::INFO) << "key: " << hex_string( std::string(s_prf_.key().begin(), s_prf_.key().end()) )<< std::endl;   
            //     logger::log(logger::INFO) << "keyword counter: " << kw_counter << std::endl;            
            //     logger::log(logger::INFO) << "master_derivation_key: " << hex_string( master_derivation_key() )<< std::endl;
            // }
            assert(success);
          
            pre_st = kw_counter == 0 ? "0000000000000000" : state_prf().prf_string(seed + std::to_string(kw_counter - 1));      
            
            st = state_prf().prf_string(seed + std::to_string(kw_counter));
                     
            std::string deriv_key = derivation_prf().prf_string(seed);
            
            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Derivation key: " << hex_string(deriv_key) << std::endl;
            }
            
            std::array<uint8_t, kUpdateTokenSize> mask;
            
            gen_update_token_masks(deriv_key, st, req.token, mask);
            req.index = xor_mask(index + pre_st, mask);

            if (logger::severity() <= logger::DBG) {
                logger::log(logger::DBG) << "Update token: (" << hex_string(req.token) << ", " << std::hex << req.index << ")" << std::endl;
            }
            
            return req;
        }
        
        std::ostream& FastClient::print_stats(std::ostream& out) const
        {
            out << "Number of keywords: " << keyword_count() << std::endl;
            
            return out;
        }
        
        void FastClient::write_keys(const std::string& dir_path) const
        {
            if (!is_directory(dir_path)) {
                throw std::runtime_error(dir_path + ": not a directory");
            }
            
            std::string master_key_path = dir_path + "/" + derivation_key_file__;
            std::string state_key_path = dir_path + "/" + state_key_file__;
                      
            std::ofstream master_key_out(master_key_path.c_str()), state_key_out(state_key_path.c_str());
            if (!master_key_out.is_open()) {
                throw std::runtime_error(master_key_path + ": unable to write the master derivation key");
            }

            if (!state_key_out.is_open()) {
                throw std::runtime_error(state_key_path + ": unable to write the state derivation key");
            }

            master_key_out << master_derivation_key();
            master_key_out.close();

            state_key_out << state_derivation_key();
            state_key_out.close();
        }
    }
}
