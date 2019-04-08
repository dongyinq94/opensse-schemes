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
// spirt
// add by dongyinq94@github.com 

#pragma once





#include <sse/crypto/tdp.hpp>
#include <sse/crypto/prf.hpp>

#include <string>
#include <thread>
#include <vector>
#include <list>
#include <iostream>
#include <cassert>
#include <cmath>
#include <atomic> 
#include <mutex>
# include <iostream>
# include <time.h>
# include <stdlib.h>
#include <array>

namespace sse {
    namespace spirt {
        // add by dongyin

    




        constexpr size_t kDerivationKeySize = 16;
        constexpr size_t kStateKeySize = 16;
        constexpr size_t kUpdateTokenSize = 16;
        constexpr size_t kIndexSize = 8;
        
        typedef std::string search_token_type; 
        typedef std::string update_token_type;
        typedef std::string index_type;  // length should be 8!
        
        
        struct SearchRequest
        {
            search_token_type   token;  // state info
            std::string         derivation_key;
            uint32_t            add_count;
            std::string         key;
        };
        
        
        struct UpdateRequest
        {
            update_token_type   token;
            index_type          index;
        };
                struct Node
{
    int left;
    int right;
    std::string name;
    Node *leftchild;
    Node *rightchilid;
};

std::string sxor_mask(const std::string a, const std::string  b);
std::string ybytetobit(char a);
std::string m_bytetobit( std::string a);
std::string ybittobyte(std::string a);
std::string m_bittobyte(std::string a);

int TRsearch(std::string* a,long lnode,long rnode,long lvalue,long rvalue,int & count);
int TRupdate(long lnode,long rnode,int v,const std::string &  ind, std::function<void(const std::string &, const std::string &)> callback);
std::vector<std::string> split(const std::string &s, const std::string &seperator);
 void gen_update_token_masks(const std::string &deriv_key,
                                    const std::string search_token,//st
                                    const int up_counter,
                                    const int key_counter,
                                    update_token_type &update_token,//ut
                                    std::string &mask1,      //key foe eop
                                    std::string &mask2);//  key for eop
void get_cache_db_masks(const std::string &deriv_key,
                                const std::string search_token,
                                const int up_counter,update_token_type &update_token);
void gen_search_key_masks(const std::string &deriv_key,
                                    const std::string search_token,
                                    const int key_counter,
                                    std::string &mask1,
                                    std::string &mask2);                                  

    }
}
