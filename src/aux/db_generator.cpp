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


#include "db_generator.hpp"
#include "utils/logger.hpp"

#include <sse/crypto/fpe.hpp>
#include <sse/crypto/random.hpp>
#include "utils/utils.hpp"
#include "spirt/spirt_common.hpp"

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

#define MIN(a,b) (((a) > (b)) ? (b) : (a))

namespace sse {
    namespace sophos {


          
        static uint64_t xorshift128(uint64_t &x, uint64_t &y, uint64_t &z, uint64_t &w) {
            uint64_t t = x;
            t ^= t << 11;
            t ^= t >> 8;
            x = y; y = z; z = w;
            w ^= w >> 19;
            w ^= t;
            return w;
        }

        
        static uint64_t optimal_num_group(size_t N_entries, size_t step, size_t group_size)
        {
            return floorl(((long double)N_entries)/(1.2*step*group_size));
        }
        
        const std::string kKeyword01PercentBase    = "0.1";
        const std::string kKeyword1PercentBase     = "1";
        const std::string kKeyword10PercentBase    = "10";

        const std::string kKeywordGroupBase      = "Group-";
        const std::string kKeyword10GroupBase    = kKeywordGroupBase + "10^";
        const std::string kKeywordRand10GroupBase    = kKeywordGroupBase + "rand-10^";

        constexpr uint32_t max_10_counter = ~0;
        
        static void generation_job(unsigned int thread_id, size_t N_entries, size_t step, crypto::Fpe *rnd_perm, std::atomic_size_t *entries_counter, std::atomic_size_t *docs_counter, std::function<void(const std::string &, const std::string &)> callback)
        {
            
            
            size_t counter = thread_id;
            std::string id_string = std::to_string(thread_id);
            
    
            
            std::string kw;
            uint32_t new_entries;
             new_entries = 0;
             int m=1024;

             
            

            for (size_t i = 0; counter < N_entries; counter += step, i++) {
                size_t ind = rnd_perm->encrypt_64(counter);
               
                srand(ind%1024);

                double w_d = ((double)ind)/((uint64_t)~0);
                std::list<std::string> insertions;
                int v=ind%10;
                srand(v);
                int bv=(ind%10079)%m;
                int av[10]={0,0,0,0,0,0,0,0,0,0};
                std::string index_128;
                for(int j=0;j<128;j++)
                {
                    index_128+='0';
                }
               // std::cout<<"all0index"<<index_128<<std::endl;
                for(int j=0;j<v;j++)
                {
                    if(j!=0)
                    {
                    srand(av[j-1]);
                    }
                    av[j]=rand()%128;
                    //std::cout<<av[j]<<"~"<<std::endl;
                    index_128[av[j]]='1';
                }
               // std::cout<<"gengeraredindex128"<<index_128<<std::endl;
                std::string index=spirt::m_bittobyte(index_128);
              //  std::cout<<"generatededindex128/8byte"<<index<<std::endl;

                std::cout<<bv<<"bv"<<std::endl;
                std::string name=std::to_string(bv)+"to"+std::to_string(bv);
               // std::cout<<name<<std::endl;


              
                sse::spirt::TRupdate(0,m-1,bv,index,callback);
                //std::cout<<"test bytetpbit"<<spirt::m_bytetobit(index);
              //  std::cout<<std::endl<<bv<<std::endl;
          
                
            
                
            

                new_entries += 5;
                
                (*entries_counter) += new_entries;
                (*docs_counter)++;
            }
            
            std::string log = "Random DB generation: thread " + std::to_string(thread_id) + " completed:";
            
             
            
          
            
            logger::log(logger::INFO) << log << std::endl;
        }
        
        
        void gen_db(size_t N_entries, std::function<void(const std::string &, const std::string &)> callback)
        {
            crypto::Fpe rnd_perm;
            std::atomic_size_t entries_counter(0);
            std::atomic_size_t docs_counter(0);

            unsigned int n_threads = std::thread::hardware_concurrency();
            std::vector<std::thread> threads;
            std::mutex rpc_mutex;
            
            for (unsigned int i = 0; i < n_threads; i++) {
                threads.push_back(std::thread(generation_job, i, N_entries, n_threads, &rnd_perm, &entries_counter, &docs_counter, callback));
                std::cout<<"thread";
            }

            for (unsigned int i = 0; i < n_threads; i++) {
                threads[i].join();
            }
            
            std::string log = "Random DB generation: " + std::to_string(docs_counter.load()) + " new keyword string generated, representing " + std::to_string(entries_counter.load()) + " entries";

            logger::log(logger::INFO) << log << std::endl;
        }

    }
}
