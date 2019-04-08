//
//  client_main.cpp
//  fast
//
//  Created by Raphael Bost on 03/04/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

//
// Forward Private Searchable Symmetric Encryption with Optimized I/O Efficiency
//      
//      FAST - by Xiangfu Song
//      bintasong@gmail.com
//

#include "fast/fast_client_runner.hpp"
#include "src/utils/logger.hpp"
#include "aux/db_generator.hpp"

#include <sse/crypto/utils.hpp>

#include <stdio.h>
#include <mutex>
#include<iostream>

#include <unistd.h>
struct Node
{
    int left;
    int right;
    std::string name;
    Node *leftchild;
    Node *rightchilid;
};
 int count=0;

int search(std::string * a,Node *p1,int left,int right)
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
       search(a,p1->leftchild,left,right);
       else
       {
           search(a,p1->leftchild,left,p1->leftchild->right);
           search(a,p1->rightchilid,p1->rightchilid->left,right);

       }
       
   }
   else
   {
       search(a,p1->rightchilid,left,right);
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

int main(int argc, char** argv) {
    sse::logger::set_severity(sse::logger::INFO);
    sse::logger::set_benchmark_file("benchmark_fast_client.out");
    
    sse::crypto::init_crypto_lib();
     std::string search_arry[10];

     std::string ss;
     int left;
    int right;
     std::stringstream is("");
    
      Node a[63];
      int count0=0;
      int count1=0;
      int count2=1;
      int m=32;
      Node *p=& a[0];
      for(int i=0;i<63;i++)
      {   
          //std::cout<<count1<<std::endl;
          //std::cout<<count2<<std::endl;
          a[i].left = (0+count1*(m/count2));
          a[i].right = (0+(count1+1)*(m/count2)-1);
          a[i].name=std::to_string(a[i].left) + "to" + std::to_string(a[i].right);
          if(count2 != m)
          {
          a[i].leftchild= &a[(i+1)*2-1];
          a[i].rightchilid= &a[(i+1)*2];
          }
          else
          {
              a[i].leftchild=NULL;
              a[i].rightchilid=NULL;
          }
          count1++;
          if(count1 == count2)
          {
              count1=0;
              count2=2*count2;
          }
          
          
      }
      int search_count;
  
    
    opterr = 0;
    int c;

    std::list<std::string> input_files;
    std::list<std::string> keywords;
    std::string client_db;
    bool print_stats = false;
    uint32_t bench_count = 0;
    uint32_t rnd_entries_count = 0;
    
    while ((c = getopt (argc, argv, "l:b:o:i:t:dpr:")) != -1)
        switch (c)
    {
        case 'l':
            input_files.push_back(std::string(optarg));
            break;
        case 'b':
            client_db = std::string(optarg);
            break;
        case 't':
            bench_count = atoi(optarg);
            break;
//         case 'd': // load a default file, only for debugging
// //            input_files.push_back("/Volumes/Storage/WP_Inverted/inverted_index_all_sizes/inverted_index_10000.json");
//             input_files.push_back("/Users/raphaelbost/Documents/inverted_index_1000.json");
//             break;
        case 'p':
            print_stats = true;
            break;
        case 'r':
            rnd_entries_count = (uint32_t)std::stod(std::string(optarg),nullptr);
            //atol(optarg);
            break;
        case '?':
            if (optopt == 'l' || optopt == 'b' || optopt == 't' || optopt == 'r')
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
            return 1;
        default:
            exit(-1);
    }
    
    
    for (int index = optind; index < argc; index++)
    {
          keywords.push_back(std::string(argv[index]));
    }

    if (client_db.size()==0) {
        sse::logger::log(sse::logger::WARNING) << "Client database not specified" << std::endl;
        sse::logger::log(sse::logger::WARNING) << "Using \'test.csdb\' by default" << std::endl;
        client_db = "test.csdb";
    }else{
        sse::logger::log(sse::logger::INFO) << "Running client with database " << client_db << std::endl;
    }
    
    std::unique_ptr<sse::fast::FastClientRunner> client_runner;
    

    size_t setup_size = 1e5;
    uint32_t n_keywords = 1e4;
    
    if( rnd_entries_count > 0)
    {
        setup_size = 11*rnd_entries_count;
        n_keywords = 1.4*rnd_entries_count/(10*std::thread::hardware_concurrency());
    }
    
    client_runner.reset( new sse::fast::FastClientRunner("localhost:4240", client_db, setup_size, n_keywords) );
    
    // for (std::string &path : input_files) {
    //     sse::logger::log(sse::logger::INFO) << "Load file " << path << std::endl;
    //     client_runner->load_inverted_index(path);
    //     sse::logger::log(sse::logger::INFO) << "Done loading file " << path << std::endl;
    // }
    
    if (rnd_entries_count > 0) {
        sse::logger::log(sse::logger::INFO) << "Randomly generating database with " << rnd_entries_count << " docs" << std::endl;
        
//        auto post_callback = [&writer, &res_size, &writer_lock](index_type i)

        auto gen_callback = [&client_runner](const std::string &s, size_t i)
        {

            std::string index( reinterpret_cast<const char*>(&i), sse::fast::kIndexSize );

            // sse::logger::log(sse::logger::INFO) << "i: " << sizeof(i) <<", index: "<< index.size() << std::endl;
            
            client_runner->async_update(s, index);
        };
        
        client_runner->start_update_session();
        //sse::sophos::gen_db(rnd_entries_count, gen_callback);
        client_runner->end_update_session();
    }
    
    for (std::string &kw : keywords) {
        std::cout << " -------------- Search -------------- " << std::endl;
        
        std::mutex logger_mtx;
        std::ostream& log_stream = sse::logger::log(sse::logger::INFO);
        bool first = true;
        
        auto print_callback = [&logger_mtx, &log_stream, &first](std::string res)
        {
             logger_mtx.lock();
            
             if (!first) {
                 log_stream << ", ";
             }
             first = false;
             log_stream << res;
            
             logger_mtx.unlock();
        };
        
        log_stream << "Search results: \n{";
        std::vector<std::string> v = split(kw, "to"); //可按多个字符来分隔;
  for(std::vector<std::string>::size_type i = 0; i != v.size(); ++i)
    std::cout << v[i] << "011 ";
  std::cout << std::endl;
  char* end;
  left=static_cast<int>(strtol(v[0].c_str(),&end,10));
  right=static_cast<int>(strtol(v[1].c_str(),&end,10));
      std::cout<<"?"<<left<<"?"<<right;
      count=0;
      search_count=search(search_arry,p,left,right);
      std::cout<<search_count<<"scount";
   

            auto res = client_runner->Rsearch(search_arry, search_count,print_callback);
     
        
        
        log_stream << "}" << std::endl;
    }
    
//    if (bench_count > 0) {
//        std::cout << "-------------- Search Benchmarks --------------" << std::endl;
//        client_runner->search_benchmark(bench_count);
//    }
    
    if (print_stats)
    {
        client_runner->print_stats(sse::logger::log(sse::logger::INFO));
    }
    
    client_runner.reset();
    
    sse::crypto::cleanup_crypto_lib();

    
    return 0;
}
