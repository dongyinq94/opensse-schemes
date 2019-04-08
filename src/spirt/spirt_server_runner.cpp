//
// fast - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of fast.
//
// fast is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// fast is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with fast.  If not, see <http://www.gnu.org/licenses/>.
//

//
// Forward Private Searchable Symmetric Encryption with Optimized I/O Efficiency
//      
//      FAST - by Xiangfu Song
//      bintasong@gmail.com
//
// spirt
// add by dongyinq94@github.com

#include "spirt_server_runner.hpp"

#include "utils/utils.hpp"
#include "utils/logger.hpp"

#include <fstream>
#include <atomic>
#include <thread>

#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include <grpc++/security/server_credentials.h>


namespace sse {
    namespace spirt {

        const std::string SpirtImpl::edb_map_file = "edb.dat";
        const std::string SpirtImpl::cache_map_file = "cache.dat";

SpirtImpl::SpirtImpl(const std::string& path) :
storage_path_(path), async_search_(true)
{
    if (is_directory(storage_path_)) {
        // try to initialize everything from this directory
        
        // std::string pk_path     = storage_path_ + "/" + pk_file;
        std::string edb_map_path  = storage_path_ + "/" + edb_map_file;
        std::string cache_map_path  = storage_path_ + "/" + cache_map_file;

        // if (!is_file(pk_path)) {
        //     // error, the secret key file is not there
        //     throw std::runtime_error("Missing secret key file");
        // }
        if (!is_directory(edb_map_path)) {
            // error, the token map data is not there
            throw std::runtime_error("Missing edb");
        }
        if (!is_directory(cache_map_path)) {
            // error, the token map data is not there
            throw std::runtime_error("Missing cache");
        }
        // std::ifstream pk_in(pk_path.c_str());
        // std::stringstream pk_buf;
        
        // pk_buf << pk_in.rdbuf();

        server_.reset( new SpirtServer(edb_map_path,cache_map_path) );
    }else if (exists(storage_path_)){
        // there should be nothing else than a directory at path, but we found something  ...
        throw std::runtime_error(storage_path_ + ": not a directory");
    }else{
        // postpone creation upon the reception of the setup message
    }
}

grpc::Status SpirtImpl::setup(grpc::ServerContext* context,
                    const spirt::SetupMessage* message,
                    google::protobuf::Empty* e)
{
    
    logger::log(logger::TRACE) << "Setup!" << std::endl;
    
    if (server_) {
        // problem, the server is already set up
        logger::log(logger::ERROR) << "Info: server received a setup message but is already set up" << std::endl;

        return grpc::Status(grpc::FAILED_PRECONDITION, "The server was already set up");
    }
    
    // create the content directory but first check that nothing is already there
    
    if (exists(storage_path_))
    {
        logger::log(logger::ERROR) << "Error: Unable to create the server's content directory" << std::endl;

        return grpc::Status(grpc::ALREADY_EXISTS, "Unable to create the server's content directory");
    }
    
    if (!create_directory(storage_path_, (mode_t)0700)) {
        logger::log(logger::ERROR) << "Error: Unable to create the server's content directory" << std::endl;

        return grpc::Status(grpc::PERMISSION_DENIED, "Unable to create the server's content directory");
    }
    
    // now, we have the directory, and we should be able to conclude the setup
    // however, the bucket_map constructor in FastServer's constructor can raise an exception, so we need to take care of it
    
    std::string edb_map_path  = storage_path_ + "/" + edb_map_file;
    std::string cache_map_path  = storage_path_ + "/" + cache_map_file;

    try {
        logger::log(logger::INFO) << "Seting up with size " << message->setup_size() << std::endl;
        server_.reset(new SpirtServer(edb_map_path,cache_map_path,message->setup_size()));
    } catch (std::exception &e) {
        logger::log(logger::ERROR) << "Error when setting up the server's core" << std::endl;
        
        server_.reset();
        return grpc::Status(grpc::FAILED_PRECONDITION, "Unable to create the server's core.");
    }

    logger::log(logger::TRACE) << "Successful setup" << std::endl;

    return grpc::Status::OK;
}

#define PRINT_BENCH_SEARCH(t,c) \
        "SEARCH: " + (((c) != 0) ?  std::to_string((t)/(c)) + " ms/pair, " + std::to_string((c)) + " pairs" : \
                                    std::to_string((t)) + " ms, no pair found" )
        
//#define PRINT_BENCH_SEARCH_PAR_RPC(t,c) \
//"Search: " + (((c) != 0) ?  std::to_string((t)/(c)) + " ms/pair (with RPC), " + std::to_string((c)) + " pairs" : \
//std::to_string((t)) + " ms, no pair found" )
//
//#define PRINT_BENCH_SEARCH_PAR_NORPC(t,c) \
//"Search: " + (((c) != 0) ?  std::to_string((t)/(c)) + " ms/pair (without RPC), " + std::to_string((c)) + " pairs" : \
//std::to_string((t)) + " ms, no pair found" )
//
        
//#define PRINT_BENCH_SEARCH_PAR_RPC(t,c) \
//"Search (with PRC): " + std::to_string((c)) + " " + (((c) != 0) ?  std::to_string((t)/(c)) + " ms/pair" : \
//std::to_string((t)) + " ms, no pair found" )
//        
//#define PRINT_BENCH_SEARCH_PAR_NORPC(t,c) \
//"Search: " + (((c) != 0) ?  std::to_string((t)/(c)) + " ms/pair (without RPC), " + std::to_string((c)) + " pairs" : \
//std::to_string((t)) + " ms, no pair found" )

#define PRINT_BENCH_SEARCH_PAR_RPC(t,c) \
std::to_string((c)) + " \t\t " + (((c) != 0) ?  std::to_string((t)/(c)) : \
std::to_string((t)) )
        
#define PRINT_BENCH_SEARCH_PAR_NORPC(t,c) \
std::to_string((c)) + " \t\t " + (((c) != 0) ?  std::to_string((t)/(c)) : \
std::to_string((t)) )



grpc::Status SpirtImpl::search(grpc::ServerContext* context,
                                const spirt::SearchRequestMessage* mes,
                                grpc::ServerWriter<spirt::SearchReply>* writer)
{
    if(async_search_){
        return async_search(context, mes, writer);
    }else{
        return sync_search(context, mes, writer);
    }
}

grpc::Status SpirtImpl::sync_search(grpc::ServerContext* context,
                                     const spirt::SearchRequestMessage* mes,
                                     grpc::ServerWriter<spirt::SearchReply>* writer)
{
    if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION, "The server is not set up");
    }

    logger::log(logger::TRACE) << "Searching ...";
    std::list<std::string> res_list;
    
    BENCHMARK_Q((res_list = server_->search(message_to_request(mes))),res_list.size(), PRINT_BENCH_SEARCH_PAR_NORPC)
//    BENCHMARK_Q((res_list = server_->search_parallel(message_to_request(mes))),res_list.size(), PRINT_BENCH_SEARCH_PAR_NORPC)
//    BENCHMARK_Q((res_list = server_->search_parallel_light(message_to_request(mes),1)),res_list.size(), PRINT_BENCH_SEARCH_PAR_NORPC)
//    BENCHMARK_Q((res_list = server_->search_parallel(message_to_request(mes),2)),res_list.size(), PRINT_BENCH_SEARCH_PAR_NORPC)
//    BENCHMARK_Q((res_list = server_->search_parallel_light(message_to_request(mes),3)),res_list.size(), PRINT_BENCH_SEARCH_PAR_NORPC)
//    BENCHMARK_SIMPLE("\n\n",{;})
    
    for (auto& i : res_list) {
        spirt::SearchReply reply;
        reply.set_result( i );
        
        writer->Write(reply);
    }
    
    logger::log(logger::TRACE) << " done" << std::endl;
    
    
    return grpc::Status::OK;
}


grpc::Status SpirtImpl::async_search(grpc::ServerContext* context,
                                      const spirt::SearchRequestMessage* mes,
                                      grpc::ServerWriter<spirt::SearchReply>* writer)
{
    if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION, "The server is not set up");
    }
    
    logger::log(logger::TRACE) << "Searching ...";

    std::atomic_uint res_size(0);
    
    std::mutex writer_lock;
    
    auto post_callback = [&writer, &res_size, &writer_lock](index_type i)
    {
        spirt::SearchReply reply;
        reply.set_result( i );
        
        writer_lock.lock();
        writer->Write(reply);
        writer_lock.unlock();

        res_size++;
    };

    // TODO
    BENCHMARK_Q((server_->search_callback( message_to_request(mes), post_callback) ),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
//     if (mes->add_count() >= 40) { // run the search algorithm in parallel only if there are more than 2 results
//         BENCHMARK_Q((server_->search_parallel_callback(message_to_request(mes), post_callback, std::thread::hardware_concurrency(), 8,1)),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
// //        BENCHMARK_Q((server_->search_parallel_light_callback(message_to_request(mes), post_callback, std::thread::hardware_concurrency())),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
// //        BENCHMARK_Q((server_->search_parallel_light_callback(message_to_request(mes), post_callback, 10)),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
//     }else if (mes->add_count() >= 2) {
//                 BENCHMARK_Q((server_->search_parallel_light_callback(message_to_request(mes), post_callback, std::thread::hardware_concurrency())),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
//     }else{
//         BENCHMARK_Q((server_->search_callback(message_to_request(mes), post_callback)),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
//     }
    
    logger::log(logger::TRACE) << " done" << std::endl;
    
    
    return grpc::Status::OK;
}
   grpc::Status SpirtImpl::Rsearch(grpc::ServerContext* context,grpc::ServerReaderWriter<spirt::SearchReply,spirt::SearchRequestMessage>* stream) 
     {
         if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION, "The server is not set up");
    }
    
    logger::log(logger::TRACE) << "Searching ...123.";

    int res_size =1;
    
    std::mutex writer_lock;
    
    SearchRequestMessage request;
    std::vector<spirt::SearchRequest> srequest;
    while(stream->Read( &request))
    {
        srequest.push_back(message_to_request(&request));
    }
    auto post_callback = [&stream, &res_size, &writer_lock](index_type i)
    {
        spirt::SearchReply reply;
        reply.set_result( i );
        std::cout<<i<<std::endl;
        
        writer_lock.lock();
       stream->Write(reply);
        writer_lock.unlock();

        res_size++;
    };

    // TODO
    BENCHMARK_Q((server_->Rsearch_callback( srequest, post_callback) ),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
//     if (mes->add_count() >= 40) { // run the search algorithm in parallel only if there are more than 2 results
//         BENCHMARK_Q((server_->search_parallel_callback(message_to_request(mes), post_callback, std::thread::hardware_concurrency(), 8,1)),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
// //        BENCHMARK_Q((server_->search_parallel_light_callback(message_to_request(mes), post_callback, std::thread::hardware_concurrency())),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
// //        BENCHMARK_Q((server_->search_parallel_light_callback(message_to_request(mes), post_callback, 10)),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
//     }else if (mes->add_count() >= 2) {
//                 BENCHMARK_Q((server_->search_parallel_light_callback(message_to_request(mes), post_callback, std::thread::hardware_concurrency())),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
//     }else{
//         BENCHMARK_Q((server_->search_callback(message_to_request(mes), post_callback)),res_size, PRINT_BENCH_SEARCH_PAR_RPC)
//     }
    
    logger::log(logger::TRACE) << " done" << std::endl;
    
    
    return grpc::Status::OK;
         

     }
        

grpc::Status SpirtImpl::update(grpc::ServerContext* context,
                    const spirt::UpdateRequestMessage* mes,
                    google::protobuf::Empty* e)
{
    std::unique_lock<std::mutex> lock(update_mtx_);
    
    if (!server_) {
        // problem, the server is already set up
        return grpc::Status(grpc::FAILED_PRECONDITION, "The server is not set up");
    }

    logger::log(logger::TRACE) << "Updating ..." << std::endl;

    server_->update(message_to_request(mes));
 
    logger::log(logger::TRACE) << " done" << std::endl;

    return grpc::Status::OK;
}

        grpc::Status SpirtImpl::bulk_update(grpc::ServerContext* context,
                                        grpc::ServerReader<spirt::UpdateRequestMessage>* reader, google::protobuf::Empty* e)
        {
            if (!server_) {
                // problem, the server is already set up
                return grpc::Status(grpc::FAILED_PRECONDITION, "The server is not set up");
            }
            
            logger::log(logger::TRACE) << "Updating (bulk)..." << std::endl;

            spirt::UpdateRequestMessage mes;
            
            while (reader->Read(&mes)) {
                server_->update(message_to_request(&mes));
            }
            
            logger::log(logger::TRACE) << "Updating (bulk)... done" << std::endl;

            
            return grpc::Status::OK;
        }
        

std::ostream& SpirtImpl::print_stats(std::ostream& out) const
{
    if (server_) {
        return server_->print_stats(out);
    }
    return out;
}

bool SpirtImpl::search_asynchronously() const
{
    return async_search_;
}

void SpirtImpl::set_search_asynchronously(bool flag)
{
    async_search_ = flag;
}
        
SearchRequest message_to_request(const SearchRequestMessage* mes)
{
    SearchRequest req;
    
    req.add_count = mes->add_count();
    req.derivation_key = mes->derivation_key();
    req.token = mes->search_token();
    req.key= mes->key();

    return req;
}

UpdateRequest message_to_request(const UpdateRequestMessage* mes)
{
    UpdateRequest req;
    
    req.index = mes->index();
    req.token = mes->update_token();

    return req;
}
       
void run_spirt_server(const std::string &address, const std::string& server_db_path, grpc::Server **server_ptr, bool async_search) {
    std::string server_address(address);
    SpirtImpl service(server_db_path);
    
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    logger::log(logger::INFO) << "Server listening on " << server_address << std::endl;
    
    *server_ptr = server.get();
    
    service.print_stats(sse::logger::log(sse::logger::INFO));
    service.set_search_asynchronously(async_search);
    
    server->Wait();
}

} // namespace spirt
} // namespace sse
