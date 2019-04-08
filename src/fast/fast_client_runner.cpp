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


#include "fast_client_runner.hpp"

#include "fast_net_types.hpp"
#include "fast/fast_client.hpp"
#include "fast/fast_server.hpp"

#include "utils/thread_pool.hpp"
#include "utils/utils.hpp"
#include "utils/logger.hpp"

#include <sse/dbparser/DBParserJSON.h>

#include <chrono>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <fstream>

#include <grpc/grpc.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>

namespace sse {
namespace fast {


FastClientRunner::FastClientRunner(const std::string& address, const std::string& path, size_t setup_size, uint32_t n_keywords)
    : bulk_update_state_{0}, update_launched_count_(0), update_completed_count_(0)
{
    std::shared_ptr<grpc::Channel> channel(grpc::CreateChannel(address,
                                                               grpc::InsecureChannelCredentials()));
    stub_ = fast::Fast::NewStub(channel);
                    
    if (is_directory(path)) {
        // try to initialize everything from this directory

        client_ = FastClient::construct_from_directory(path);
        
    }else if (exists(path)){
        // there should be nothing else than a directory at path, but we found something  ...
        throw std::runtime_error(path + ": not a directory");
    }else{      
        // start by creating a new directory
        if (!create_directory(path, (mode_t)0700)) {
            throw std::runtime_error(path + ": unable to create directory");
        }
        
        client_ = FastClient::init_in_directory(path, n_keywords);
        
        // send a setup message to the server
        bool success = send_setup(setup_size);
        
        if (!success) {
            throw std::runtime_error("Unsuccessful server setup");
        }
    }
    
    // start the thread that will look for completed updates
    update_completion_thread_ = new std::thread(&FastClientRunner::update_completion_loop, this);
}


FastClientRunner::~FastClientRunner()
{
    update_cq_.Shutdown();
    wait_updates_completion();
    update_completion_thread_->join();
}
    
bool FastClientRunner::send_setup(const size_t setup_size) const
{
    grpc::ClientContext context;
    fast::SetupMessage message;
    google::protobuf::Empty e;

    message.set_setup_size(setup_size);
    // message.set_public_key(client_->public_key());
    
    grpc::Status status = stub_->setup(&context, message, &e);

    if (status.ok()) {
        logger::log(logger::TRACE) << "Setup succeeded." << std::endl;
    } else {
        logger::log(logger::ERROR) << "Setup failed: " << std::endl;
        logger::log(logger::ERROR) << status.error_message() << std::endl;
        return false;
    }

    return true;
}
    
    
const FastClient& FastClientRunner::client() const
{
    if (!client_) {
        throw std::logic_error("Invalid state");
    }
    return *client_;
}
    
std::list<index_type> FastClientRunner::search(const std::string& keyword, std::function<void(index_type)> receive_callback) const
{
    logger::log(logger::TRACE) << "Search " << keyword << std::endl;
    
    grpc::ClientContext context;
    fast::SearchRequestMessage message;
    fast::SearchReply reply;
    
    message = request_to_message(client_->search_request(keyword));
    
    std::unique_ptr<grpc::ClientReader<fast::SearchReply> > reader( stub_->search(&context, message) );
    std::list<index_type> results;
    
    
    while (reader->Read(&reply)) {
//        logger::log(logger::TRACE) << "New result received: "
//        << std::dec << reply.result() << std::endl;
        results.push_back(reply.result());
        
        if (receive_callback != NULL) {
            receive_callback(reply.result());
        }
    }
    grpc::Status status = reader->Finish();
    if (status.ok()) {
        logger::log(logger::TRACE) << "Search succeeded." << std::endl;
    } else {
        logger::log(logger::ERROR) << "Search failed:" << std::endl;
        logger::log(logger::ERROR) << status.error_message() << std::endl;
    }
    
    return results;
}
std::list<index_type> FastClientRunner::Rsearch( std::string * keyword, int count, std::function<void(index_type)> receive_callback) const
{
    logger::log(logger::TRACE) << "Search " << keyword << std::endl;
    

    fast::SearchRequestMessage message;
    fast::SearchReply reply;

    std::list<index_type> results;
    
    grpc::ClientContext context;
    auto stream=stub_->Rsearch(&context);

   

   std::cout<<"??   "<<count;


 for(int i=0;i<count;i++)
      {
          std::cout<<"??  messagrto ";
              message = request_to_message(client_->search_request(keyword[i]));;
           stream->Write(message);

          
      }  
      stream->WritesDone();

         while (stream->Read(&reply)) {
//        logger::log(logger::TRACE) << "New result received: "
//        << std::dec << reply.result() << std::endl;
        results.push_back(reply.result());
        std::cout<<"12345";

        
        if (receive_callback != NULL) {
            receive_callback(reply.result());
            std::cout<<"13579";
        }
        }
    
  
    grpc::Status status = stream->Finish();
    if (status.ok()) {
        logger::log(logger::TRACE) << "Search succeeded." << std::endl;
    } else {
        logger::log(logger::ERROR) << "Search failed:" << std::endl;
        logger::log(logger::ERROR) << status.error_message() << std::endl;
    }
    
    return results;
}
void FastClientRunner::update(const std::string& keyword, index_type index)
{
    grpc::ClientContext context;
    fast::UpdateRequestMessage message;
    google::protobuf::Empty e;
    

    if (bulk_update_state_.writer) { // an update session is running, use it
        update_in_session(keyword, index);
    }else{
        message = request_to_message(client_->update_request(keyword, index));

        grpc::Status status = stub_->update(&context, message, &e);
        
        if (status.ok()) {
            logger::log(logger::TRACE) << "Update succeeded." << std::endl;
        } else {
            logger::log(logger::ERROR) << "Update failed:" << std::endl;
            logger::log(logger::ERROR) << status.error_message() << std::endl;
        }
    }
}

void FastClientRunner::async_update(const std::string& keyword, index_type index)
{
    grpc::ClientContext context;
    fast::UpdateRequestMessage message;


    if (bulk_update_state_.is_up) { // an update session is running, use it
        update_in_session(keyword, index);
    }else{
        logger::log(logger::WARNING) << "This is dangerous: you should not use async_updates, they are still buggy..." << std::endl;

        message = request_to_message(client_->update_request(keyword, index));

        update_tag_type *tag = new update_tag_type(); // TODO 
        std::unique_ptr<grpc::ClientAsyncResponseReader<google::protobuf::Empty> > rpc(
                                                                    stub_->Asyncupdate(&context, message, &update_cq_));

        tag->reply.reset(new google::protobuf::Empty());
        tag->status.reset(new grpc::Status());
        tag->index.reset(new size_t(update_launched_count_++));
        
        rpc->Finish(tag->reply.get(), tag->status.get(), tag);
    }
}
    
    void FastClientRunner::update_in_session(const std::string& keyword, index_type index)
    {
        fast::UpdateRequestMessage message = request_to_message(client_->update_request(keyword, index));

        if(! bulk_update_state_.is_up)
        {
            throw std::runtime_error("Invalid state: the update session is not up");
        }
        
        bulk_update_state_.mtx.lock();
        if(! bulk_update_state_.writer->Write(message))
        {
            logger::log(logger::ERROR) << "Update session: broken stream." << std::endl;
        }
        bulk_update_state_.mtx.unlock();
    }

void FastClientRunner::wait_updates_completion()
{
    stop_update_completion_thread_ = true;
    std::unique_lock<std::mutex> lock(update_completion_mtx_);
    update_completion_cv_.wait(lock, [this]{ return update_launched_count_ == update_completed_count_; });
}
    
void FastClientRunner::start_update_session()
{
    if (bulk_update_state_.writer) {
        logger::log(logger::WARNING) << "Invalid client state: the bulk update session is already up" << std::endl;
        return;
    }
    
    bulk_update_state_.context.reset(new grpc::ClientContext());
    bulk_update_state_.writer = stub_->bulk_update(bulk_update_state_.context.get(), &(bulk_update_state_.response));
    bulk_update_state_.is_up = true;
    
    logger::log(logger::TRACE) << "Update session started." << std::endl;
}

void FastClientRunner::end_update_session()
{
    if (!bulk_update_state_.writer) {
        logger::log(logger::WARNING) << "Invalid client state: the bulk update session is not up" << std::endl;
        return;
    }
    
    bulk_update_state_.writer->WritesDone();
    ::grpc::Status status = bulk_update_state_.writer->Finish();
    
    if (!status.ok()) {
        logger::log(logger::ERROR) << "Status not OK at the end of update sessions. Status: " << status.error_message() << std::endl;
    }
    
    bulk_update_state_.is_up = false;
    bulk_update_state_.context.reset();
    bulk_update_state_.writer.reset();
    
    logger::log(logger::TRACE) << "Update session terminated." << std::endl;
}

    
void FastClientRunner::update_completion_loop()
{
    update_tag_type* tag;
    bool ok = false;

    for (; stop_update_completion_thread_ == false ; ok = false) {
        bool r = update_cq_.Next((void**)&tag, &ok);
        if (!r) {
            logger::log(logger::TRACE) << "Close asynchronous update loop" << std::endl;
            return;
        }

        logger::log(logger::TRACE) << "Asynchronous update " << std::dec << *(tag->index) << " succeeded." << std::endl;
        delete tag;
        
        {
            std::lock_guard<std::mutex> lock(update_completion_mtx_);
            update_completed_count_++;
            
            if (update_launched_count_ == update_completed_count_) {
                update_completion_cv_.notify_all();
            }
        }
    }
}
    
// bool FastClientRunner::load_inverted_index(const std::string& path)
// {
//     try {
        
//         dbparser::DBParserJSON parser(path.c_str());
//         ThreadPool pool(std::thread::hardware_concurrency());
        
//         std::atomic_size_t counter(0);
        
//         auto add_list_callback = [this,&pool,&counter](const string kw, const list<index_type> docs)
//         {
//             auto work = [this,&counter](const string& keyword, const list<index_type> &documents)
//             {
//                 for (index_type doc : documents) {
//                     this->async_update(keyword, doc);
//                 }
//                 counter++;
                
//                 if ((counter % 100) == 0) {
//                     logger::log(sse::logger::INFO) << "\rLoading: " << counter << " keywords processed" << std::flush;
//                 }
//             };
//             pool.enqueue(work,kw,docs);
            
//         };
        
        
//         parser.addCallbackList(add_list_callback);
        
//         start_update_session();

//         parser.parse();
        
//         pool.join();
//         logger::log(sse::logger::INFO) << "\rLoading: " << counter << " keywords processed" << std::endl;
        
//         wait_updates_completion();
        
//         end_update_session();

//         return true;
//     } catch (std::exception& e) {
//         logger::log(logger::ERROR) << "\nFailed to load file " << path << " : " << e.what() << std::endl;
//         return false;
//     }
//     return false;
// }

std::ostream& FastClientRunner::print_stats(std::ostream& out) const
{
    return client_->print_stats(out);
}
    
SearchRequestMessage request_to_message(const SearchRequest& req)
{
    SearchRequestMessage mes;
    
    mes.set_add_count(req.add_count);
    mes.set_derivation_key(req.derivation_key);
    mes.set_search_token(req.token.data(), req.token.size());
    
    return mes;
}

UpdateRequestMessage request_to_message(const UpdateRequest& req)
{
    UpdateRequestMessage mes;
    
    mes.set_update_token(req.token.data(), req.token.size());
    mes.set_index(req.index);
    
    return mes;
}


} // namespace sophos
} // namespace sse
