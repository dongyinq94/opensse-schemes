//
//  main.cpp
//  fast
//
//  Created by Raphael Bost on 29/03/2016.
//  Copyright © 2016 Raphael Bost. All rights reserved.
//

#include <iostream>
#include <fstream>
#include <memory>

#include "fast/fast_client.hpp"
#include "fast/fast_server.hpp"
#include "src/utils/utils.hpp"

using namespace sse::fast;
using namespace std;

void test_client_server()
{
/*     string client_sk_path = "tdp_sk.key";
    string client_master_key_path = "derivation_master.key";
    string client_tdp_prg_key_path = "tdp_prg.key";
    string server_pk_path = "tdp_pk.key";
    
    
    ifstream client_sk_in(client_sk_path.c_str());
    ifstream client_master_key_in(client_master_key_path.c_str());
    ifstream client_tdp_prg_key_in(client_tdp_prg_key_path.c_str());
    ifstream server_pk_in(server_pk_path.c_str());
    
    unique_ptr<FastClient> client;
    unique_ptr<FastServer> server;
    
    SearchRequest s_req;
    UpdateRequest u_req;
    std::list<index_type> res;
    string key;

    if((client_sk_in.good() != client_master_key_in.good()) || (client_sk_in.good() != server_pk_in.good()) || (client_sk_in.good() != client_tdp_prg_key_in.good()))
    {
        client_sk_in.close();
        client_master_key_in.close();
        server_pk_in.close();
        client_tdp_prg_key_in.close();
        
        throw std::runtime_error("All streams are not in the same state");
    }
    
    if (client_sk_in.good() == true) {
        // the files exist
        cout << "Restart client and server" << endl;
        
        stringstream client_sk_buf, client_master_key_buf, server_pk_buf, client_tdp_prg_key_buf;

        client_sk_buf << client_sk_in.rdbuf();
        client_master_key_buf << client_master_key_in.rdbuf();
        server_pk_buf << server_pk_in.rdbuf();
        client_tdp_prg_key_buf << client_tdp_prg_key_in.rdbuf();

        client.reset(new  FastClient("client.sav", client_sk_buf.str(), client_master_key_buf.str(), client_tdp_prg_key_buf.str()));
        
        server.reset(new FastServer("server.dat", server_pk_buf.str()));
        
        SearchRequest s_req;
        std::list<index_type> res;
        string key;

    }else{
        cout << "Create new client-server instances" << endl;
        
        client.reset(new FastClient("client.sav", 1000));

        server.reset(new FastServer("server.dat", 1000, client->public_key()));
        
        // write keys to files
        ofstream client_sk_out(client_sk_path.c_str());
        client_sk_out << client->private_key();
        client_sk_out.close();
        
        ofstream client_master_key_out(client_master_key_path.c_str());
        client_master_key_out << client->master_derivation_key();
        client_master_key_out.close();

        ofstream server_pk_out(server_pk_path.c_str());
        server_pk_out << server->public_key();
        server_pk_out.close();

        u_req = client->update_request("toto", 0);
        server->update(u_req);
        
        u_req = client->update_request("titi", 0);
        server->update(u_req);
        
        u_req = client->update_request("toto", 1);
        server->update(u_req);
        
        u_req = client->update_request("tata", 0);
        server->update(u_req);
        

    }
    

    
    key = "toto";
    s_req = client->search_request(key);
    res = server->search(s_req);

    cout << "Search " << key << ". Results: [";
    for(index_type i : res){
        cout << i << ", ";
    }
    cout << "]" << endl;

    key = "titi";
    s_req = client->search_request(key);
    res = server->search(s_req);
    
    cout << "Search " << key << ". Results: [";
    for(index_type i : res){
        cout << i << ", ";
    }
    cout << "]" << endl;

    key = "tata";
    s_req = client->search_request(key);
    res = server->search(s_req);
    
    cout << "Search " << key << ". Results: [";
    for(index_type i : res){
        cout << i << ", ";
    }
    cout << "]" << endl;

    
    client_sk_in.close();
    client_master_key_in.close();
    server_pk_in.close();

}

void test_kw_indexer()
{
    
    map<string, uint32_t> m, n;
    
    m["toto"] = 0;
    m["titi"] = 1;
    m["tata"] = 2;
    m["tutu"] = 34;
    
    ofstream out("test.csv");
    
    write_keyword_map(out, m);
    
    out.close();
    
    ifstream in("test.csv");
    
    bool ret = parse_keyword_map(in, n);
    
    if (ret) {
        cout << "Success" << endl;
    }else{
        cout << "Failed" << endl;
    }
    
    for (auto p : n) {
        cout << p.first << "| , |" << p.second << endl;
    }
     */
}

int main(int argc, const char * argv[]) {

    test_client_server();
    
    return 0;
}
