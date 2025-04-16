#include <iostream>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <queue>
#include <unordered_map>
#include <algorithm>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// Graph Node Structure with CKKS-compatible embeddings
struct GraphNode {
    int id;
    vector<double> embedding; // Original embedding
    Ciphertext encrypted_embedding; // CKKS encrypted embedding
    vector<int> neighbors;
};

class ParallelGraphRetriever {
private:
    shared_ptr<SEALContext> context;
    unique_ptr<CKKSEncoder> encoder;
    unique_ptr<Encryptor> encryptor;
    unique_ptr<Evaluator> evaluator;
    unique_ptr<Decryptor> decryptor;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    size_t poly_modulus_degree;
    double scale;

    vector<GraphNode> graph;
    mutex graph_mutex;
    mutex crypto_mutex;
    atomic<int> progress;
    size_t batch_size;

    // Thread-safe initialization of graph vectors
    void parallel_initialize_vectors(size_t start, size_t end) {
        vector<Plaintext> plain_embeddings(end - start);
        vector<Ciphertext> encrypted_embeddings(end - start);

        // Process embeddings in parallel
        for (size_t i = start; i < end; i++) {
            encoder->encode(graph[i].embedding, scale, plain_embeddings[i - start]);
            
            // Cryptographic operations need to be serialized
            {
                lock_guard<mutex> lock(crypto_mutex);
                encryptor->encrypt(plain_embeddings[i - start], encrypted_embeddings[i - start]);
            }

            graph[i].encrypted_embedding = encrypted_embeddings[i - start];
            progress.fetch_add(1, memory_order_relaxed);
        }
    }

public:
    ParallelGraphRetriever(size_t poly_modulus_degree = 8192, double scale = pow(2.0, 40))
        : poly_modulus_degree(poly_modulus_degree), scale(scale) {
        // Initialize SEAL context
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
        
        context = make_shared<SEALContext>(parms);
        encoder = make_unique<CKKSEncoder>(*context);
        
        KeyGenerator keygen(*context);
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);
        
        encryptor = make_unique<Encryptor>(*context, public_key);
        evaluator = make_unique<Evaluator>(*context);
        decryptor = make_unique<Decryptor>(*context, secret_key);

        batch_size = 100; // Default batch size
    }

    // Load graph with embeddings
    void load_graph(const vector<GraphNode>& nodes) {
        graph = nodes;
        progress.store(0, memory_order_relaxed);
    }

    // Parallel initialization of graph vectors
    void initialize_encrypted_embeddings(size_t num_threads = thread::hardware_concurrency()) {
        size_t total_nodes = graph.size();
        size_t nodes_per_thread = (total_nodes + num_threads - 1) / num_threads;
        vector<thread> threads;

        auto start = chrono::high_resolution_clock::now();

        for (size_t i = 0; i < num_threads; i++) {
            size_t start_idx = i * nodes_per_thread;
            size_t end_idx = min((i + 1) * nodes_per_thread, total_nodes);
            threads.emplace_back(&ParallelGraphRetriever::parallel_initialize_vectors, this, start_idx, end_idx);
        }

        // Progress tracking
        while (progress.load(memory_order_relaxed) < total_nodes) {
            this_thread::sleep_for(chrono::seconds(1));
            cout << "Initialization progress: " << progress.load(memory_order_relaxed) << " / " << total_nodes << endl;
        }

        for (auto& t : threads) {
            t.join();
        }

        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
        cout << "Initialization completed in " << duration.count() << " ms" << endl;
    }

    // Retrieve similar nodes with proper similarity comparison
    vector<int> retrieve_similar_nodes(const vector<double>& query_embedding) {
        // Encrypt the query
        Plaintext plain_query;
        Ciphertext encrypted_query;
        {
            lock_guard<mutex> lock(crypto_mutex);
            encoder->encode(query_embedding, scale, plain_query);
            encryptor->encrypt(plain_query, encrypted_query);
        }

        // Compute similarities with all nodes
        vector<pair<double, int>> similarities(graph.size());
        
        #pragma omp parallel for
        for (size_t i = 0; i < graph.size(); i++) {
            Ciphertext sim;
            Plaintext plain_sim;
            vector<double> decoded_sim;
            
            {
                lock_guard<mutex> lock(crypto_mutex);
                evaluator->multiply(encrypted_query, graph[i].encrypted_embedding, sim);
                evaluator->relinearize_inplace(sim, relin_keys);
                evaluator->rescale_to_next_inplace(sim);
                decryptor->decrypt(sim, plain_sim);
                encoder->decode(plain_sim, decoded_sim);
            }
            
            // Calculate similarity score (cosine similarity approximation)
            double score = 0.0;
            for (double val : decoded_sim) score += val * val;
            similarities[i] = {score, graph[i].id};
        }

        // Sort by similarity (descending order)
        sort(similarities.begin(), similarities.end(), 
            [](const pair<double, int>& a, const pair<double, int>& b) {
                return a.first > b.first;
            });

        // Return top 10 most similar nodes
        vector<int> results;
        for (size_t i = 0; i < min(static_cast<size_t>(10), similarities.size()); i++) {
            results.push_back(similarities[i].second);
        }
        return results;
    }

    // Optimized batch retrieval
    vector<vector<int>> batch_retrieve(const vector<vector<double>>& queries) {
        vector<vector<int>> results(queries.size());

        // Process in batches
        for (size_t i = 0; i < queries.size(); i += batch_size) {
            size_t current_batch_size = min(batch_size, queries.size() - i);
            vector<thread> threads;

            for (size_t j = 0; j < current_batch_size; j++) {
                threads.emplace_back([this, &queries, &results, i, j]() {
                    results[i + j] = retrieve_similar_nodes(queries[i + j]);
                });
            }

            for (auto& t : threads) {
                t.join();
            }

            cout << "Processed batch " << (i / batch_size + 1) << " / " << (queries.size() + batch_size - 1) / batch_size << endl;
        }

        return results;
    }

    // Set batch size for parallel processing
    void set_batch_size(size_t size) {
        batch_size = size;
    }
};

// Example usage
int main() {
    // Example graph creation - simple linear graph with meaningful embeddings
    const size_t graph_size = 1000;
    vector<GraphNode> graph_nodes(graph_size);
    
    for (int i = 0; i < graph_size; i++) {
        graph_nodes[i].id = i;
        // Create embeddings that vary smoothly across the graph
        graph_nodes[i].embedding = {
            static_cast<double>(i) / graph_size,                // Linear feature
            sin(static_cast<double>(i) / graph_size * M_PI),    // Periodic feature
            static_cast<double>(i % 100) / 100.0                // Local feature
        };
        
        // Connect to neighbors (simple linear graph)
        if (i > 0) graph_nodes[i].neighbors.push_back(i - 1);
        if (i < graph_size - 1) graph_nodes[i].neighbors.push_back(i + 1);
    }

    // Initialize retriever
    ParallelGraphRetriever retriever;
    retriever.load_graph(graph_nodes);
    retriever.initialize_encrypted_embeddings(); // Parallel initialization

    // Example query - looking for nodes with middle-range features
    vector<double> query = {0.5, 1.0, 0.5}; // Max sine value at 0.5 position
    auto results = retriever.retrieve_similar_nodes(query);

    cout << "\nMost similar nodes to query {0.5, 1.0, 0.5}: ";
    for (int node_id : results) {
        cout << node_id << " ";
    }
    cout << endl;

    // Show sample embeddings for verification
    cout << "\nSample embeddings:\n";
    cout << "Node 500: ";
    for (double val : graph_nodes[500].embedding) cout << val << " ";
    cout << "\nNode 501: ";
    for (double val : graph_nodes[501].embedding) cout << val << " ";
    cout << "\nNode 502: ";
    for (double val : graph_nodes[502].embedding) cout << val << " ";
    cout << endl;

    // Batch processing example
    vector<vector<double>> queries = {
        {0.25, 0.0, 0.25},  // Should match lower range
        {0.75, -1.0, 0.75}   // Should match upper range
    };
    auto batch_results = retriever.batch_retrieve(queries);

    for (size_t i = 0; i < batch_results.size(); i++) {
        cout << "\nQuery " << i << " results: ";
        for (int node_id : batch_results[i]) {
            cout << node_id << " ";
        }
    }
    cout << endl;

    return 0;
}