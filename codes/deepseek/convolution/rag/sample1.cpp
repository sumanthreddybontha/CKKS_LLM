#include <iostream>
#include <vector>
#include <map>
#include <memory>
#include <cmath>
#include <random>
#include <algorithm>
#include <unordered_set>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// Graph Node Structure
struct GraphNode {
    int id;
    vector<double> embedding;
    vector<int> neighbors;
};

// Simplified Knowledge Graph
class KnowledgeGraph {
private:
    vector<GraphNode> nodes;
    map<int, int> id_to_index;
    size_t embedding_size;

public:
    KnowledgeGraph(size_t emb_size) : embedding_size(emb_size) {}

    void add_node(int id, const vector<double>& embedding) {
        if (embedding.size() != embedding_size) {
            throw invalid_argument("Embedding size mismatch");
        }
        nodes.push_back({id, embedding, {}});
        id_to_index[id] = nodes.size() - 1;
    }

    void add_edge(int from_id, int to_id) {
        if (!id_to_index.count(from_id) || !id_to_index.count(to_id)) {
            throw invalid_argument("Node ID not found");
        }
        nodes[id_to_index[from_id]].neighbors.push_back(to_id);
    }

    const GraphNode& get_node(int id) const {
        return nodes[id_to_index.at(id)];
    }

    vector<int> get_neighbors(int id) const {
        return nodes[id_to_index.at(id)].neighbors;
    }

    const vector<double>& get_embedding(int id) const {
        return nodes[id_to_index.at(id)].embedding;
    }

    size_t size() const { return nodes.size(); }
    
    vector<GraphNode>& get_nodes() { return nodes; }
    const vector<GraphNode>& get_nodes() const { return nodes; }
};

// Simplified Graph Embedding Model (TransE-like)
class GraphEmbedder {
private:
    size_t embedding_size;
    default_random_engine generator;
    uniform_real_distribution<double> dist;

public:
    GraphEmbedder(size_t emb_size) : 
        embedding_size(emb_size), 
        dist(-1.0, 1.0) {}

    void initialize_embeddings(KnowledgeGraph& graph) {
        for (auto& node : graph.get_nodes()) {
            vector<double> new_embedding(embedding_size);
            for (auto& val : new_embedding) {
                val = dist(generator);
            }
            node.embedding = new_embedding;
        }
    }

    vector<double> embed_query(const string& query) {
        vector<double> embedding(embedding_size);
        for (auto& val : embedding) {
            val = dist(generator);
        }
        return embedding;
    }
    
    size_t get_embedding_size() const { return embedding_size; }
};

// Graph Retriever with CKKS Operations
class GraphRetriever {
private:
    const KnowledgeGraph& graph;
    GraphEmbedder& embedder;
    unique_ptr<SEALContext> context;
    unique_ptr<CKKSEncoder> encoder;
    unique_ptr<Encryptor> encryptor;
    unique_ptr<Decryptor> decryptor;
    unique_ptr<Evaluator> evaluator;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    size_t top_k;

    // Modified sum elements function to be more robust
    void sum_elements(const Ciphertext& encrypted_vec, Ciphertext& encrypted_sum) {
        encrypted_sum = encrypted_vec;
        Ciphertext rotated;
        evaluator->rotate_vector(encrypted_sum, 1, galois_keys, rotated);
        evaluator->add_inplace(encrypted_sum, rotated);
    }

public:
    GraphRetriever(const KnowledgeGraph& g, GraphEmbedder& e, size_t k = 3) 
        : graph(g), embedder(e), top_k(k) {
        // Initialize CKKS scheme with more conservative parameters
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(
            poly_modulus_degree, { 60, 40, 40, 60 }));
        
        context = make_unique<SEALContext>(parms);
        encoder = make_unique<CKKSEncoder>(*context);
        KeyGenerator keygen(*context);
        
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);
        keygen.create_galois_keys(galois_keys);
        
        encryptor = make_unique<Encryptor>(*context, public_key);
        decryptor = make_unique<Decryptor>(*context, secret_key);
        evaluator = make_unique<Evaluator>(*context);
    }

    vector<int> retrieve(const string& query) {
        try {
            // Embed the query
            auto query_embedding = embedder.embed_query(query);

            // Encrypt the query embedding with proper scale
            double scale = pow(2.0, 40);
            Plaintext plain_query;
            encoder->encode(query_embedding, scale, plain_query);
            Ciphertext encrypted_query;
            encryptor->encrypt(plain_query, encrypted_query);

            // Find most similar nodes
            vector<pair<double, int>> scores;
            for (const auto& node : graph.get_nodes()) {
                // Encode node embedding
                Plaintext plain_node;
                encoder->encode(node.embedding, scale, plain_node);
                
                // Compute dot product homomorphically
                Ciphertext encrypted_result;
                evaluator->multiply_plain(encrypted_query, plain_node, encrypted_result);
                evaluator->relinearize_inplace(encrypted_result, relin_keys);
                evaluator->rescale_to_next_inplace(encrypted_result);
                
                // Sum all elements
                Ciphertext encrypted_sum;
                sum_elements(encrypted_result, encrypted_sum);
                
                // Decrypt the result
                Plaintext plain_result;
                decryptor->decrypt(encrypted_sum, plain_result);
                vector<double> result;
                encoder->decode(plain_result, result);
                
                scores.emplace_back(result[0], node.id);
            }

            // Sort by score and get top-k
            sort(scores.begin(), scores.end(), greater<pair<double, int>>());
            vector<int> results;
            for (size_t i = 0; i < min(top_k, scores.size()); ++i) {
                results.push_back(scores[i].second);
            }

            return results;
        } catch (const exception& e) {
            cerr << "Error in retrieval: " << e.what() << endl;
            return {};
        }
    }

    vector<int> get_context(int node_id, int depth = 1) {
        vector<int> context;
        vector<int> current_level = {node_id};
        unordered_set<int> visited;

        for (int i = 0; i <= depth; ++i) {
            vector<int> next_level;
            for (int nid : current_level) {
                if (visited.count(nid)) continue;
                visited.insert(nid);
                context.push_back(nid);
                
                for (int neighbor : graph.get_neighbors(nid)) {
                    if (!visited.count(neighbor)) {
                        next_level.push_back(neighbor);
                    }
                }
            }
            current_level = next_level;
        }

        return context;
    }
};

// Response Generator
class ResponseGenerator {
public:
    string generate_response(const vector<int>& node_ids, const KnowledgeGraph& graph) {
        string response = "Generated response based on nodes: ";
        for (int id : node_ids) {
            response += to_string(id) + " ";
            // Add some sample information about each node
            const auto& node = graph.get_node(id);
            response += "(embedding norm: " + 
                      to_string(sqrt(inner_product(node.embedding.begin(), 
                                                 node.embedding.end(),
                                                 node.embedding.begin(), 0.0))) +
                      ", neighbors: " + to_string(node.neighbors.size()) + ") ";
        }
        return response;
    }
};

// Main Graph-RAG System
class GraphRAGSystem {
private:
    KnowledgeGraph graph;
    GraphEmbedder embedder;
    unique_ptr<GraphRetriever> retriever;
    ResponseGenerator generator;

public:
    GraphRAGSystem(size_t emb_size = 128) 
        : graph(emb_size), embedder(emb_size) {
        initialize_sample_graph();
        retriever = make_unique<GraphRetriever>(graph, embedder);
    }

    void initialize_sample_graph() {
        // Initialize with more meaningful embeddings
        embedder.initialize_embeddings(graph);
        
        // Create a simple graph with 10 nodes
        for (int i = 0; i < 10; ++i) {
            vector<double> embedding(embedder.get_embedding_size());
            graph.add_node(i, embedding);
        }

        // Create a simple graph structure
        graph.add_edge(0, 1);
        graph.add_edge(0, 2);
        graph.add_edge(1, 3);
        graph.add_edge(2, 4);
        graph.add_edge(3, 5);
        graph.add_edge(4, 6);
        graph.add_edge(5, 7);
        graph.add_edge(6, 8);
        graph.add_edge(7, 9);
        // Add some reverse edges to make it more interesting
        graph.add_edge(1, 0);
        graph.add_edge(2, 0);
        graph.add_edge(4, 2);
    }

    string query(const string& question) {
        try {
            auto relevant_nodes = retriever->retrieve(question);
            
            vector<int> context_nodes;
            for (int node_id : relevant_nodes) {
                auto context = retriever->get_context(node_id);
                context_nodes.insert(context_nodes.end(), context.begin(), context.end());
            }

            // Remove duplicates
            sort(context_nodes.begin(), context_nodes.end());
            context_nodes.erase(unique(context_nodes.begin(), context_nodes.end()), context_nodes.end());

            return generator.generate_response(context_nodes, graph);
        } catch (const exception& e) {
            return "Error processing query: " + string(e.what());
        }
    }
};

int main() {
    try {
        GraphRAGSystem rag_system;

        cout << "Testing Graph-RAG system:" << endl;
        cout << rag_system.query("Find related nodes") << endl;
        cout << rag_system.query("Search for connected concepts") << endl;
        
        // Additional test queries
        cout << rag_system.query("Node connections") << endl;
        cout << rag_system.query("Graph structure") << endl;

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}