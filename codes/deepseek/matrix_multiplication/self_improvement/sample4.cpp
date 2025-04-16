#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <future>
#include <random>
#include <sstream>

// Simple XOR encryption (placeholder)
std::string encrypt(const std::vector<int>& vec, const std::string& key) {
    std::ostringstream oss;
    for (size_t i = 0; i < vec.size(); ++i) {
        char encrypted = vec[i] ^ key[i % key.size()];
        oss << std::hex << (int)encrypted;
    }
    return oss.str();
}

// Evaluation function (could be fitness score, etc.)
int evaluate(const std::vector<int>& vec) {
    int sum = 0;
    for (int val : vec) sum += val;
    return sum;
}

// Thread-safe initialization of a vector
std::vector<int> initialize_vector(int persona_id, int size) {
    std::vector<int> vec(size);
    std::mt19937 rng(persona_id); // Seed with persona_id for determinism
    std::uniform_int_distribution<int> dist(1, 100);
    for (int& val : vec) {
        val = dist(rng);
    }
    return vec;
}

int main() {
    const int num_personas = 6;
    const int vector_size = 10;
    const std::string encryption_key = "secretKey";

    // Future-based async initialization
    std::vector<std::future<std::vector<int>>> futures;
    for (int i = 0; i < num_personas; ++i) {
        futures.push_back(std::async(std::launch::async, initialize_vector, i, vector_size));
    }

    // Serial encryption and evaluation
    for (int i = 0; i < num_personas; ++i) {
        std::vector<int> vec = futures[i].get();

        std::string encrypted = encrypt(vec, encryption_key);
        int score = evaluate(vec);

        std::cout << "Persona " << i << ":\n";
        std::cout << "  Vector: ";
        for (int val : vec) std::cout << val << " ";
        std::cout << "\n  Encrypted: " << encrypted;
        std::cout << "\n  Evaluation Score: " << score << "\n\n";
    }

    return 0;
}
