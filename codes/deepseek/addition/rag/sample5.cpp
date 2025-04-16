#include <iostream>
#include <vector>
#include <memory>
#include <chrono>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unistd.h>
#include <cmath>
#include "seal/seal.h"

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <unistd.h>
#endif

using namespace std;
using namespace seal;

class MemoryOptimizedCKKS {
private:
    struct MemoryProfile {
        string platform;
        size_t total_memory;
        size_t available_memory;
        size_t optimal_chunk_size;
        vector<int> recommended_moduli;
    };

    vector<MemoryProfile> memory_graph;
    shared_ptr<SEALContext> context;
    unique_ptr<CKKSEncoder> encoder;
    SecretKey secret_key;  // Moved to class member
    double scale;
    size_t poly_modulus_degree;
    size_t slot_count;

    size_t get_system_memory() {
#ifdef _WIN32
        MEMORYSTATUSEX status;
        status.dwLength = sizeof(status);
        GlobalMemoryStatusEx(&status);
        return status.ullTotalPhys / (1024 * 1024); // MB
#else
        long pages = sysconf(_SC_PHYS_PAGES);
        long page_size = sysconf(_SC_PAGE_SIZE);
        return (pages * page_size) / (1024 * 1024); // MB
#endif
    }

    void init_memory_graph() {
        size_t system_mem = get_system_memory();
        cout << "Detected system memory: " << system_mem << " MB\n";

        memory_graph = {
            {"Low-Memory", 4096, static_cast<size_t>(4096 * 0.75), 4096, {40, 30, 40}},
            {"Standard", 8192, static_cast<size_t>(8192 * 0.75), 8192, {50, 40, 50}},
            {"High-Memory", 16384, static_cast<size_t>(16384 * 0.75), 16384, {60, 50, 60}},
            {"Server-Grade", 32768, static_cast<size_t>(32768 * 0.75), 32768, {60, 50, 40, 50, 60}}
        };

        memory_graph.push_back({
            "Current-System",
            system_mem,
            static_cast<size_t>(system_mem * 0.75),
            0,
            {}
        });
    }

    vector<vector<double>> split_into_chunks(const vector<double>& data, size_t chunk_size) {
        vector<vector<double>> chunks;
        for (size_t i = 0; i < data.size(); i += chunk_size) {
            size_t end = min(i + chunk_size, data.size());
            chunks.emplace_back(data.begin() + i, data.begin() + end);
        }
        return chunks;
    }

public:
    MemoryOptimizedCKKS(size_t poly_degree = 0) {
        init_memory_graph();
        
        const MemoryProfile* best_profile = &memory_graph[0];
        size_t system_mem = get_system_memory();
        
        for (const auto& profile : memory_graph) {
            if (system_mem >= profile.total_memory && 
                profile.total_memory > best_profile->total_memory) {
                best_profile = &profile;
            }
        }

        poly_modulus_degree = poly_degree ? poly_degree : best_profile->optimal_chunk_size;
        slot_count = poly_modulus_degree / 2;
        
        cout << "Selected memory profile: " << best_profile->platform 
             << " with chunk size " << poly_modulus_degree 
             << " (" << slot_count << " slots)\n";

        vector<int> moduli_bits;
        if (best_profile->recommended_moduli.empty()) {
            if (poly_modulus_degree <= 4096) {
                moduli_bits = {40, 30, 40};
            } else if (poly_modulus_degree <= 8192) {
                moduli_bits = {50, 40, 50};
            } else {
                moduli_bits = {60, 50, 60};
            }
        } else {
            moduli_bits = best_profile->recommended_moduli;
        }

        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(
            poly_modulus_degree, moduli_bits));

        context = make_shared<SEALContext>(parms);
        encoder = make_unique<CKKSEncoder>(*context);
        
        // Generate keys during construction
        KeyGenerator keygen(*context);
        secret_key = keygen.secret_key();
        
        scale = pow(2.0, moduli_bits[0] - 10);
    }

    vector<Ciphertext> encrypt_data(const vector<double>& data) {
        auto chunks = split_into_chunks(data, slot_count);
        vector<Ciphertext> ciphertexts;

        PublicKey public_key;
        KeyGenerator keygen(*context, secret_key);
        keygen.create_public_key(public_key);
        Encryptor encryptor(*context, public_key);

        for (const auto& chunk : chunks) {
            Plaintext plain;
            encoder->encode(chunk, scale, plain);
            Ciphertext cipher;
            encryptor.encrypt(plain, cipher);
            ciphertexts.push_back(std::move(cipher));
        }
        
        return ciphertexts;
    }

    vector<double> decrypt_data(const vector<Ciphertext>& ciphertexts) {
        vector<double> result;
        Decryptor decryptor(*context, secret_key);

        for (const auto& cipher : ciphertexts) {
            Plaintext plain;
            decryptor.decrypt(cipher, plain);
            vector<double> chunk;
            encoder->decode(plain, chunk);
            result.insert(result.end(), chunk.begin(), chunk.end());
        }
        
        return result;
    }

    void print_memory_stats() const {
        cout << "\nCurrent Memory Configuration:\n";
        cout << "Polynomial Degree: " << poly_modulus_degree << "\n";
        cout << "Total Slots: " << slot_count << "\n";
        cout << "Scale: 2^" << log2(scale) << "\n";
        
        auto context_data = context->first_context_data();
        cout << "Modulus Chain:\n";
        while (context_data) {
            cout << " - Level " << context_data->chain_index() 
                 << ": " << context_data->total_coeff_modulus_bit_count() 
                 << " bits\n";
            context_data = context_data->next_context_data();
        }
    }
};

int main() {
    cout << "Memory-Optimized CKKS with RAG Integration\n";
    cout << "=========================================\n";

    try {
        MemoryOptimizedCKKS ckks;

        vector<double> test_data(10000);
        for (size_t i = 0; i < test_data.size(); i++) {
            test_data[i] = (i % 100) / 10.0;
        }

        auto ciphertexts = ckks.encrypt_data(test_data);
        cout << "Encrypted data into " << ciphertexts.size() << " ciphertexts\n";

        auto decrypted = ckks.decrypt_data(ciphertexts);
        cout << "Decrypted data contains " << decrypted.size() << " values\n";

        // Verify first and last few values
        cout << "First values: ";
        for (size_t i = 0; i < min(size_t(5), decrypted.size()); i++) {
            cout << decrypted[i] << " ";
        }
        cout << "\nLast values: ";
        for (size_t i = max(size_t(0), decrypted.size() - 5); i < decrypted.size(); i++) {
            cout << decrypted[i] << " ";
        }
        cout << endl;

        ckks.print_memory_stats();
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    return 0;
}