#include <iostream>
#include <iomanip>
#include <vector>
#include <map>
#include <cmath>
#include "seal/seal.h"

using namespace std;
using namespace seal;

class NoiseAwareCKKS {
private:
    shared_ptr<SEALContext> context;
    unique_ptr<KeyGenerator> keygen;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    unique_ptr<Encryptor> encryptor;
    unique_ptr<Evaluator> evaluator;
    unique_ptr<Decryptor> decryptor;
    unique_ptr<CKKSEncoder> encoder;
    double scale;
    size_t poly_modulus_degree;

    // RAG Feature 1: Graph of modulus switching paths
    struct ModulusSwitchPath {
        vector<int> moduli_bits;
        vector<size_t> optimal_switch_points;
        string path_name;
    };
    vector<ModulusSwitchPath> modulus_paths;

    // RAG Feature 2: Noise tracking system
    struct OperationRecord {
        string op_name;
        int level;
        double noise_estimate;
    };
    vector<OperationRecord> noise_history;

public:
    NoiseAwareCKKS(size_t poly_degree = 8192, int security_level = 128) {
        initialize_context(poly_degree, security_level);
        initialize_modulus_paths();
    }

    void initialize_context(size_t poly_degree, int security_level) {
        poly_modulus_degree = poly_degree;
        
        // Select parameters based on security level
        vector<int> moduli_bits;
        if (security_level == 128) {
            moduli_bits = {50, 40, 40, 50};
            scale = pow(2.0, 40);
        } else { // 192-bit
            moduli_bits = {60, 50, 50, 60};
            scale = pow(2.0, 50);
        }

        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(poly_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_degree, moduli_bits));

        context = make_shared<SEALContext>(parms);
        keygen = make_unique<KeyGenerator>(*context);
        keygen->create_public_key(public_key);
        secret_key = keygen->secret_key();
        keygen->create_relin_keys(relin_keys);
        keygen->create_galois_keys(gal_keys);

        encryptor = make_unique<Encryptor>(*context, public_key);
        evaluator = make_unique<Evaluator>(*context);
        decryptor = make_unique<Decryptor>(*context, secret_key);
        encoder = make_unique<CKKSEncoder>(*context);
    }

    void initialize_modulus_paths() {
        // Predefined modulus switching paths (would come from knowledge graph)
        modulus_paths = {
            {{50, 40, 40, 50}, {2, 1}, "Balanced-4Level"},
            {{60, 50, 40, 40, 50}, {3, 2, 1}, "Extended-5Level"},
            {{60, 50, 40, 40, 40, 50}, {4, 3, 2, 1}, "Deep-6Level"}
        };
    }

    // RAG Feature 3: Retrieve optimal switching points
    vector<size_t> get_optimal_switch_points(const string& path_name) {
        for (const auto& path : modulus_paths) {
            if (path.path_name == path_name) {
                return path.optimal_switch_points;
            }
        }
        return modulus_paths[0].optimal_switch_points; // Default
    }

    // Noise estimation functions
    double estimate_noise(const Ciphertext& cipher) {
        // Simplified noise estimation - in practice would use more accurate methods
        auto context_data = context->get_context_data(cipher.parms_id());
        size_t level = context_data->chain_index();
        double noise_est = 100.0 / (level + 1);
        return noise_est;
    }

    void record_operation(const string& op_name, const Ciphertext& cipher) {
        auto context_data = context->get_context_data(cipher.parms_id());
        noise_history.push_back({
            op_name,
            static_cast<int>(context_data->chain_index()),
            estimate_noise(cipher)
        });
    }

    // RAG Feature 4: Visual progress tracking
    void print_noise_history() {
        cout << "\nNoise Budget Tracking:\n";
        cout << "-------------------------------------------------\n";
        cout << "| Operation       | Level | Noise Estimate |\n";
        cout << "-------------------------------------------------\n";
        
        for (const auto& record : noise_history) {
            cout << "| " << setw(15) << left << record.op_name
                 << " | " << setw(5) << record.level
                 << " | " << setw(13) << fixed << setprecision(2) << record.noise_estimate
                 << " |\n";
        }
        cout << "-------------------------------------------------\n";
    }

    // CKKS Operations with noise tracking
    Ciphertext encrypt_vector(const vector<double>& values) {
        Plaintext plain;
        encoder->encode(values, scale, plain);
        Ciphertext cipher;
        encryptor->encrypt(plain, cipher);
        record_operation("Encrypt", cipher);
        return cipher;
    }

    Ciphertext add_vectors(const Ciphertext& a, const Ciphertext& b) {
        Ciphertext result;
        evaluator->add(a, b, result);
        record_operation("Add", result);
        return result;
    }

    Ciphertext multiply_vectors(const Ciphertext& a, const Ciphertext& b) {
        Ciphertext result;
        evaluator->multiply(a, b, result);
        evaluator->relinearize_inplace(result, relin_keys);
        evaluator->rescale_to_next_inplace(result);
        record_operation("Multiply", result);
        return result;
    }

    vector<double> decrypt_vector(const Ciphertext& cipher) {
        Plaintext plain;
        decryptor->decrypt(cipher, plain);
        vector<double> result;
        encoder->decode(plain, result);
        return result;
    }

    void modulus_switch_to_next(Ciphertext& cipher) {
        evaluator->mod_switch_to_next_inplace(cipher);
        record_operation("ModSwitch", cipher);
    }
};

int main() {
    cout << "Noise-Aware CKKS System with RAG Features\n";
    cout << "=========================================\n";

    // Initialize system with RAG capabilities
    NoiseAwareCKKS ckks(8192, 128);

    // Input data
    vector<double> vec1 = {1.0, 2.0, 3.0, 4.0};
    vector<double> vec2 = {0.5, 1.5, 2.5, 3.5};

    // Encrypt vectors
    auto cipher1 = ckks.encrypt_vector(vec1);
    auto cipher2 = ckks.encrypt_vector(vec2);

    // Perform operations
    auto cipher_add = ckks.add_vectors(cipher1, cipher2);
    auto cipher_mult = ckks.multiply_vectors(cipher1, cipher2);

    // Modulus switching demonstration
    ckks.modulus_switch_to_next(cipher_mult);
    ckks.modulus_switch_to_next(cipher_mult);

    // Retrieve optimal switching points from knowledge graph
    auto switch_points = ckks.get_optimal_switch_points("Balanced-4Level");
    cout << "\nOptimal switching points from RAG: ";
    for (auto pt : switch_points) cout << pt << " ";
    cout << endl;

    // Decrypt and show results
    auto result_add = ckks.decrypt_vector(cipher_add);
    auto result_mult = ckks.decrypt_vector(cipher_mult);

    cout << "\nResults:\n";
    cout << "Addition: [";
    for (auto val : result_add) cout << val << " ";
    cout << "]\n";

    cout << "Multiplication: [";
    for (auto val : result_mult) cout << val << " ";
    cout << "]\n";

    // Display noise tracking history
    ckks.print_noise_history();

    return 0;
}