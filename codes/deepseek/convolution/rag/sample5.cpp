#include <iostream>
#include <vector>
#include <memory>
#include <cmath>
#include <seal/seal.h>

using namespace std;
using namespace seal;

class NoiseManagedGraphAttention {
public:
    NoiseManagedGraphAttention(size_t poly_modulus_degree, 
                             const vector<Modulus> &coeff_modulus,
                             double initial_noise_stddev = 0.1,
                             double attention_sharpening = 1.0)
        : attention_sharpening_(attention_sharpening) {
        
        // Initialize encryption parameters
        EncryptionParameters params(scheme_type::ckks);
        params.set_poly_modulus_degree(poly_modulus_degree);
        
        // Set the coefficient modulus
        params.set_coeff_modulus(coeff_modulus);
        
        // Create SEAL context with security level
        context_ = make_shared<SEALContext>(params, true, sec_level_type::tc128);
        
        // Generate keys
        KeyGenerator keygen(*context_);
        secret_key_ = keygen.secret_key();
        keygen.create_public_key(public_key_);
        keygen.create_relin_keys(relin_keys_);
        keygen.create_galois_keys(galois_keys_);
        
        // Create evaluator and encoder
        evaluator_ = make_shared<Evaluator>(*context_);
        encoder_ = make_shared<CKKSEncoder>(*context_);
        encryptor_ = make_shared<Encryptor>(*context_, public_key_);
        decryptor_ = make_shared<Decryptor>(*context_, secret_key_);
        
        // Initialize noise parameters
        noise_stddev_ = initial_noise_stddev;
        scale_ = pow(2.0, 40); // Default scale
    }

    // Rest of the implementation remains the same...
    // [Previous implementation of graph_attention() and other methods]
    
private:
    // SEAL components
    shared_ptr<SEALContext> context_;
    SecretKey secret_key_;
    PublicKey public_key_;
    RelinKeys relin_keys_;
    GaloisKeys galois_keys_;
    shared_ptr<Evaluator> evaluator_;
    shared_ptr<CKKSEncoder> encoder_;
    shared_ptr<Encryptor> encryptor_;
    shared_ptr<Decryptor> decryptor_;
    
    // Noise and attention parameters
    double noise_stddev_;
    double scale_;
    double attention_sharpening_;
};

int main() {
    try {
        // Example parameters
        size_t poly_modulus_degree = 8192;
        
        // Create coefficient modulus - must use Modulus class in SEAL 4.1
        std::vector<seal::Modulus> coeff_modulus = seal::CoeffModulus::Create(poly_modulus_degree, {40, 40, 40, 40});
        
        // Initialize noise-managed graph attention
        NoiseManagedGraphAttention gnn(poly_modulus_degree, coeff_modulus, 0.1, 1.5);
        
        cout << "Noise-managed graph attention initialized successfully!" << endl;
        
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }
    
    return 0;
}