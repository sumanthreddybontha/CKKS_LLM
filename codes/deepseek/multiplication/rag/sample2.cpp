#include <iostream>
#include <vector>
#include <memory>
#include <cmath>
#include <seal/seal.h>

using namespace std;
using namespace seal;

class CKKSMultiplier {
public:
    CKKSMultiplier(size_t poly_modulus_degree = 8192, 
                  vector<int> bit_sizes = {50, 30, 30, 40},
                  double scale = pow(2.0, 40)) 
    {
        // Initialize SEAL context with CKKS scheme
        EncryptionParameters params(scheme_type::ckks);
        params.set_poly_modulus_degree(poly_modulus_degree);
        
        // Create modulus chain
        params.set_coeff_modulus(CoeffModulus::Create(
            poly_modulus_degree, bit_sizes));
        
        context_ = make_shared<SEALContext>(params);
        
        // Generate keys
        KeyGenerator keygen(*context_);
        secret_key_ = keygen.secret_key();
        keygen.create_public_key(public_key_);
        keygen.create_relin_keys(relin_keys_);
        
        // Set up encoder and encryptor/decryptor
        encoder_ = make_shared<CKKSEncoder>(*context_);
        encryptor_ = make_shared<Encryptor>(*context_, public_key_);
        decryptor_ = make_shared<Decryptor>(*context_, secret_key_);
        evaluator_ = make_shared<Evaluator>(*context_);
        
        scale_ = scale;
        chunk_size_ = min(static_cast<size_t>(1024), encoder_->slot_count());
        slot_count_ = encoder_->slot_count();
        
        cout << "CKKS initialized with " << slot_count_ << " slots" << endl;
    }
    
    vector<double> multiply_large_vectors(const vector<double>& vec1, 
                                        const vector<double>& vec2) {
        if (vec1.size() != vec2.size()) {
            throw invalid_argument("Vectors must be of equal length");
        }
        
        size_t total_size = vec1.size();
        vector<double> result(total_size, 0.0);
        
        cout << "Processing " << total_size << " elements in chunks of " 
             << chunk_size_ << endl;
        
        for (size_t i = 0; i < total_size; i += chunk_size_) {
            size_t current_chunk_size = min(chunk_size_, total_size - i);
            
            // Process chunks
            auto ct1 = process_chunk(vec1, i, current_chunk_size);
            auto ct2 = process_chunk(vec2, i, current_chunk_size);
            
            // Multiply
            Ciphertext product;
            evaluator_->multiply(ct1, ct2, product);
            evaluator_->relinearize_inplace(product, relin_keys_);
            evaluator_->rescale_to_next_inplace(product);
            
            // Decrypt and decode
            vector<double> chunk_result = decrypt_and_decode(product, current_chunk_size);
            
            // Copy to final result
            copy(chunk_result.begin(), chunk_result.end(), result.begin() + i);
            
            cout << "Processed chunk " << (i/chunk_size_ + 1) 
                 << "/" << ceil(static_cast<double>(total_size)/chunk_size_) << endl;
        }
        
        return result;
    }
    
private:
    shared_ptr<SEALContext> context_;
    SecretKey secret_key_;
    PublicKey public_key_;
    RelinKeys relin_keys_;
    shared_ptr<CKKSEncoder> encoder_;
    shared_ptr<Encryptor> encryptor_;
    shared_ptr<Decryptor> decryptor_;
    shared_ptr<Evaluator> evaluator_;
    double scale_;
    size_t chunk_size_;
    size_t slot_count_;
    
    Ciphertext process_chunk(const vector<double>& vec, size_t start, size_t length) {
        vector<double> chunk(slot_count_, 0.0);
        copy(vec.begin() + start, vec.begin() + start + length, chunk.begin());
        
        Plaintext plain;
        encoder_->encode(chunk, scale_, plain);
        
        Ciphertext cipher;
        encryptor_->encrypt(plain, cipher);
        
        return cipher;
    }
    
    vector<double> decrypt_and_decode(const Ciphertext& cipher, size_t output_length) {
        Plaintext plain;
        decryptor_->decrypt(cipher, plain);
        
        vector<double> result;
        encoder_->decode(plain, result);
        result.resize(output_length);
        
        return result;
    }
};

int main() {
    try {
        // Initialize with parameters suitable for demonstration
        size_t poly_modulus_degree = 8192;
        vector<int> bit_sizes = {40, 30, 30, 40}; // Proper modulus chain for CKKS
        double scale = pow(2.0, 40);
        
        CKKSMultiplier multiplier(poly_modulus_degree, bit_sizes, scale);
        
        // Create test vectors
        size_t vec_size = 2000;
        vector<double> vec1(vec_size);
        vector<double> vec2(vec_size);
        
        for (size_t i = 0; i < vec_size; ++i) {
            vec1[i] = 1.0;
            vec2[i] = 2.0;
        }
        
        cout << "Starting CKKS multiplication..." << endl;
        auto result = multiplier.multiply_large_vectors(vec1, vec2);
        
        // Verify results
        cout << "\nVerification (first 5 elements):" << endl;
        for (size_t i = 0; i < 5; ++i) {
            cout << vec1[i] << " * " << vec2[i] << " = " << result[i] 
                 << " (expected: " << vec1[i] * vec2[i] << ")" << endl;
        }
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}