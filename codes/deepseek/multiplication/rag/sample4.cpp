#include <iostream>
#include <vector>
#include <cmath>
#include <seal/seal.h>

using namespace std;
using namespace seal;

class CKKSKaratsubaMultiplier {
public:
    CKKSKaratsubaMultiplier(size_t poly_modulus_degree = 8192,
                          vector<int> bit_sizes = {40, 30, 30, 40},
                          double scale = pow(2.0, 30)) {
        // 1. Set up encryption parameters
        EncryptionParameters params(scheme_type::ckks);
        params.set_poly_modulus_degree(poly_modulus_degree);
        
        // 2. Create modulus chain suitable for CKKS
        params.set_coeff_modulus(CoeffModulus::Create(
            poly_modulus_degree, bit_sizes));
        
        // 3. Create and validate context
        context_ = make_shared<SEALContext>(params);
        if (!context_->parameters_set()) {
            throw runtime_error("Invalid encryption parameters");
        }
        
        // 4. Generate keys
        KeyGenerator keygen(*context_);
        secret_key_ = keygen.secret_key();
        keygen.create_public_key(public_key_);
        keygen.create_relin_keys(relin_keys_);
        
        // 5. Initialize operations
        encoder_ = make_unique<CKKSEncoder>(*context_);
        encryptor_ = make_unique<Encryptor>(*context_, public_key_);
        decryptor_ = make_unique<Decryptor>(*context_, secret_key_);
        evaluator_ = make_unique<Evaluator>(*context_);
        
        scale_ = scale;
        slot_count_ = encoder_->slot_count();
        
        cout << "Initialized CKKS with " << slot_count_ << " slots" << endl;
    }

    vector<double> multiply(double a, double b) {
        // 1. Karatsuba decomposition
        auto [a1, a2] = decompose(a);
        auto [b1, b2] = decompose(b);
        
        // 2. Encode and encrypt components
        vector<double> a_vec = {a1, a2};
        vector<double> b_vec = {b1, b2};
        
        Plaintext a_plain, b_plain;
        encoder_->encode(a_vec, scale_, a_plain);
        encoder_->encode(b_vec, scale_, b_plain);
        
        Ciphertext a_ct, b_ct;
        encryptor_->encrypt(a_plain, a_ct);
        encryptor_->encrypt(b_plain, b_ct);
        
        // 3. Compute intermediate products
        Ciphertext z0, z1, z2;
        evaluator_->multiply(a_ct, b_ct, z0);  // a1*b1
        evaluator_->relinearize_inplace(z0, relin_keys_);
        evaluator_->rescale_to_next_inplace(z0);
        
        evaluator_->multiply(a_ct, b_ct, z1);  // a1*b2 + a2*b1
        evaluator_->relinearize_inplace(z1, relin_keys_);
        evaluator_->rescale_to_next_inplace(z1);
        
        evaluator_->multiply(a_ct, b_ct, z2);  // a2*b2
        evaluator_->relinearize_inplace(z2, relin_keys_);
        evaluator_->rescale_to_next_inplace(z2);
        
        // 4. Combine results
        Ciphertext result;
        evaluator_->add(z0, z1, result);
        evaluator_->add_inplace(result, z2);
        
        // 5. Decrypt and decode
        Plaintext result_plain;
        decryptor_->decrypt(result, result_plain);
        
        vector<double> result_vec;
        encoder_->decode(result_plain, result_vec);
        
        return result_vec;
    }

private:
    pair<double, double> decompose(double num) {
        double base = pow(10.0, floor(log10(abs(num))/2));
        double high = floor(num / base);
        double low = num - high * base;
        return {high, low};
    }

    shared_ptr<SEALContext> context_;
    SecretKey secret_key_;
    PublicKey public_key_;
    RelinKeys relin_keys_;
    unique_ptr<CKKSEncoder> encoder_;
    unique_ptr<Encryptor> encryptor_;
    unique_ptr<Decryptor> decryptor_;
    unique_ptr<Evaluator> evaluator_;
    double scale_;
    size_t slot_count_;
};

int main() {
    try {
        CKKSKaratsubaMultiplier multiplier;
        
        double a = 123.456;
        double b = 789.012;
        
        auto result = multiplier.multiply(a, b);
        
        cout << "Result components: ";
        for (auto val : result) {
            cout << val << " ";
        }
        cout << "\nExpected: " << a * b << endl;
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}