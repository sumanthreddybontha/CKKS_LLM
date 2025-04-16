#include <iostream>
#include <vector>
#include <memory>
#include <seal/seal.h>

using namespace seal;
using namespace std;

class CKKSConvolution {
public:
    CKKSConvolution() {
        initialize();
    }

    void initialize() {
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(
            poly_modulus_degree, {40, 30, 30, 40}));

        context_ = make_shared<SEALContext>(parms);
        keygen_ = make_shared<KeyGenerator>(*context_);
        secret_key_ = make_shared<SecretKey>(keygen_->secret_key());
        keygen_->create_public_key(public_key_);
        keygen_->create_relin_keys(relin_keys_);
        keygen_->create_galois_keys(galois_keys_);

        encryptor_ = make_shared<Encryptor>(*context_, public_key_);
        evaluator_ = make_shared<Evaluator>(*context_);
        decryptor_ = make_shared<Decryptor>(*context_, *secret_key_);

        scale_ = pow(2.0, 30);
        encoder_ = make_shared<CKKSEncoder>(*context_);
    }

    vector<double> convolve(const vector<double>& input, const vector<double>& kernel) {
        // Encode and encrypt input vector
        Plaintext plain_input;
        encoder_->encode(input, scale_, plain_input);
        Ciphertext encrypted_input;
        encryptor_->encrypt(plain_input, encrypted_input);

        // Encode kernel vector as plaintext
        Plaintext plain_kernel;
        encoder_->encode(kernel, scale_, plain_kernel);

        // Perform convolution (polynomial multiplication)
        Ciphertext encrypted_result;
        evaluator_->multiply_plain(encrypted_input, plain_kernel, encrypted_result);
        evaluator_->rescale_to_next_inplace(encrypted_result);

        // Decrypt and decode result
        Plaintext plain_result;
        decryptor_->decrypt(encrypted_result, plain_result);
        
        vector<double> result;
        encoder_->decode(plain_result, result);

        // Return only the valid part of the result (first N elements)
        result.resize(input.size());
        return result;
    }

private:
    shared_ptr<SEALContext> context_;
    shared_ptr<KeyGenerator> keygen_;
    shared_ptr<SecretKey> secret_key_;
    PublicKey public_key_;
    RelinKeys relin_keys_;
    GaloisKeys galois_keys_;

    shared_ptr<Encryptor> encryptor_;
    shared_ptr<Evaluator> evaluator_;
    shared_ptr<Decryptor> decryptor_;
    shared_ptr<CKKSEncoder> encoder_;
    double scale_;
};

int main() {
    try {
        // Example usage
        CKKSConvolution conv;

        // Input vector (length must be <= N/2 where N is poly modulus degree)
        vector<double> input = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
        vector<double> kernel = {0.5, 0.25, 0.125, 0.0625};

        cout << "Performing convolution..." << endl;
        auto result = conv.convolve(input, kernel);

        cout << "Done. First few result values:" << endl;
        for (size_t i = 0; i < min((size_t)5, result.size()); i++) {
            cout << result[i] << " ";
        }
        cout << endl;

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }

    return 0;
}