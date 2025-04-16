#include <seal/seal.h>
#include <vector>
#include <iostream>
using namespace seal;
using namespace std;

class BatchedConvolution {
public:
    BatchedConvolution() {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(16384);
        parms.set_coeff_modulus(CoeffModulus::Create(16384, {50, 40, 40, 50}));
        
        context_ = std::make_shared<SEALContext>(parms);
        keygen_ = std::make_shared<KeyGenerator>(*context_);
        
        // Generate public and secret keys
        keygen_->create_public_key(public_key_);
        secret_key_ = keygen_->secret_key();
        keygen_->create_galois_keys(galois_keys_);
        
        encoder_ = std::make_shared<CKKSEncoder>(*context_);
        evaluator_ = std::make_shared<Evaluator>(*context_);
        encryptor_ = std::make_shared<Encryptor>(*context_, public_key_);
        decryptor_ = std::make_shared<Decryptor>(*context_, secret_key_);
        
        scale_ = pow(2.0, 40);
    }

    std::vector<std::vector<double>> batch_convolve(
        const std::vector<double>& input,
        const std::vector<std::vector<double>>& kernels) {
        
        // Encrypt the input
        Plaintext pt_input;
        encoder_->encode(input, scale_, pt_input);
        Ciphertext ct_input;
        encryptor_->encrypt(pt_input, ct_input);
        
        std::vector<Plaintext> pt_kernels;
        for (const auto& kernel : kernels) {
            Plaintext pt;
            encoder_->encode(kernel, scale_, pt);
            pt_kernels.push_back(pt);
        }
        
        std::vector<std::vector<double>> results;
        for (const auto& pt_kernel : pt_kernels) {
            Ciphertext ct_result;
            evaluator_->multiply_plain(ct_input, pt_kernel, ct_result);
            evaluator_->rescale_to_next_inplace(ct_result);
            
            Plaintext pt_result;
            decryptor_->decrypt(ct_result, pt_result);
            
            std::vector<double> result;
            encoder_->decode(pt_result, result);
            result.resize(input.size());
            results.push_back(result);
        }
        
        return results;
    }

private:
    std::shared_ptr<SEALContext> context_;
    std::shared_ptr<KeyGenerator> keygen_;
    PublicKey public_key_;
    SecretKey secret_key_;
    GaloisKeys galois_keys_;
    std::shared_ptr<CKKSEncoder> encoder_;
    std::shared_ptr<Evaluator> evaluator_;
    std::shared_ptr<Encryptor> encryptor_;
    std::shared_ptr<Decryptor> decryptor_;
    double scale_;
};

int main() {
    // Example usage
    BatchedConvolution conv;
    
    vector<double> input = {1.0, 2.0, 3.0, 4.0};
    vector<vector<double>> kernels = {
        {0.5, 0.5, 0.5, 0.5},
        {1.0, -1.0, 1.0, -1.0}
    };
    
    auto results = conv.batch_convolve(input, kernels);
    
    cout << "Convolution results:" << endl;
    for (size_t i = 0; i < results.size(); i++) {
        cout << "Kernel " << i << ": ";
        for (auto val : results[i]) {
            cout << val << " ";
        }
        cout << endl;
    }
    
    return 0;
}