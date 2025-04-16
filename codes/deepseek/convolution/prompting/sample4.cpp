#include <seal/seal.h>
#include <vector>
#include <iostream>
using namespace seal;
using namespace std;

class DepthwiseConvolution {
public:
    DepthwiseConvolution() {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(8192);
        parms.set_coeff_modulus(CoeffModulus::Create(8192, {40, 30, 30, 40}));
        
        context_ = std::make_shared<SEALContext>(parms);
        keygen_ = std::make_shared<KeyGenerator>(*context_);
        
        // Generate necessary keys
        keygen_->create_public_key(public_key_);
        secret_key_ = keygen_->secret_key();
        keygen_->create_relin_keys(relin_keys_);
        
        // Initialize all required SEAL components
        encoder_ = std::make_shared<CKKSEncoder>(*context_);
        evaluator_ = std::make_shared<Evaluator>(*context_);
        encryptor_ = std::make_shared<Encryptor>(*context_, public_key_);
        decryptor_ = std::make_shared<Decryptor>(*context_, secret_key_);
        
        scale_ = pow(2.0, 30);
    }

    std::vector<double> depthwise_conv(
        const std::vector<double>& input,
        const std::vector<double>& depth_kernel) {
        
        Plaintext pt_input, pt_kernel;
        encoder_->encode(input, scale_, pt_input);
        encoder_->encode(depth_kernel, scale_, pt_kernel);
        
        Ciphertext ct_input;
        encryptor_->encrypt(pt_input, ct_input);
        
        evaluator_->multiply_plain_inplace(ct_input, pt_kernel);
        evaluator_->rescale_to_next_inplace(ct_input);
        
        Plaintext pt_result;
        decryptor_->decrypt(ct_input, pt_result);
        
        std::vector<double> result;
        encoder_->decode(pt_result, result);
        result.resize(input.size());
        
        return result;
    }

private:
    std::shared_ptr<SEALContext> context_;
    std::shared_ptr<KeyGenerator> keygen_;
    PublicKey public_key_;
    SecretKey secret_key_;
    RelinKeys relin_keys_;
    std::shared_ptr<CKKSEncoder> encoder_;
    std::shared_ptr<Evaluator> evaluator_;
    std::shared_ptr<Encryptor> encryptor_;
    std::shared_ptr<Decryptor> decryptor_;
    double scale_;
};

int main() {
    // Example usage
    DepthwiseConvolution conv;
    
    vector<double> input = {1.0, 2.0, 3.0, 4.0};
    vector<double> kernel = {0.5, 0.5, 0.5, 0.5};
    
    auto result = conv.depthwise_conv(input, kernel);
    
    cout << "Depthwise convolution result:" << endl;
    for (auto val : result) {
        cout << val << " ";
    }
    cout << endl;
    
    return 0;
}