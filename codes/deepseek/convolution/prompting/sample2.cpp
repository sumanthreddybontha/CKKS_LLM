#include <seal/seal.h>
#include <vector>
#include <iostream>
using namespace seal;

class LinearConvolution {
public:
    LinearConvolution() {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(8192);
        parms.set_coeff_modulus(CoeffModulus::Create(8192, {40, 30, 30, 40}));
        
        context_ = std::make_shared<SEALContext>(parms);
        keygen_ = std::make_shared<KeyGenerator>(*context_);
        keygen_->create_public_key(public_key_);
        encryptor_ = std::make_shared<Encryptor>(*context_, public_key_);
        evaluator_ = std::make_shared<Evaluator>(*context_);
        decryptor_ = std::make_shared<Decryptor>(*context_, keygen_->secret_key());
        encoder_ = std::make_shared<CKKSEncoder>(*context_);
        scale_ = pow(2.0, 30);
    }

    std::vector<double> convolve(const std::vector<double>& input, 
                               const std::vector<double>& kernel) {
        // Pad vectors for linear convolution
        size_t padded_size = input.size() + kernel.size() - 1;
        std::vector<double> padded_input(input);
        std::vector<double> padded_kernel(kernel);
        padded_input.resize(padded_size, 0.0);
        padded_kernel.resize(padded_size, 0.0);

        Plaintext pt_input, pt_kernel;
        encoder_->encode(padded_input, scale_, pt_input);
        encoder_->encode(padded_kernel, scale_, pt_kernel);
        
        Ciphertext ct_input;
        encryptor_->encrypt(pt_input, ct_input);
        
        evaluator_->multiply_plain_inplace(ct_input, pt_kernel);
        evaluator_->rescale_to_next_inplace(ct_input);
        
        Plaintext pt_result;
        decryptor_->decrypt(ct_input, pt_result);
        
        std::vector<double> result;
        encoder_->decode(pt_result, result);
        result.resize(input.size() + kernel.size() - 1);
        
        return result;
    }

private:
    std::shared_ptr<SEALContext> context_;
    std::shared_ptr<KeyGenerator> keygen_;
    PublicKey public_key_;
    std::shared_ptr<Encryptor> encryptor_;
    std::shared_ptr<Evaluator> evaluator_;
    std::shared_ptr<Decryptor> decryptor_;
    std::shared_ptr<CKKSEncoder> encoder_;
    double scale_;
};

int main() {
    // Example usage
    LinearConvolution conv;
    
    std::vector<double> input = {1.0, 2.0, 3.0, 4.0};
    std::vector<double> kernel = {0.5, 1.0, 0.5};
    
    auto result = conv.convolve(input, kernel);
    
    std::cout << "Convolution result: ";
    for (auto val : result) {
        std::cout << val << " ";
    }
    std::cout << std::endl;
    
    return 0;
}