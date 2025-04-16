#include <seal/seal.h>
#include <vector>
#include <iostream>
using namespace seal;

class StridedConvolution {
public:
    StridedConvolution(size_t stride = 2) : stride_(stride) {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(8192);
        parms.set_coeff_modulus(CoeffModulus::Create(8192, {40, 30, 30, 40}));
        
        context_ = std::make_shared<SEALContext>(parms);
        keygen_ = std::make_shared<KeyGenerator>(*context_);
        
        // Generate public and secret keys
        keygen_->create_public_key(public_key_);
        secret_key_ = keygen_->secret_key();
        keygen_->create_galois_keys(galois_keys_);
        
        // Initialize the objects
        encryptor_ = std::make_shared<Encryptor>(*context_, public_key_);
        evaluator_ = std::make_shared<Evaluator>(*context_);
        decryptor_ = std::make_shared<Decryptor>(*context_, secret_key_);
        
        encoder_ = std::make_shared<CKKSEncoder>(*context_);
        scale_ = pow(2.0, 30);
    }

    std::vector<double> strided_conv(
        const std::vector<double>& input,
        const std::vector<double>& kernel) {
        
        Plaintext pt_input, pt_kernel;
        encoder_->encode(input, scale_, pt_input);
        encoder_->encode(kernel, scale_, pt_kernel);
        
        Ciphertext ct_input;
        encryptor_->encrypt(pt_input, ct_input);
        
        // Apply strided convolution using rotations
        Ciphertext ct_result;
        evaluator_->multiply_plain(ct_input, pt_kernel, ct_result);
        evaluator_->rescale_to_next_inplace(ct_result);
        
        // Rotate and add for strided output
        Ciphertext rotated;
        evaluator_->rotate_vector(ct_result, stride_, galois_keys_, rotated);
        evaluator_->add_inplace(ct_result, rotated);
        
        Plaintext pt_result;
        decryptor_->decrypt(ct_result, pt_result);
        
        std::vector<double> result;
        encoder_->decode(pt_result, result);
        
        // Downsample according to stride
        std::vector<double> strided_result;
        for (size_t i = 0; i < result.size(); i += stride_) {
            strided_result.push_back(result[i]);
        }
        
        return strided_result;
    }

private:
    std::shared_ptr<SEALContext> context_;
    std::shared_ptr<KeyGenerator> keygen_;
    std::shared_ptr<Encryptor> encryptor_;
    std::shared_ptr<Evaluator> evaluator_;
    std::shared_ptr<Decryptor> decryptor_;
    std::shared_ptr<CKKSEncoder> encoder_;
    PublicKey public_key_;
    SecretKey secret_key_;
    GaloisKeys galois_keys_;
    double scale_;
    size_t stride_;
};

int main() {
    // Example usage
    StridedConvolution conv;
    
    // Sample input and kernel
    std::vector<double> input = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
    std::vector<double> kernel = {0.5, 0.5};
    
    // Perform strided convolution
    std::vector<double> result = conv.strided_conv(input, kernel);
    
    // Print the result
    std::cout << "Strided convolution result: ";
    for (double val : result) {
        std::cout << val << " ";
    }
    std::cout << std::endl;
    
    return 0;
}