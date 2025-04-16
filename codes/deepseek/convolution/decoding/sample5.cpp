#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

class CKKSConvolver {
public:
    CKKSConvolver(size_t poly_degree = 8192) {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(poly_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_degree, {50, 30, 30, 50}));
        
        context_ = make_shared<SEALContext>(parms);
        encoder_ = make_shared<CKKSEncoder>(*context_);
        
        KeyGenerator keygen(*context_);
        secret_key_ = keygen.secret_key();
        keygen.create_public_key(public_key_);
        keygen.create_relin_keys(relin_keys_);
        
        encryptor_ = make_shared<Encryptor>(*context_, public_key_);
        evaluator_ = make_shared<Evaluator>(*context_);
        decryptor_ = make_shared<Decryptor>(*context_, secret_key_);
    }

    vector<double> convolve(const vector<double>& a, const vector<double>& b) {
        size_t slot_count = encoder_->slot_count();
        vector<double> a_padded(a), b_padded(b);
        a_padded.resize(slot_count, 0.0);
        b_padded.resize(slot_count, 0.0);

        Plaintext pt_a, pt_b;
        encoder_->encode(a_padded, pow(2.0, 40), pt_a);
        encoder_->encode(b_padded, pow(2.0, 40), pt_b);

        Ciphertext ct_a, ct_b;
        encryptor_->encrypt(pt_a, ct_a);
        encryptor_->encrypt(pt_b, ct_b);

        Ciphertext ct_result;
        evaluator_->multiply(ct_a, ct_b, ct_result);
        evaluator_->relinearize_inplace(ct_result, relin_keys_);
        evaluator_->rescale_to_next_inplace(ct_result);

        Plaintext pt_result;
        decryptor_->decrypt(ct_result, pt_result);
        vector<double> result;
        encoder_->decode(pt_result, result);
        
        result.resize(a.size() + b.size() - 1);
        return result;
    }

private:
    shared_ptr<SEALContext> context_;
    shared_ptr<CKKSEncoder> encoder_;
    SecretKey secret_key_;
    PublicKey public_key_;
    RelinKeys relin_keys_;
    shared_ptr<Encryptor> encryptor_;
    shared_ptr<Evaluator> evaluator_;
    shared_ptr<Decryptor> decryptor_;
};

int main() {
    cout << "Optimized CKKS Convolution\n";
    
    CKKSConvolver convolver;
    vector<double> input = {1.0, 2.0, 3.0, 4.0};
    vector<double> kernel = {0.5, 0.25, 0.125, 0.0625};
    
    auto result = convolver.convolve(input, kernel);
    
    cout << "Convolution result (first 7): ";
    for (size_t i = 0; i < 7; ++i) {
        cout << result[i] << " ";
    }
    cout << endl;
    
    return 0;
}