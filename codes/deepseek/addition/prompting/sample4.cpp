#include <seal/seal.h>
#include <vector>
#include <omp.h>

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {50, 30, 50}));
    
    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    
    // Parallel-safe initialization
    constexpr size_t vec_size = 10000;
    std::vector<double> input1(vec_size), input2(vec_size);
    
    #pragma omp parallel for
    for (size_t i = 0; i < vec_size; i++) {
        input1[i] = i * 1.1;
        input2[i] = i * 2.2;
    }
    
    // Serial crypto section
    CKKSEncoder encoder(context);
    Plaintext plain1, plain2;
    encoder.encode(input1, pow(2.0, 40), plain1);
    encoder.encode(input2, pow(2.0, 40), plain2);
    
    PublicKey public_key;
    keygen.create_public_key(public_key);
    Encryptor encryptor(context, public_key);
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    
    Evaluator evaluator(context);
    evaluator.add_inplace(encrypted1, encrypted2);
    
    return 0;
}