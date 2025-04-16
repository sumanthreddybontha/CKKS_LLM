#include <seal/seal.h>
#include <vector>
#include <iostream>
using namespace seal;
using namespace std;

int main() {
    // Parameter setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 30, 50}));
    
    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    // Core operations
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    Decryptor decryptor(context, secret_key);
    
    // Data preparation
    vector<double> input{1.1, 2.2}, input2{3.3, 4.4};
    Plaintext plain1, plain2;
    encoder.encode(input, pow(2.0, 40), plain1);
    encoder.encode(input2, pow(2.0, 40), plain2);
    
    // Encryption
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    
    // Homomorphic addition
    evaluator.add_inplace(encrypted1, encrypted2);
    
    // Decryption and verification
    Plaintext plain_result;
    decryptor.decrypt(encrypted1, plain_result);
    
    vector<double> result;
    encoder.decode(plain_result, result);
    
    cout << "Result: " << result[0] << ", " << result[1] << endl;
    
    return 0;
}