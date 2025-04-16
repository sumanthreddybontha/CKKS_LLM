#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main() {
    // Setup parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 30, 30, 50}));
    
    double scale = pow(2.0, 40);
    SEALContext context(parms);
    
    // Key generation
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    // Setup crypto objects
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    // Batch encoding setup
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    
    // Prepare multiple vectors
    vector<double> input1(slot_count, 0.0), input2(slot_count, 0.0);
    for (size_t i = 0; i < 5; i++) {
        input1[i] = 1.1 * (i+1);
        input2[i] = 2.2 * (i+1);
    }
    
    // Encode and encrypt
    Plaintext plain1, plain2;
    encoder.encode(input1, scale, plain1);
    encoder.encode(input2, scale, plain2);
    
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    
    // Homomorphic addition
    evaluator.add_inplace(encrypted1, encrypted2);
    
    // Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted1, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    
    // Print first 5 elements
    cout << "Result (first 5 elements): ";
    for (size_t i = 0; i < 5; i++) {
        cout << result[i] << " ";
    }
    cout << endl;
    
    return 0;
}