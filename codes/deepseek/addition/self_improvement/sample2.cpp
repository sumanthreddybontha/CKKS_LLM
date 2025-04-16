#include <seal/seal.h>
#include <vector>
#include <iostream>
using namespace seal;
using namespace std;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 30, 50}));
    
    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    Decryptor decryptor(context, secret_key);
    
    // Full slot utilization
    size_t slot_count = encoder.slot_count();
    vector<double> input(slot_count), input2(slot_count);
    
    // Fill all slots with patterned data
    for (size_t i = 0; i < slot_count; i++) {
        input[i] = 1.1 * i;
        input2[i] = 2.2 * i;
    }
    
    Plaintext plain1, plain2;
    encoder.encode(input, pow(2.0, 40), plain1);
    encoder.encode(input2, pow(2.0, 40), plain2);
    
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    
    evaluator.add_inplace(encrypted1, encrypted2);
    
    // Selective decoding
    vector<double> result;
    Plaintext plain_result;
    decryptor.decrypt(encrypted1, plain_result);
    encoder.decode(plain_result, result);
    
    cout << "First element: " << result[0] 
         << "\nMiddle element: " << result[slot_count/2]
         << "\nLast element: " << result.back() << endl;
    
    return 0;
}