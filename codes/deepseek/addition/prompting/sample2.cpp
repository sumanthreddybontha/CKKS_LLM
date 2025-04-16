#include <seal/seal.h>
#include <vector>  // Added missing include
#include <iostream> // Needed for pow() and cout

using namespace seal;
using namespace std; // Added to simplify vector usage

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {50, 30, 50}));
    
    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    vector<double> input1(slot_count, 0.0), input2(slot_count, 0.0); // Fixed initialization
    
    // Batch encode 4 vectors interleaved
    for (size_t i = 0; i < 4; i++) {
        input1[i*4] = 1.1*(i+1); 
        input2[i*4] = 2.2*(i+1);
    }
    
    Plaintext plain1, plain2;
    encoder.encode(input1, pow(2.0, 40), plain1);
    encoder.encode(input2, pow(2.0, 40), plain2);
    
    Ciphertext encrypted1, encrypted2;
    Encryptor encryptor(context, public_key);
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    
    Evaluator evaluator(context);
    evaluator.add_inplace(encrypted1, encrypted2);
    
    vector<double> result;
    Plaintext plain_result;
    Decryptor decryptor(context, secret_key);
    decryptor.decrypt(encrypted1, plain_result);
    encoder.decode(plain_result, result);
    
    cout << "First result: " << result[0] << endl;
    return 0;
}