#include <seal/seal.h>
#include <vector>  // Added missing include
#include <iostream> // Needed for pow()

using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 60}));
    
    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    std::vector<double> input1{1.1, 2.2}, input2{3.3, 4.4}; // Fixed: added std::
    Plaintext plain1, plain2;
    encoder.encode(input1, pow(2.0, 40), plain1);
    encoder.encode(input2, pow(2.0, 40), plain2);
    
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    
    evaluator.add_inplace(encrypted1, encrypted2);
    
    Plaintext plain_result;
    decryptor.decrypt(encrypted1, plain_result);
    std::vector<double> result; // Fixed: added std::
    encoder.decode(plain_result, result);
    
    return 0;
}