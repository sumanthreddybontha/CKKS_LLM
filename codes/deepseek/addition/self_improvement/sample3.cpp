#include <seal/seal.h>
#include <vector>
#include <iostream>
using namespace seal;
using namespace std;

int main() {
    // Extended modulus chain
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    
    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    Decryptor decryptor(context, secret_key);
    
    // Data preparation
    vector<double> input{1.1, 2.2}, input2{3.3, 4.4};
    Plaintext plain1, plain2;
    encoder.encode(input, pow(2.0, 40), plain1);
    encoder.encode(input2, pow(2.0, 40), plain2);
    
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    
    // Modulus switching demonstration
    auto print_level = [](const Ciphertext& c, const string& msg) {
        cout << msg << c.coeff_modulus_size()-1 << endl;
    };
    
    print_level(encrypted1, "Initial level: ");
    
    evaluator.mod_switch_to_next_inplace(encrypted1);
    evaluator.mod_switch_to_next_inplace(encrypted2);
    print_level(encrypted1, "After first switch: ");
    
    evaluator.add_inplace(encrypted1, encrypted2);
    print_level(encrypted1, "After addition: ");
    
    // Final decryption
    Plaintext plain_result;
    decryptor.decrypt(encrypted1, plain_result);
    
    vector<double> result;
    encoder.decode(plain_result, result);
    
    cout << "Result: " << result[0] << ", " << result[1] << endl;
    
    return 0;
}