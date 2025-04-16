#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main() {
    // Enhanced parameter setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    
    double scale = pow(2.0, 40);
    SEALContext context(parms);
    //print_parameters(context);
    
    // Key generation with modulus switching
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    // Crypto objects
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    // Input vectors
    vector<double> input1{1.0, 2.0, 3.0, 4.0, 5.0};
    vector<double> input2{0.5, 1.5, 2.5, 3.5, 4.5};
    
    // Encode and encrypt
    Plaintext plain1, plain2;
    encoder.encode(input1, scale, plain1);
    encoder.encode(input2, scale, plain2);
    
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    
    // Modulus switching before operation
    cout << "Before modulus switching - level: " << encrypted1.coeff_modulus_size() - 1 << endl;
    evaluator.mod_switch_to_inplace(encrypted1, context.last_context_data()->parms_id());
    evaluator.mod_switch_to_inplace(encrypted2, context.last_context_data()->parms_id());
    cout << "After modulus switching - level: " << encrypted1.coeff_modulus_size() - 1 << endl;
    
    // Homomorphic addition
    evaluator.add_inplace(encrypted1, encrypted2);
    
    // Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted1, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    
    // Output
    cout << "Result: ";
    for (auto val : result) {
        cout << val << " ";
    }
    cout << endl;
    
    return 0;
}