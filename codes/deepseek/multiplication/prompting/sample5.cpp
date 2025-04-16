#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set up the encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    
    // The poly_modulus_degree should be a power of two (e.g., 8192)
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Set the coefficient modulus to achieve a certain security level and precision
    // This is a 60-bit + 40-bit + 60-bit configuration
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 60}));
    
    // Step 2: Create the SEALContext
    // This validates the parameters for correctness
    SEALContext context(parms);
    
    // Step 3: Generate encryption keys
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    // Step 4: Create encryptor, evaluator, and decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    // Step 5: Create CKKS encoder
    // The scale is set to pow(2.0, 40) to match the 40-bit coefficient modulus
    double scale = pow(2.0, 40);
    CKKSEncoder encoder(context);
    
    // Step 6: Prepare input data
    vector<double> input1{0.5, 1.0, 2.0, 3.0};
    vector<double> input2{2.0, 3.0, 4.0, 5.0};
    
    // Print the expected result
    cout << "Expected multiplication result: ";
    for (size_t i = 0; i < input1.size(); i++) {
        cout << input1[i] * input2[i] << ((i < input1.size() - 1) ? ", " : "\n");
    }
    
    // Step 7: Encode the inputs into plaintext polynomials
    Plaintext plain1, plain2;
    encoder.encode(input1, scale, plain1);
    encoder.encode(input2, scale, plain2);
    
    // Step 8: Encrypt the plaintexts
    Ciphertext cipher1, cipher2;
    encryptor.encrypt(plain1, cipher1);
    encryptor.encrypt(plain2, cipher2);
    
    // Step 9: Perform homomorphic multiplication
    Ciphertext encrypted_result;
    evaluator.multiply(cipher1, cipher2, encrypted_result);
    
    // Step 10: Relinearize the result to reduce ciphertext size
    // First we need to generate relinearization keys
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    
    // Step 11: Rescale the result to maintain the scale
    evaluator.rescale_to_next_inplace(encrypted_result);
    
    // Step 12: Decrypt and decode the result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    
    vector<double> result;
    encoder.decode(plain_result, result);
    
    // Step 13: Print the result (only the first few slots)
    cout << "Computed multiplication result: ";
    for (size_t i = 0; i < input1.size(); i++) {
        cout << result[i] << ((i < input1.size() - 1) ? ", " : "\n");
    }
    
    return 0;
}