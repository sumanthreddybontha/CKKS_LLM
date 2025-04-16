#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set up the encryption parameters
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);
    
    // Set the coefficient moduli to achieve a specific security level and precision
    params.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, 
        { 60, 40, 40, 60 }  // Primes: 60-bit for initial and final, 40-bit for intermediate
    ));
    
    // Step 2: Create the SEALContext
    SEALContext context(params);
    
    // Step 3: Generate keys
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    // Step 4: Create encryptor, evaluator, and decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    // Step 5: Create CKKS encoder
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    
    // Step 6: Prepare input data
    vector<double> input1{ 1.0, 2.0, 3.0, 4.0 };
    vector<double> input2{ 2.0, 3.0, 4.0, 5.0 };
    
    // Print expected plaintext result
    vector<double> expected_result;
    for (size_t i = 0; i < input1.size(); i++) {
        expected_result.push_back(input1[i] * input2[i]);
    }
    cout << "Expected plaintext result: ";
    for (auto val : expected_result) {
        cout << val << " ";
    }
    cout << endl;
    
    // Step 7: Encode the inputs
    double scale = pow(2.0, 40);
    Plaintext plain1, plain2;
    encoder.encode(input1, scale, plain1);
    encoder.encode(input2, scale, plain2);
    
    // Step 8: Encrypt the plaintexts
    Ciphertext cipher1, cipher2;
    encryptor.encrypt(plain1, cipher1);
    encryptor.encrypt(plain2, cipher2);
    
    // Step 9: Perform multiplication
    cout << "Performing homomorphic multiplication..." << endl;
    evaluator.multiply_inplace(cipher1, cipher2);
    
    // Step 10: Relinearize the result to reduce ciphertext size
    evaluator.relinearize_inplace(cipher1, relin_keys);
    
    // Step 11: Rescale the result to maintain precision
    evaluator.rescale_to_next_inplace(cipher1);
    
    // Step 12: Decrypt and decode the result
    Plaintext plain_result;
    decryptor.decrypt(cipher1, plain_result);
    
    vector<double> result;
    encoder.decode(plain_result, result);
    
    // Step 13: Print the result (only the first few values)
    cout << "Homomorphic multiplication result (first " << input1.size() << " values): ";
    for (size_t i = 0; i < input1.size(); i++) {
        cout << result[i] << " ";
    }
    cout << endl;
    
    return 0;
}