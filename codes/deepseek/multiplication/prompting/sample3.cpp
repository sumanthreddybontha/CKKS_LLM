#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

int main() {
    // Step 1: Set up the CKKS encryption scheme parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Set the coefficient moduli to achieve ~128-bit security
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, { 60, 40, 40, 60 }));
    
    // Step 2: Create the SEAL context
    SEALContext context(parms);
    
    // Step 3: Generate encryption keys
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
    
    // Step 6: Set the scale for encoding/decoding
    double scale = pow(2.0, 40);
    
    // Step 7: Prepare input data
    vector<double> input1 = { 3.141, 2.718, 1.618 };
    vector<double> input2 = { 1.414, 1.732, 2.236 };
    
    // Step 8: Encode the inputs into plaintext polynomials
    Plaintext plain1, plain2;
    encoder.encode(input1, scale, plain1);
    encoder.encode(input2, scale, plain2);
    
    // Step 9: Encrypt the plaintexts
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    
    // Step 10: Perform homomorphic multiplication
    cout << "Performing multiplication..." << endl;
    evaluator.multiply_inplace(encrypted1, encrypted2);
    
    // Step 11: Relinearize the result to reduce ciphertext size
    evaluator.relinearize_inplace(encrypted1, relin_keys);
    
    // Step 12: Rescale the result to maintain the scale
    evaluator.rescale_to_next_inplace(encrypted1);
    
    // Step 13: Decrypt the result
    Plaintext plain_result;
    decryptor.decrypt(encrypted1, plain_result);
    
    // Step 14: Decode the result
    vector<double> result;
    encoder.decode(plain_result, result);
    
    // Step 15: Print the results
    cout << "Input 1: " << input1[0] << ", " << input1[1] << ", " << input1[2] << endl;
    cout << "Input 2: " << input2[0] << ", " << input2[1] << ", " << input2[2] << endl;
    cout << "Result:  " << result[0] << ", " << result[1] << ", " << result[2] << endl;
    
    // Verify the results
    cout << "Expected results:" << endl;
    cout << input1[0] * input2[0] << ", " 
         << input1[1] * input2[1] << ", " 
         << input1[2] * input2[2] << endl;
    
    return 0;
}