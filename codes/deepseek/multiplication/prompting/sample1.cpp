#include <seal/seal.h>
#include <iostream>
#include <vector>


using namespace std;
using namespace seal;

int main() {
    // Step 1: Set up encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Set the coefficient modulus to achieve 128-bit security
    parms.set_coeff_modulus(CoeffModulus::Create(
        poly_modulus_degree, { 60, 40, 40, 60 }));
    
    // Step 2: Create the SEALContext
    SEALContext context(parms);
    
    // Step 3: Generate keys
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    // Step 4: Create encryptor, evaluator, and decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    // Step 5: Create CKKS encoder
    CKKSEncoder encoder(context);
    
    // Step 6: Set up scale parameter for encoding
    double scale = pow(2.0, 40);
    
    // Step 7: Prepare input data
    vector<double> input1{ 1.5, 2.7, 3.9 };
    vector<double> input2{ 2.0, 3.0, 4.0 };
    
    // Step 8: Encode the inputs
    Plaintext plain1, plain2;
    encoder.encode(input1, scale, plain1);
    encoder.encode(input2, scale, plain2);
    
    // Step 9: Encrypt the encoded inputs
    Ciphertext cipher1, cipher2;
    encryptor.encrypt(plain1, cipher1);
    encryptor.encrypt(plain2, cipher2);
    
    // Step 10: Perform multiplication
    cout << "Performing multiplication..." << endl;
    evaluator.multiply_inplace(cipher1, cipher2);
    
    // Step 11: Relinearize the result to reduce ciphertext size
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    evaluator.relinearize_inplace(cipher1, relin_keys);
    
    // Step 12: Rescale the result to maintain scale consistency
    evaluator.rescale_to_next_inplace(cipher1);
    
    // Step 13: Decrypt the result
    Plaintext plain_result;
    decryptor.decrypt(cipher1, plain_result);
    
    // Step 14: Decode the result
    vector<double> result;
    encoder.decode(plain_result, result);
    
    // Step 15: Display results
    cout << "Input 1: " << input1[0] << ", " << input1[1] << ", " << input1[2] << endl;
    cout << "Input 2: " << input2[0] << ", " << input2[1] << ", " << input2[2] << endl;
    cout << "Result:  " << result[0] << ", " << result[1] << ", " << result[2] << endl;
    
    return 0;
}