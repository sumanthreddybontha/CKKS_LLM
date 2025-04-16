#include <iostream>
#include <vector>
#include <seal/seal.h>

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
    
    // Step 2: Create the SEAL context
    SEALContext context(parms);
    
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
    
    // Pad the vectors with zeros to fill all slots
    input1.resize(slot_count);
    input2.resize(slot_count);
    
    // Step 7: Encode and encrypt the data
    double scale = pow(2.0, 40);
    Plaintext plain1, plain2;
    encoder.encode(input1, scale, plain1);
    encoder.encode(input2, scale, plain2);
    
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    
    // Step 8: Perform multiplication
    cout << "Performing multiplication..." << endl;
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted1, encrypted2, encrypted_product);
    
    // Step 9: Relinearize the result to keep ciphertext size manageable
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    
    // Step 10: Rescale the result to maintain scale
    evaluator.rescale_to_next_inplace(encrypted_product);
    
    // Step 11: Decrypt and decode the result
    Plaintext plain_result;
    decryptor.decrypt(encrypted_product, plain_result);
    
    vector<double> result;
    encoder.decode(plain_result, result);
    
    // Step 12: Print the results (only first few elements)
    cout << "Input vector 1: ";
    for (size_t i = 0; i < 4; ++i) {
        cout << input1[i] << ((i < 3) ? ", " : "\n");
    }
    
    cout << "Input vector 2: ";
    for (size_t i = 0; i < 4; ++i) {
        cout << input2[i] << ((i < 3) ? ", " : "\n");
    }
    
    cout << "Result (product): ";
    for (size_t i = 0; i < 4; ++i) {
        cout << result[i] << ((i < 3) ? ", " : "\n");
    }
    
    return 0;
}