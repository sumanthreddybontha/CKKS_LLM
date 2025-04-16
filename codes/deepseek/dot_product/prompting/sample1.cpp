#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void print_example_banner(string title);

int main() {
    print_example_banner("CKKS Dot Product: Basic Implementation");

    // Step 1: Set up encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    
    // Step 2: Create SEALContext
    auto context = SEALContext::Create(parms);
    print_parameters(context);
    
    // Step 3: Generate keys
    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();
    
    // Step 4: Create encryptor, evaluator, decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    // Step 5: Create CKKS encoder
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    
    // Step 6: Prepare input vectors
    vector<double> vec1{ 1.0, 2.0, 3.0, 4.0 };
    vector<double> vec2{ 2.0, 3.0, 4.0, 5.0 };
    
    // Pad vectors with zeros if needed
    vec1.resize(slot_count, 0.0);
    vec2.resize(slot_count, 0.0);
    
    // Step 7: Encode and encrypt vectors
    Plaintext plain_vec1, plain_vec2;
    encoder.encode(vec1, pow(2.0, 40), plain_vec1);
    encoder.encode(vec2, pow(2.0, 40), plain_vec2);
    
    Ciphertext encrypted_vec1, encrypted_vec2;
    encryptor.encrypt(plain_vec1, encrypted_vec1);
    encryptor.encrypt(plain_vec2, encrypted_vec2);
    
    // Step 8: Compute dot product homomorphically
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted_vec1, encrypted_vec2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);
    
    Ciphertext encrypted_result;
    evaluator.add_many(vector<Ciphertext>{encrypted_product}, encrypted_result);
    
    // Step 9: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    
    vector<double> result;
    encoder.decode(plain_result, result);
    
    cout << "Dot product: " << result[0] << endl;
    cout << "Expected result: " << 1.0*2.0 + 2.0*3.0 + 3.0*4.0 + 4.0*5.0 << endl;
    
    return 0;
}

void print_example_banner(string title) {
    cout << endl;
    cout << "====================================================================" << endl;
    cout << title << endl;
    cout << "====================================================================" << endl;
    cout << endl;
}