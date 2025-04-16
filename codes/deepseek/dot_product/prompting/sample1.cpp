#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void print_parameters(const shared_ptr<SEALContext> &context) {
    auto &context_data = *context->first_context_data();
    cout << "Parameter set:" << endl;
    cout << " scheme: CKKS" << endl;
    cout << " poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << " coeff_modulus size: ";
    cout << context_data.parms().coeff_modulus().size() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    size_t coeff_mod_count = coeff_modulus.size();
    for (size_t i = 0; i < coeff_mod_count - 1; i++) {
        cout << coeff_modulus[i].bit_count() << " + ";
    }
    cout << coeff_modulus.back().bit_count();
    cout << ") bits" << endl;
}

void example_ckks_dot_product() {
    // Step 1: Setup CKKS parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Recommended coeff_modulus for poly_modulus_degree = 8192
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50, 30, 30, 50 }));
    
    // Step 2: Create SEAL context
    SEALContext context(parms);
    print_parameters(make_shared<SEALContext>(context));
    
    // Step 3: Key generation
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    // Generate Galois keys for rotation operations
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    
    // Step 4: Set up encoder and encryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    
    // Step 5: Prepare the vectors for dot product
    vector<double> vec1{ 1.0, 2.0, 3.0, 4.0 };
    vector<double> vec2{ 2.0, 3.0, 4.0, 5.0 };
    
    // Pad vectors with zeros to fill all slots
    vec1.resize(slot_count, 0.0);
    vec2.resize(slot_count, 0.0);
    
    // Calculate expected result (plaintext dot product)
    double expected_result = inner_product(vec1.begin(), vec1.end(), vec2.begin(), 0.0);
    cout << "Expected plaintext result: " << expected_result << endl;
    
    // Step 6: Encode and encrypt the vectors
    double scale = pow(2.0, 40);
    
    Plaintext plain_vec1, plain_vec2;
    encoder.encode(vec1, scale, plain_vec1);
    encoder.encode(vec2, scale, plain_vec2);
    
    Ciphertext encrypted_vec1, encrypted_vec2;
    encryptor.encrypt(plain_vec1, encrypted_vec1);
    encryptor.encrypt(plain_vec2, encrypted_vec2);
    
    // Step 7: Compute dot product in encrypted form
    // Multiply element-wise
    Ciphertext encrypted_product;
    evaluator.multiply(encrypted_vec1, encrypted_vec2, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);
    
    // Sum all elements (rotate and add)
    Ciphertext encrypted_result = encrypted_product;
    for (size_t i = 1; i < slot_count; i *= 2) {
        Ciphertext rotated;
        evaluator.rotate_vector(encrypted_result, i, galois_keys, rotated);
        evaluator.add_inplace(encrypted_result, rotated);
    }
    
    // Step 8: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    
    vector<double> result;
    encoder.decode(plain_result, result);
    
    cout << "Computed result: " << result[0] << endl;
    cout << "Absolute error: " << abs(result[0] - expected_result) << endl;
}

int main() {
    cout << "CKKS Dot Product Example using Microsoft SEAL" << endl;
    try {
        example_ckks_dot_product();
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }
    return 0;
}