#include <iostream>
#include <vector>
#include <numeric>
#include <chrono>
#include "seal/seal.h"

using namespace std;
using namespace seal;

void print_matrix(const vector<double> &matrix, size_t rows, size_t cols) {
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; j < cols; j++) {
            cout << matrix[i * cols + j] << "\t";
        }
        cout << endl;
    }
}

int main() {
    // Step 1: Parameter setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    vector<int> modulus_bits = {60, 40, 40, 60};
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, modulus_bits));
    
    SEALContext context(parms);
    // print_parameters(context);
    cout << endl;

    // Step 2: Key generation
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // Step 3: Set up crypto objects
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    // Step 4: Prepare data
    vector<double> input_matrix(10 * 10);
    iota(input_matrix.begin(), input_matrix.end(), 1.0); // Fill with 1.0 to 100.0

    vector<double> kernel = {
        1.0, 0.0, -1.0,
        2.0, 0.0, -2.0,
        1.0, 0.0, -1.0
    };

    cout << "Input matrix (10x10):" << endl;
    print_matrix(input_matrix, 10, 10);
    cout << "\nKernel (3x3):" << endl;
    print_matrix(kernel, 3, 3);

    // Step 5: Encode and encrypt matrix
    vector<double> padded_matrix(slot_count, 0.0);
    copy(input_matrix.begin(), input_matrix.end(), padded_matrix.begin());
    
    double scale = pow(2.0, 40);
    Plaintext plain_matrix;
    encoder.encode(padded_matrix, scale, plain_matrix);
    
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    // Step 6: Encode kernel (as plaintext)
    vector<double> padded_kernel(slot_count, 0.0);
    copy(kernel.begin(), kernel.end(), padded_kernel.begin());
    
    Plaintext plain_kernel;
    encoder.encode(padded_kernel, scale, plain_kernel);

    // Step 7: Perform multiplication - CORRECT APPROACH
    Ciphertext encrypted_result;
    evaluator.multiply_plain(encrypted_matrix, plain_kernel, encrypted_result);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_result);

    // Step 8: Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    
    vector<double> result;
    encoder.decode(plain_result, result);

    vector<double> final_result(result.begin(), result.begin() + 100);
    cout << "\nResult (first 10x10 elements):" << endl;
    print_matrix(final_result, 10, 10);

    return 0;
}