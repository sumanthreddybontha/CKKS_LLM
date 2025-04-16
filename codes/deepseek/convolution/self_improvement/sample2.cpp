#include <iostream>
#include <vector>
#include <algorithm>
#include "seal/seal.h"

using namespace std;
using namespace seal;

vector<double> batch_conv1d(const vector<double>& input, const vector<double>& kernel) {
    // Parameters setup
    const size_t poly_modulus_degree = 8192;
    const vector<int> bit_sizes = {60, 40, 40, 60}; // Optimal for 128-bit security
    
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, bit_sizes));
    
    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    // Determine scaling factor
    double scale = pow(2.0, 40);
    
    // Determine padding size (needs to be <= poly_modulus_degree/2 for CKKS)
    size_t N = input.size();
    size_t M = kernel.size();
    size_t padded_size = 1;
    while (padded_size < N + M - 1) padded_size <<= 1;
    if (padded_size > encoder.slot_count())
        throw logic_error("Input too large for polynomial degree");

    // Prepare input vectors with padding
    vector<double> padded_input(padded_size, 0.0);
    copy(input.begin(), input.end(), padded_input.begin());
    
    vector<double> padded_kernel(padded_size, 0.0);
    copy(kernel.begin(), kernel.end(), padded_kernel.begin());

    // Encode and encrypt input
    Plaintext plain_input;
    encoder.encode(padded_input, scale, plain_input);
    Ciphertext encrypted_input;
    encryptor.encrypt(plain_input, encrypted_input);

    // Encode kernel (no encryption needed for plaintext kernel)
    Plaintext plain_kernel;
    encoder.encode(padded_kernel, scale, plain_kernel);

    // Compute convolution via SIMD operations
    Ciphertext encrypted_result;
    evaluator.multiply_plain(encrypted_input, plain_kernel, encrypted_result);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_result);

    // Sum rotated results for linear convolution
    Ciphertext accum_result = encrypted_result;
    for (size_t i = 1; i < N + M - 1; i++) {
        Ciphertext rotated;
        evaluator.rotate_vector(encrypted_result, i, gal_keys, rotated);
        evaluator.add_inplace(accum_result, rotated);
    }

    // Decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(accum_result, plain_result);
    vector<double> result(padded_size);
    encoder.decode(plain_result, result);

    // Extract valid convolution results
    return vector<double>(result.begin(), result.begin() + (N + M - 1));
}

int main() {
    // Example usage
    vector<double> input = {1.0, 2.0, 3.0};
    vector<double> kernel = {0.5, 0.5};
    
    auto result = batch_conv1d(input, kernel);
    
    // Print final result
    cout << "Batch convolution result: ";
    for (auto val : result) {
        cout << val << " ";
    }
    cout << endl;
    
    return 0;
}