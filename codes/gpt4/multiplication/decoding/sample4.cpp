#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

// Helper to print vectors
void print_matrix(const vector<double>& matrix, size_t rows, size_t cols) {
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; j < cols; j++) {
            cout << matrix[i * cols + j] << "\t";
        }
        cout << endl;
    }
}

int main() {
    // Step 1: Set CKKS parameters
    size_t poly_modulus_degree = 8192;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    // Step 2: Create context and key generator
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
keygen.create_relin_keys(relin_keys);

    // Step 3: Create Encryptor, Decryptor, Evaluator, and Encoder
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    // Step 4: Create 10x10 matrix and 3x3 kernel
    const size_t rows = 10, cols = 10;
    const size_t ksize = 3;
    vector<double> matrix(rows * cols);
    vector<double> kernel = {0.0, 1.0, 0.0,
                             1.0, -4.0, 1.0,
                             0.0, 1.0, 0.0}; // Example Laplacian kernel

    // Fill the matrix with sample values
    for (size_t i = 0; i < rows * cols; i++) {
        matrix[i] = static_cast<double>(i + 1);
    }

    // Encode and encrypt matrix and kernel
    Plaintext plain_matrix, plain_kernel;
    encoder.encode(matrix, scale, plain_matrix);
    encoder.encode(kernel, scale, plain_kernel);

    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    // Step 5: Convolution operation
    // Output will be (10 - 3 + 1) x (10 - 3 + 1) = 8x8 = 64 elements
    vector<double> conv_result;

    for (size_t i = 0; i <= rows - ksize; i++) {
        for (size_t j = 0; j <= cols - ksize; j++) {
            vector<double> window;
            for (size_t ki = 0; ki < ksize; ki++) {
                for (size_t kj = 0; kj < ksize; kj++) {
                    window.push_back(matrix[(i + ki) * cols + (j + kj)]);
                }
            }

            // Encode and encrypt window
            Plaintext plain_window;
            encoder.encode(window, scale, plain_window);
            Ciphertext encrypted_window;
            encryptor.encrypt(plain_window, encrypted_window);

            // Encode kernel (can be reused, already done above)
            // Multiply element-wise
            Ciphertext multiplied;
            evaluator.multiply_plain(encrypted_window, plain_kernel, multiplied);
            evaluator.relinearize_inplace(multiplied, relin_keys);
            evaluator.rescale_to_next_inplace(multiplied);

            // Decrypt and decode
            Plaintext plain_result;
            decryptor.decrypt(multiplied, plain_result);
            vector<double> decoded;
            encoder.decode(plain_result, decoded);

            // Sum all elements in the decoded result (dot product)
            double sum = 0.0;
            for (double val : decoded) sum += val;
            conv_result.push_back(sum);
        }
    }

    // Step 6: Output the final result (8x8 convolution output)
    cout << "Convolution Result (8x8):\n";
    print_matrix(conv_result, rows - ksize + 1, cols - ksize + 1);

    return 0;
}