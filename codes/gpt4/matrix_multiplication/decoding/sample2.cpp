#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include "seal/seal.h"

using namespace std;
using namespace seal;
using namespace chrono;

// Helper: Print encryption parameters
void print_parameters(const SEALContext &context) {
    auto &context_data = *context.key_context_data();
    cout << "Encryption parameters:" << endl;
    cout << "  Poly modulus degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << "  Coeff moduli size: ";
    for (const auto &mod : context_data.parms().coeff_modulus()) {
        cout << mod.bit_count() << " ";
    }
    cout << endl;
}

// Print matrix (for small ones)
void print_matrix(const vector<vector<double>> &matrix, size_t row_count = 4, size_t col_count = 4) {
    for (size_t i = 0; i < min(row_count, matrix.size()); i++) {
        cout << "[ ";
        for (size_t j = 0; j < min(col_count, matrix[i].size()); j++) {
            cout << matrix[i][j] << " ";
        }
        cout << "]" << endl;
    }
    if (row_count < matrix.size() || col_count < matrix[0].size()) {
        cout << "[ ... ]" << endl;
    }
}

// Generate a random matrix
vector<vector<double>> generate_random_matrix(size_t rows, size_t cols, double min = 0.0, double max = 1.0) {
    vector<vector<double>> matrix(rows, vector<double>(cols));
    random_device rd;
    mt19937 gen(rd());
    uniform_real_distribution<double> dist(min, max);
    for (size_t i = 0; i < rows; i++)
        for (size_t j = 0; j < cols; j++)
            matrix[i][j] = dist(gen);
    return matrix;
}

// Plaintext matrix multiply
vector<vector<double>> plain_matrix_multiply(const vector<vector<double>> &a,
                                             const vector<vector<double>> &b) {
    size_t rows_a = a.size();
    size_t cols_a = a[0].size();
    size_t cols_b = b[0].size();
    vector<vector<double>> result(rows_a, vector<double>(cols_b, 0.0));
    for (size_t i = 0; i < rows_a; i++)
        for (size_t j = 0; j < cols_b; j++)
            for (size_t k = 0; k < cols_a; k++)
                result[i][j] += a[i][k] * b[k][j];
    return result;
}

int main() {
    size_t poly_modulus_degree = 8192;
    vector<int> coeff_modulus = {60, 40, 40, 60};
    int scale_bits = 40;

    // Matrix dims
    size_t rows_a = 2, cols_a = 4, cols_b = 3;

    auto matrix_a = generate_random_matrix(rows_a, cols_a, 0.1, 1.0);
    auto matrix_b = generate_random_matrix(cols_a, cols_b, 0.1, 1.0);

    cout << "Matrix A:" << endl;
    print_matrix(matrix_a);
    cout << "\nMatrix B:" << endl;
    print_matrix(matrix_b);

    auto plain_result = plain_matrix_multiply(matrix_a, matrix_b);
    cout << "\nPlaintext result:" << endl;
    print_matrix(plain_result);

    // === SEAL Setup ===
    EncryptionParameters params(scheme_type::ckks);
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, coeff_modulus));
    SEALContext context(params);

    print_parameters(context);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
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

    double scale = pow(2.0, scale_bits);

    // Flatten matrices
    vector<double> flat_a, flat_b;
    for (size_t i = 0; i < rows_a; i++)
        for (size_t j = 0; j < cols_a; j++)
            flat_a.push_back(matrix_a[i][j]);

    for (size_t j = 0; j < cols_b; j++)
        for (size_t i = 0; i < cols_a; i++)
            flat_b.push_back(matrix_b[i][j]);

    Plaintext plain_a, plain_b;
    encoder.encode(flat_a, scale, plain_a);
    encoder.encode(flat_b, scale, plain_b);

    Ciphertext encrypted_a, encrypted_b;
    encryptor.encrypt(plain_a, encrypted_a);
    encryptor.encrypt(plain_b, encrypted_b);

    Ciphertext result;
    evaluator.multiply(encrypted_a, encrypted_b, result);
    evaluator.relinearize_inplace(result, relin_keys);
    evaluator.rescale_to_next_inplace(result);

    // Decrypt and decode
    Plaintext plain_result_cipher;
    decryptor.decrypt(result, plain_result_cipher);

    vector<double> decoded_result;
    encoder.decode(plain_result_cipher, decoded_result);

    // Reshape back into matrix
    vector<vector<double>> encrypted_matrix_result(rows_a, vector<double>(cols_b));
    for (size_t i = 0; i < rows_a; i++)
        for (size_t j = 0; j < cols_b; j++)
            encrypted_matrix_result[i][j] = decoded_result[i * cols_b + j];

    cout << "\nEncrypted result:" << endl;
    print_matrix(encrypted_matrix_result);

    // Error analysis
    double max_error = 0.0, avg_error = 0.0;
    size_t count = 0;
    for (size_t i = 0; i < rows_a; i++) {
        for (size_t j = 0; j < cols_b; j++) {
            double error = abs(plain_result[i][j] - encrypted_matrix_result[i][j]);
            max_error = max(max_error, error);
            avg_error += error;
            count++;
        }
    }
    avg_error /= count;

    cout << "\nMaximum error: " << max_error << endl;
    cout << "Average error: " << avg_error << endl;

    return 0;
}
