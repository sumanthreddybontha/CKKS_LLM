#include <iostream>
#include <vector>
#include <complex>
#include <chrono>
#include <fstream>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// Print a matrix (truncated to 4x4 by default)
void print_matrix(const vector<vector<double>> &matrix, size_t row_count = 4, size_t col_count = 4) {
    for (size_t i = 0; i < min(row_count, matrix.size()); i++) {
        cout << "[";
        for (size_t j = 0; j < min(col_count, matrix[i].size()); j++) {
            cout << matrix[i][j];
            if (j != min(col_count, matrix[i].size()) - 1) cout << ", ";
        }
        cout << "]\n";
    }
}

// Generate a random matrix of given size
vector<vector<double>> random_matrix(size_t rows, size_t cols) {
    vector<vector<double>> matrix(rows, vector<double>(cols));
    for (size_t i = 0; i < rows; i++)
        for (size_t j = 0; j < cols; j++)
            matrix[i][j] = static_cast<double>(rand()) / RAND_MAX;
    return matrix;
}

// Plaintext matrix multiplication
vector<vector<double>> plain_matrix_mult(const vector<vector<double>> &A, const vector<vector<double>> &B) {
    size_t rows_A = A.size(), cols_A = A[0].size(), cols_B = B[0].size();
    vector<vector<double>> result(rows_A, vector<double>(cols_B, 0.0));
    for (size_t i = 0; i < rows_A; i++)
        for (size_t j = 0; j < cols_B; j++)
            for (size_t k = 0; k < cols_A; k++)
                result[i][j] += A[i][k] * B[k][j];
    return result;
}

// Encode matrix (row-wise)
vector<Plaintext> encode_matrix(const vector<vector<double>> &matrix, CKKSEncoder &encoder, double scale) {
    size_t rows = matrix.size(), cols = matrix[0].size();
    vector<Plaintext> encoded(rows);
    for (size_t i = 0; i < rows; i++) {
        vector<double> row_data(cols);
        for (size_t j = 0; j < cols; j++) row_data[j] = matrix[i][j];
        encoder.encode(row_data, scale, encoded[i]);
    }
    return encoded;
}

// Encrypt encoded matrix
vector<Ciphertext> encrypt_matrix(const vector<Plaintext> &encoded, Encryptor &encryptor) {
    vector<Ciphertext> encrypted(encoded.size());
    for (size_t i = 0; i < encoded.size(); i++)
        encryptor.encrypt(encoded[i], encrypted[i]);
    return encrypted;
}

// Homomorphic matrix multiplication: Encrypted A × Plain B
vector<Ciphertext> encrypted_matrix_mult(
    const vector<Ciphertext> &encrypted_A,
    const vector<vector<double>> &plain_B,
    CKKSEncoder &encoder,
    Evaluator &evaluator,
    RelinKeys &relin_keys,
    GaloisKeys &galois_keys,
    double scale) {

    size_t rows_A = encrypted_A.size();
    size_t cols_B = plain_B[0].size();
    size_t inner_dim = plain_B.size();

    // Encode columns of B
    vector<Plaintext> encoded_B(cols_B);
    for (size_t j = 0; j < cols_B; j++) {
        vector<double> col_data(inner_dim);
        for (size_t k = 0; k < inner_dim; k++) col_data[k] = plain_B[k][j];
        encoder.encode(col_data, scale, encoded_B[j]);
    }

    // Multiply and rotate-sum to compute dot product
    vector<Ciphertext> result(rows_A);
    for (size_t i = 0; i < rows_A; i++) {
        Ciphertext temp;
        evaluator.multiply_plain(encrypted_A[i], encoded_B[0], temp);
        evaluator.relinearize_inplace(temp, relin_keys);
        evaluator.rescale_to_next_inplace(temp);

        for (size_t j = 1; j < cols_B; j++) {
            Ciphertext temp2;
            evaluator.multiply_plain(encrypted_A[i], encoded_B[j], temp2);
            evaluator.relinearize_inplace(temp2, relin_keys);
            evaluator.rescale_to_next_inplace(temp2);

            evaluator.rotate_vector_inplace(temp2, -static_cast<int>(j), galois_keys);
            evaluator.add_inplace(temp, temp2);
        }

        result[i] = temp;
    }

    return result;
}

// Decrypt and decode result
vector<vector<double>> decrypt_matrix(
    const vector<Ciphertext> &encrypted_matrix,
    Decryptor &decryptor,
    CKKSEncoder &encoder,
    size_t row_size) {

    vector<vector<double>> result(encrypted_matrix.size(), vector<double>(row_size));
    for (size_t i = 0; i < encrypted_matrix.size(); i++) {
        Plaintext plain;
        decryptor.decrypt(encrypted_matrix[i], plain);
        vector<double> decoded;
        encoder.decode(plain, decoded);
        for (size_t j = 0; j < row_size; j++)
            result[i][j] = decoded[j];
    }
    return result;
}

int main() {
    // CKKS setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    CKKSEncoder encoder(context);
    cout << "\nCKKS Parameters:\n";
    cout << " - poly_modulus_degree: " << poly_modulus_degree << "\n";
    cout << " - coeff_modulus sizes: ";
    for (const auto &q : parms.coeff_modulus()) cout << q.bit_count() << " ";
    cout << "bits\n - slots: " << encoder.slot_count() << "\n\n";

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Generate random matrices
    size_t rows_A = 4, cols_A = 4, cols_B = 4;
    auto A = random_matrix(rows_A, cols_A);
    auto B = random_matrix(cols_A, cols_B);

    cout << "Matrix A:\n"; print_matrix(A);
    cout << "\nMatrix B:\n"; print_matrix(B);

    // Plaintext multiplication
    auto t1 = chrono::high_resolution_clock::now();
    auto plain_result = plain_matrix_mult(A, B);
    auto t2 = chrono::high_resolution_clock::now();
    cout << "\nPlaintext Result:\n"; print_matrix(plain_result);
    cout << "Plaintext time: " << chrono::duration_cast<chrono::microseconds>(t2 - t1).count() << " us\n\n";

    // Encrypt A
    auto t_enc_start = chrono::high_resolution_clock::now();
    auto encoded_A = encode_matrix(A, encoder, scale);
    auto encrypted_A = encrypt_matrix(encoded_A, encryptor);
    auto t_enc_end = chrono::high_resolution_clock::now();
    cout << "Encryption time: " << chrono::duration_cast<chrono::microseconds>(t_enc_end - t_enc_start).count() << " us\n";

    // Homomorphic matrix multiplication
    auto t_he_start = chrono::high_resolution_clock::now();
    auto encrypted_result = encrypted_matrix_mult(encrypted_A, B, encoder, evaluator, relin_keys, galois_keys, scale);
    auto t_he_end = chrono::high_resolution_clock::now();
    cout << "HE computation time: " << chrono::duration_cast<chrono::microseconds>(t_he_end - t_he_start).count() << " us\n";

    // Decrypt result
    auto t_dec_start = chrono::high_resolution_clock::now();
    auto he_result = decrypt_matrix(encrypted_result, decryptor, encoder, cols_B);
    auto t_dec_end = chrono::high_resolution_clock::now();
    cout << "Decryption time: " << chrono::duration_cast<chrono::microseconds>(t_dec_end - t_dec_start).count() << " us\n\n";

    // Final result
    cout << "Homomorphic Result:\n"; print_matrix(he_result);

    // Error comparison
    cout << "\nElement-wise comparison (tolerance 0.01):\n";
    double max_error = 0.0, avg_error = 0.0;
    size_t count = 0;
    for (size_t i = 0; i < rows_A; i++) {
        for (size_t j = 0; j < cols_B; j++) {
            double error = fabs(plain_result[i][j] - he_result[i][j]);
            cout << "[" << (error < 0.01 ? "OK" : "❌") << " err=" << error << "] ";
            max_error = max(max_error, error);
            avg_error += error;
            count++;
        }
        cout << endl;
    }

    avg_error /= count;
    cout << "\nMaximum error: " << max_error << "\n";
    cout << "Average error: " << avg_error << "\n";

    return 0;
}