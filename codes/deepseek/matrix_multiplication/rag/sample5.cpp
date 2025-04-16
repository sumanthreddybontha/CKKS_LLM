#include <iostream>
#include <vector>
#include <complex>
#include <chrono>
#include "seal/seal.h"

using namespace std;
using namespace seal;

// Helper function to print matrix
void print_matrix(const vector<vector<double>> &matrix, size_t row_count = 4, size_t col_count = 4) {
    for (size_t i = 0; i < min(row_count, matrix.size()); i++) {
        cout << "[";
        for (size_t j = 0; j < min(col_count, matrix[i].size()); j++) {
            cout << matrix[i][j] << ((j != min(col_count, matrix[i].size()) - 1) ? ", " : "]\n");
        }
    }
}

// Helper function to generate random matrix
vector<vector<double>> random_matrix(size_t rows, size_t cols) {
    vector<vector<double>> matrix(rows, vector<double>(cols));
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; j < cols; j++) {
            matrix[i][j] = static_cast<double>(rand()) / RAND_MAX;
        }
    }
    return matrix;
}

// Matrix multiplication for plaintext (for verification)
vector<vector<double>> plain_matrix_mult(const vector<vector<double>> &A, const vector<vector<double>> &B) {
    size_t rows_A = A.size();
    size_t cols_A = A[0].size();
    size_t cols_B = B[0].size();
    
    vector<vector<double>> result(rows_A, vector<double>(cols_B, 0.0));
    
    for (size_t i = 0; i < rows_A; i++) {
        for (size_t j = 0; j < cols_B; j++) {
            for (size_t k = 0; k < cols_A; k++) {
                result[i][j] += A[i][k] * B[k][j];
            }
        }
    }
    
    return result;
}

// Encode matrix into CKKS plaintexts (row-wise encoding)
vector<Plaintext> encode_matrix(const vector<vector<double>> &matrix, CKKSEncoder &encoder, double scale) {
    size_t rows = matrix.size();
    size_t cols = matrix[0].size();
    vector<Plaintext> encoded(rows);
    
    for (size_t i = 0; i < rows; i++) {
        vector<double> row_data(cols);
        for (size_t j = 0; j < cols; j++) {
            row_data[j] = matrix[i][j];
        }
        encoder.encode(row_data, scale, encoded[i]);
    }
    
    return encoded;
}

// Encrypt matrix (row-wise encryption)
vector<Ciphertext> encrypt_matrix(const vector<Plaintext> &encoded_matrix, Encryptor &encryptor) {
    vector<Ciphertext> encrypted(encoded_matrix.size());
    for (size_t i = 0; i < encoded_matrix.size(); i++) {
        encryptor.encrypt(encoded_matrix[i], encrypted[i]);
    }
    return encrypted;
}

// Homomorphic matrix multiplication
vector<Ciphertext> encrypted_matrix_mult(
    const vector<Ciphertext> &encrypted_A,
    const vector<vector<double>> &plain_B,
    CKKSEncoder &encoder,
    Evaluator &evaluator,
    RelinKeys &relin_keys,
    double scale) {
    
    size_t rows_A = encrypted_A.size();
    size_t cols_B = plain_B[0].size();
    size_t inner_dim = plain_B.size();
    
    // Encode plaintext matrix B
    vector<Plaintext> encoded_B(cols_B);
    for (size_t j = 0; j < cols_B; j++) {
        vector<double> col_data(inner_dim);
        for (size_t k = 0; k < inner_dim; k++) {
            col_data[k] = plain_B[k][j];
        }
        encoder.encode(col_data, scale, encoded_B[j]);
    }
    
    // Perform multiplication
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
            
            // Rotate and add
            evaluator.rotate_vector_inplace(temp2, -static_cast<int>(j), galois_keys);
            evaluator.add_inplace(temp, temp2);
        }
        
        result[i] = temp;
    }
    
    return result;
}

// Decrypt matrix (row-wise decryption)
vector<vector<double>> decrypt_matrix(
    const vector<Ciphertext> &encrypted_matrix,
    Decryptor &decryptor,
    CKKSEncoder &encoder,
    size_t row_size) {
    
    vector<vector<double>> result(encrypted_matrix.size(), vector<double>(row_size));
    
    for (size_t i = 0; i < encrypted_matrix.size(); i++) {
        Plaintext plain_result;
        decryptor.decrypt(encrypted_matrix[i], plain_result);
        
        vector<double> decoded_result;
        encoder.decode(plain_result, decoded_result);
        
        for (size_t j = 0; j < row_size; j++) {
            result[i][j] = decoded_result[j];
        }
    }
    
    return result;
}

int main() {
    // Set up parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    
    double scale = pow(2.0, 40);
    
    // Create context
    SEALContext context(parms);
    cout << endl;
    
    // Generate keys
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    
    // Set up encryptor, evaluator, decryptor, encoder
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    // Matrix dimensions
    size_t rows_A = 4;
    size_t cols_A = 4;
    size_t cols_B = 4;
    
    // Generate random matrices
    vector<vector<double>> A = random_matrix(rows_A, cols_A);
    vector<vector<double>> B = random_matrix(cols_A, cols_B);
    
    cout << "Matrix A (first few elements):" << endl;
    print_matrix(A);
    cout << endl;
    
    cout << "Matrix B (first few elements):" << endl;
    print_matrix(B);
    cout << endl;
    
    // Plaintext computation for verification
    auto start_plain = chrono::high_resolution_clock::now();
    vector<vector<double>> plain_result = plain_matrix_mult(A, B);
    auto stop_plain = chrono::high_resolution_clock::now();
    auto plain_duration = chrono::duration_cast<chrono::microseconds>(stop_plain - start_plain);
    
    cout << "Plaintext result (first few elements):" << endl;
    print_matrix(plain_result);
    cout << "Plaintext computation time: " << plain_duration.count() << " microseconds" << endl << endl;
    
    // Encode and encrypt matrix A
    auto start_encode = chrono::high_resolution_clock::now();
    vector<Plaintext> encoded_A = encode_matrix(A, encoder, scale);
    vector<Ciphertext> encrypted_A = encrypt_matrix(encoded_A, encryptor);
    auto stop_encode = chrono::high_resolution_clock::now();
    auto encode_duration = chrono::duration_cast<chrono::microseconds>(stop_encode - start_encode);
    
    cout << "Encoding/encryption time: " << encode_duration.count() << " microseconds" << endl;
    
    // Homomorphic matrix multiplication
    auto start_he = chrono::high_resolution_clock::now();
    vector<Ciphertext> encrypted_result = encrypted_matrix_mult(
        encrypted_A, B, encoder, evaluator, relin_keys, scale);
    auto stop_he = chrono::high_resolution_clock::now();
    auto he_duration = chrono::duration_cast<chrono::microseconds>(stop_he - start_he);
    
    cout << "Homomorphic computation time: " << he_duration.count() << " microseconds" << endl;
    
    // Decrypt and decode result
    auto start_decode = chrono::high_resolution_clock::now();
    vector<vector<double>> he_result = decrypt_matrix(encrypted_result, decryptor, encoder, cols_B);
    auto stop_decode = chrono::high_resolution_clock::now();
    auto decode_duration = chrono::duration_cast<chrono::microseconds>(stop_decode - start_decode);
    
    cout << "Decoding/decryption time: " << decode_duration.count() << " microseconds" << endl << endl;
    
    // Print homomorphic result
    cout << "Homomorphic result (first few elements):" << endl;
    print_matrix(he_result);
    cout << endl;
    
    // Calculate and print errors
    double max_error = 0.0;
    double avg_error = 0.0;
    size_t count = 0;
    
    for (size_t i = 0; i < rows_A; i++) {
        for (size_t j = 0; j < cols_B; j++) {
            double error = abs(plain_result[i][j] - he_result[i][j]);
            max_error = max(max_error, error);
            avg_error += error;
            count++;
        }
    }
    avg_error /= count;
    
    cout << "Maximum absolute error: " << max_error << endl;
    cout << "Average absolute error: " << avg_error << endl;
    
    return 0;
}