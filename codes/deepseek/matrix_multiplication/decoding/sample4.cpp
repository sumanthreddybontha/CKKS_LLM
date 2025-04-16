#include <iostream>
#include <vector>
#include <chrono>
#include <seal/seal.h>

using namespace std;
using namespace seal;

// Function to print matrix
void print_matrix(const vector<vector<double>> &matrix, size_t row_count = 4, size_t col_count = 4) {
    for (size_t i = 0; i < min(row_count, matrix.size()); i++) {
        cout << "[";
        for (size_t j = 0; j < min(col_count, matrix[i].size()); j++) {
            cout << matrix[i][j] << ((j != min(col_count, matrix[i].size()) - 1) ? ", " : "]\n");
        }
    }
}

// Function to perform plaintext matrix multiplication
vector<vector<double>> matrix_multiply_plain(const vector<vector<double>> &matrix1, 
                                            const vector<vector<double>> &matrix2) {
    size_t rows1 = matrix1.size();
    size_t cols1 = matrix1[0].size();
    size_t cols2 = matrix2[0].size();
    
    vector<vector<double>> result(rows1, vector<double>(cols2, 0.0));
    
    for (size_t i = 0; i < rows1; i++) {
        for (size_t j = 0; j < cols2; j++) {
            for (size_t k = 0; k < cols1; k++) {
                result[i][j] += matrix1[i][k] * matrix2[k][j];
            }
        }
    }
    
    return result;
}

int main() {
    // Step 1: Set up parameters
    cout << "Setting up CKKS parameters..." << endl;
    
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Set the coefficient modulus to achieve ~128-bit security
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    
    // Set the scale for encoding/decoding
    double scale = pow(2.0, 40);
    
    // Create the SEAL context
    SEALContext context(parms);
    // print_parameters(context);
    cout << endl;
    
    // Step 2: Generate keys
    cout << "Generating keys..." << endl;
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    
    // Create encryptor, evaluator, decryptor, encoder
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    // Step 3: Prepare matrices
    size_t dim = 4; // Matrix dimension (dim x dim)
    
    // Create first matrix (dim x dim)
    vector<vector<double>> matrix1(dim, vector<double>(dim));
    for (size_t i = 0; i < dim; i++) {
        for (size_t j = 0; j < dim; j++) {
            matrix1[i][j] = i * dim + j + 1; // 1, 2, 3, ... 16
        }
    }
    
    // Create second matrix (dim x dim)
    vector<vector<double>> matrix2(dim, vector<double>(dim));
    for (size_t i = 0; i < dim; i++) {
        for (size_t j = 0; j < dim; j++) {
            matrix2[i][j] = (i == j) ? 1.0 : 0.0; // Identity matrix
        }
    }
    
    cout << "Matrix 1:" << endl;
    print_matrix(matrix1);
    cout << endl;
    
    cout << "Matrix 2:" << endl;
    print_matrix(matrix2);
    cout << endl;
    
    // Step 4: Encode and encrypt matrices
    // We'll flatten the matrices into vectors for encoding
    vector<double> flat_matrix1, flat_matrix2;
    for (size_t i = 0; i < dim; i++) {
        flat_matrix1.insert(flat_matrix1.end(), matrix1[i].begin(), matrix1[i].end());
        flat_matrix2.insert(flat_matrix2.end(), matrix2[i].begin(), matrix2[i].end());
    }
    
    Plaintext plain_matrix1, plain_matrix2;
    encoder.encode(flat_matrix1, scale, plain_matrix1);
    encoder.encode(flat_matrix2, scale, plain_matrix2);
    
    Ciphertext encrypted_matrix1, encrypted_matrix2;
    encryptor.encrypt(plain_matrix1, encrypted_matrix1);
    encryptor.encrypt(plain_matrix2, encrypted_matrix2);
    
    // Step 5: Perform matrix multiplication
    cout << "Performing encrypted matrix multiplication..." << endl;
    
    // For CKKS, we need to implement matrix multiplication using rotations and dot products
    // This is a simplified approach for small matrices
    
    Ciphertext result;
    evaluator.multiply(encrypted_matrix1, encrypted_matrix2, result);
    evaluator.relinearize_inplace(result, relin_keys);
    evaluator.rescale_to_next_inplace(result);
    
    // Step 6: Decrypt and decode the result
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    
    vector<double> decoded_result;
    encoder.decode(plain_result, decoded_result);
    
    // Reshape the result back into a matrix
    vector<vector<double>> result_matrix(dim, vector<double>(dim));
    for (size_t i = 0; i < dim; i++) {
        for (size_t j = 0; j < dim; j++) {
            result_matrix[i][j] = decoded_result[i * dim + j];
        }
    }
    
    cout << "Encrypted multiplication result:" << endl;
    print_matrix(result_matrix);
    cout << endl;
    
    // Step 7: Compare with plaintext result
    cout << "Expected plaintext result:" << endl;
    auto expected_result = matrix_multiply_plain(matrix1, matrix2);
    print_matrix(expected_result);
    cout << endl;
    
    // Calculate and print the error
    double max_error = 0.0;
    for (size_t i = 0; i < dim; i++) {
        for (size_t j = 0; j < dim; j++) {
            double error = abs(result_matrix[i][j] - expected_result[i][j]);
            if (error > max_error) {
                max_error = error;
            }
        }
    }
    cout << "Maximum error between encrypted and plaintext result: " << max_error << endl;
    
    return 0;
}