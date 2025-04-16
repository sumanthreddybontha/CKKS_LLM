#include <iostream>
#include <vector>
#include <memory>
#include <seal/seal.h>

using namespace std;
using namespace seal;

// Helper function to print matrix
void print_matrix(const vector<vector<double>> &matrix, size_t row_count = 4, size_t col_count = 4) {
    for (size_t i = 0; i < min(row_count, matrix.size()); i++) {
        cout << "[ ";
        for (size_t j = 0; j < min(col_count, matrix[i].size()); j++) {
            cout << matrix[i][j] << ((j != min(col_count, matrix[i].size()) - 1) ? ", " : " ]\n");
        }
    }
    cout << endl;
}

// CKKS Matrix Multiplication
void ckks_matrix_multiplication() {
    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    
    double scale = pow(2.0, 40);
    
    SEALContext context(parms);
    cout << endl;
    
    // Generate keys
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
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    
    // Define matrices (2x3 and 3x2 for example)
    vector<vector<double>> matrix1 = { {1.0, 2.0, 3.0}, 
                                      {4.0, 5.0, 6.0} };
    vector<vector<double>> matrix2 = { {7.0, 8.0}, 
                                      {9.0, 10.0}, 
                                      {11.0, 12.0} };
    
    // Expected result for verification
    vector<vector<double>> expected_result = { {58.0, 64.0}, 
                                             {139.0, 154.0} };
    
    cout << "Matrix 1:" << endl;
    print_matrix(matrix1);
    cout << "Matrix 2:" << endl;
    print_matrix(matrix2);
    cout << "Expected result:" << endl;
    print_matrix(expected_result);
    
    // Encode and encrypt matrix1 (row-wise)
    vector<Plaintext> encoded_matrix1;
    vector<Ciphertext> encrypted_matrix1;
    for (const auto &row : matrix1) {
        Plaintext plain_row;
        encoder.encode(row, scale, plain_row);
        encoded_matrix1.push_back(plain_row);
        
        Ciphertext encrypted_row;
        encryptor.encrypt(plain_row, encrypted_row);
        encrypted_matrix1.push_back(encrypted_row);
    }
    
    // Encode matrix2 (column-wise) - plaintext only
    vector<Plaintext> encoded_matrix2_cols;
    for (size_t col = 0; col < matrix2[0].size(); col++) {
        vector<double> column;
        for (size_t row = 0; row < matrix2.size(); row++) {
            column.push_back(matrix2[row][col]);
        }
        
        Plaintext plain_col;
        encoder.encode(column, scale, plain_col);
        encoded_matrix2_cols.push_back(plain_col);
    }
    
    // Perform encrypted matrix multiplication
    vector<Ciphertext> encrypted_result;
    for (size_t i = 0; i < encrypted_matrix1.size(); i++) {
        for (size_t j = 0; j < encoded_matrix2_cols.size(); j++) {
            Ciphertext temp;
            evaluator.multiply_plain(encrypted_matrix1[i], encoded_matrix2_cols[j], temp);
            evaluator.relinearize_inplace(temp, relin_keys);
            evaluator.rescale_to_next_inplace(temp);
            
            // Sum all elements in the product vector
            Ciphertext sum = temp;
            for (size_t k = 0; k < log2(slot_count); k++) {
                Ciphertext rotated;
                evaluator.rotate_vector(sum, (1 << k), gal_keys, rotated);
                evaluator.add_inplace(sum, rotated);
            }
            
            encrypted_result.push_back(sum);
        }
    }
    
    // Decrypt and decode results
    cout << "Computed result:" << endl;
    vector<vector<double>> result_matrix(matrix1.size(), vector<double>(matrix2[0].size()));
    size_t idx = 0;
    for (size_t i = 0; i < matrix1.size(); i++) {
        for (size_t j = 0; j < matrix2[0].size(); j++) {
            Plaintext plain_result;
            decryptor.decrypt(encrypted_result[idx++], plain_result);
            
            vector<double> result_vec;
            encoder.decode(plain_result, result_vec);
            
            result_matrix[i][j] = result_vec[0]; // First element contains the sum
        }
    }
    
    print_matrix(result_matrix);
    
    // Verify results
    bool correct = true;
    for (size_t i = 0; i < expected_result.size(); i++) {
        for (size_t j = 0; j < expected_result[0].size(); j++) {
            if (abs(expected_result[i][j] - result_matrix[i][j]) > 0.1) {
                correct = false;
                break;
            }
        }
    }
    
    cout << "Result " << (correct ? "correct" : "incorrect") << endl;
}

int main() {
    try {
        ckks_matrix_multiplication();
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }
    return 0;
}