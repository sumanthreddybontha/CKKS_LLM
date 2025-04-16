#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

// Helper function to print matrix
void print_matrix(const vector<vector<double>> &matrix, size_t row_count = 4, size_t col_count = 4) {
    for (size_t i = 0; i < min(row_count, matrix.size()); i++) {
        cout << "[ ";
        for (size_t j = 0; j < min(col_count, matrix[i].size()); j++) {
            cout << matrix[i][j] << " ";
        }
        cout << "]" << endl;
    }
    cout << endl;
}

// Helper function to create a sample matrix
vector<vector<double>> create_sample_matrix(size_t rows, size_t cols, double start = 0.0, double step = 1.0) {
    vector<vector<double>> matrix(rows, vector<double>(cols));
    double val = start;
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; j < cols; j++) {
            matrix[i][j] = val;
            val += step;
        }
    }
    return matrix;
}

// CKKS Matrix Multiplication
void ckks_matrix_multiplication() {
    // Set up encryption parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    
    SEALContext context(parms);
    print_parameters(context);
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
    
    // Create encoder with scale 2^40
    double scale = pow(2.0, 40);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    
    // Create sample matrices (2x3 and 3x2)
    size_t row_count1 = 2;
    size_t col_count1 = 3;
    size_t row_count2 = 3;
    size_t col_count2 = 2;
    
    auto matrix1 = create_sample_matrix(row_count1, col_count1, 1.0, 1.0);
    auto matrix2 = create_sample_matrix(row_count2, col_count2, 1.0, 1.0);
    
    cout << "Matrix 1:" << endl;
    print_matrix(matrix1);
    cout << "Matrix 2:" << endl;
    print_matrix(matrix2);
    
    // Encode and encrypt matrix1 (row-wise)
    vector<Plaintext> plain_matrix1(row_count1);
    vector<Ciphertext> encrypted_matrix1(row_count1);
    
    for (size_t i = 0; i < row_count1; i++) {
        vector<double> row_data(slot_count, 0.0);
        copy(matrix1[i].begin(), matrix1[i].end(), row_data.begin());
        encoder.encode(row_data, scale, plain_matrix1[i]);
        encryptor.encrypt(plain_matrix1[i], encrypted_matrix1[i]);
    }
    
    // Encode and encrypt matrix2 (column-wise, transposed)
    vector<Plaintext> plain_matrix2(col_count2);
    vector<Ciphertext> encrypted_matrix2(col_count2);
    
    for (size_t j = 0; j < col_count2; j++) {
        vector<double> col_data(slot_count, 0.0);
        for (size_t i = 0; i < row_count2; i++) {
            col_data[i] = matrix2[i][j];
        }
        encoder.encode(col_data, scale, plain_matrix2[j]);
        encryptor.encrypt(plain_matrix2[j], encrypted_matrix2[j]);
    }
    
    // Perform matrix multiplication
    vector<vector<Ciphertext>> encrypted_result(row_count1, vector<Ciphertext>(col_count2));
    
    for (size_t i = 0; i < row_count1; i++) {
        for (size_t j = 0; j < col_count2; j++) {
            // Compute dot product between row i of matrix1 and column j of matrix2
            Ciphertext product;
            evaluator.multiply(encrypted_matrix1[i], encrypted_matrix2[j], product);
            evaluator.relinearize_inplace(product, relin_keys);
            evaluator.rescale_to_next_inplace(product);
            
            // Sum all elements in the product
            Ciphertext sum = product;
            for (size_t k = 1; k < col_count1; k <<= 1) {
                Ciphertext rotated;
                evaluator.rotate_vector(sum, k, gal_keys, rotated);
                evaluator.add_inplace(sum, rotated);
            }
            
            encrypted_result[i][j] = sum;
        }
    }
    
    // Decrypt and decode results
    vector<vector<double>> result(row_count1, vector<double>(col_count2));
    
    for (size_t i = 0; i < row_count1; i++) {
        for (size_t j = 0; j < col_count2; j++) {
            Plaintext plain_result;
            decryptor.decrypt(encrypted_result[i][j], plain_result);
            
            vector<double> decoded_result;
            encoder.decode(plain_result, decoded_result);
            
            result[i][j] = decoded_result[0]; // First slot contains the sum
        }
    }
    
    cout << "Result of matrix multiplication:" << endl;
    print_matrix(result);
    
    // Verify against plaintext computation
    vector<vector<double>> expected_result(row_count1, vector<double>(col_count2, 0.0));
    for (size_t i = 0; i < row_count1; i++) {
        for (size_t j = 0; j < col_count2; j++) {
            for (size_t k = 0; k < col_count1; k++) {
                expected_result[i][j] += matrix1[i][k] * matrix2[k][j];
            }
        }
    }
    
    cout << "Expected result:" << endl;
    print_matrix(expected_result);
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