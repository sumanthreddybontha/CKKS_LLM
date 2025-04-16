#include <iostream>
#include <vector>
#include <chrono>
#include <seal/seal.h>

using namespace std;
using namespace seal;

// Function to print matrix
void print_matrix(const vector<vector<double>> &matrix, size_t row_count, size_t col_count) {
    for (size_t i = 0; i < row_count; i++) {
        cout << "[ ";
        for (size_t j = 0; j < col_count; j++) {
            cout << matrix[i][j] << " ";
        }
        cout << "]" << endl;
    }
}

// Function to perform plaintext matrix multiplication
vector<vector<double>> matrix_multiply_plain(const vector<vector<double>> &a, 
                                            const vector<vector<double>> &b, 
                                            size_t a_rows, size_t a_cols, 
                                            size_t b_cols) {
    vector<vector<double>> result(a_rows, vector<double>(b_cols, 0));
    for (size_t i = 0; i < a_rows; i++) {
        for (size_t j = 0; j < b_cols; j++) {
            for (size_t k = 0; k < a_cols; k++) {
                result[i][j] += a[i][k] * b[k][j];
            }
        }
    }
    return result;
}

// Function to perform encrypted matrix multiplication
vector<vector<double>> matrix_multiply_encrypted(
    const vector<vector<double>> &a, 
    const vector<vector<double>> &b, 
    size_t a_rows, size_t a_cols, 
    size_t b_cols,
    CKKSEncoder &encoder,
    Encryptor &encryptor,
    Evaluator &evaluator,
    Decryptor &decryptor,
    RelinKeys &relin_keys,
    GaloisKeys &galois_keys,
    double scale) {
    
    size_t slot_count = encoder.slot_count();
    vector<vector<double>> result(a_rows, vector<double>(b_cols, 0));
    
    // Encode and encrypt each row of matrix a
    vector<Ciphertext> encrypted_a_rows(a_rows);
    for (size_t i = 0; i < a_rows; i++) {
        Plaintext plain_row;
        encoder.encode(a[i], scale, plain_row);
        encryptor.encrypt(plain_row, encrypted_a_rows[i]);
    }
    
    // Process each column of matrix b
    for (size_t j = 0; j < b_cols; j++) {
        // Get the current column from b
        vector<double> b_col(a_cols);
        for (size_t k = 0; k < a_cols; k++) {
            b_col[k] = b[k][j];
        }
        
        // Encode the column (no encryption needed)
        Plaintext plain_col;
        encoder.encode(b_col, scale, plain_col);
        
        // Multiply each encrypted row with the plaintext column
        for (size_t i = 0; i < a_rows; i++) {
            Ciphertext encrypted_product;
            evaluator.multiply_plain(encrypted_a_rows[i], plain_col, encrypted_product);
            evaluator.relinearize_inplace(encrypted_product, relin_keys);
            evaluator.rescale_to_next_inplace(encrypted_product);
            
            // Sum all elements in the product vector to get the dot product
            Ciphertext encrypted_sum = encrypted_product;
            for (size_t k = 1; k < slot_count; k <<= 1) {
                Ciphertext rotated;
                evaluator.rotate_vector(encrypted_sum, k, galois_keys, rotated);
                evaluator.add_inplace(encrypted_sum, rotated);
            }
            
            // Decrypt and decode the result
            Plaintext plain_result;
            decryptor.decrypt(encrypted_sum, plain_result);
            vector<double> decoded_result;
            encoder.decode(plain_result, decoded_result);
            
            result[i][j] = decoded_result[0];
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
    // print_parameters(context);
    
    // Generate keys
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    
    // Set up encoders/encryptors/etc.
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    
    // Define matrices
    size_t a_rows = 2, a_cols = 3;
    size_t b_rows = 3, b_cols = 2;
    
    vector<vector<double>> a = {
        {1.0, 2.0, 3.0},
        {4.0, 5.0, 6.0}
    };
    
    vector<vector<double>> b = {
        {7.0, 8.0},
        {9.0, 10.0},
        {11.0, 12.0}
    };
    
    // Perform plaintext multiplication
    cout << "Plaintext matrix A:" << endl;
    print_matrix(a, a_rows, a_cols);
    cout << "\nPlaintext matrix B:" << endl;
    print_matrix(b, b_rows, b_cols);
    
    auto plain_result = matrix_multiply_plain(a, b, a_rows, a_cols, b_cols);
    cout << "\nPlaintext result:" << endl;
    print_matrix(plain_result, a_rows, b_cols);
    
    // Perform encrypted multiplication
    cout << "\nPerforming encrypted matrix multiplication..." << endl;
    auto start = chrono::high_resolution_clock::now();
    
    auto encrypted_result = matrix_multiply_encrypted(
        a, b, a_rows, a_cols, b_cols,
        encoder, encryptor, evaluator, decryptor, relin_keys, galois_keys, scale);
    
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(stop - start);
    
    cout << "Encrypted result:" << endl;
    print_matrix(encrypted_result, a_rows, b_cols);
    cout << "\nTime taken: " << duration.count() << " milliseconds" << endl;
    
    // Calculate and print errors
    double max_error = 0.0;
    double avg_error = 0.0;
    int count = 0;
    
    for (size_t i = 0; i < a_rows; i++) {
        for (size_t j = 0; j < b_cols; j++) {
            double error = abs(plain_result[i][j] - encrypted_result[i][j]);
            if (error > max_error) {
                max_error = error;
            }
            avg_error += error;
            count++;
        }
    }
    avg_error /= count;
    
    cout << "\nMaximum absolute error: " << max_error << endl;
    cout << "Average absolute error: " << avg_error << endl;
    
    return 0;
}