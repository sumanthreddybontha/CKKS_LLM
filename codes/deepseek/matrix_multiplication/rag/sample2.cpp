#include <iostream>
#include <vector>
#include <memory>
#include <seal/seal.h>

using namespace std;
using namespace seal;

// Helper function to print matrix
void print_matrix(const vector<vector<double>> &matrix, size_t row_count, size_t col_count) {
    for (size_t i = 0; i < row_count; i++) {
        cout << "[ ";
        for (size_t j = 0; j < col_count; j++) {
            cout << matrix[i][j] << " ";
        }
        cout << "]" << endl;
    }
}

// CKKS Matrix Multiplication
void ckks_matrix_multiplication() {
    // Matrix dimensions (must be power of 2 for simplicity)
    const size_t dim1 = 2;
    const size_t dim2 = 2;
    const size_t dim3 = 2;
    
    // Original matrices
    vector<vector<double>> matrix1(dim1, vector<double>(dim2));
    vector<vector<double>> matrix2(dim2, vector<double>(dim3));
    
    // Fill matrices with sample values
    matrix1 = {{1.0, 2.0}, {3.0, 4.0}};
    matrix2 = {{2.0, 0.0}, {1.0, 2.0}};
    
    cout << "Matrix A:" << endl;
    print_matrix(matrix1, dim1, dim2);
    cout << "Matrix B:" << endl;
    print_matrix(matrix2, dim2, dim3);
    
    // CKKS Parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Set appropriate coefficient modulus for CKKS
    vector<int> bit_sizes = {60, 40, 40, 60}; // Adjust based on required precision and security
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, bit_sizes));
    
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
    
    // Encryptor, evaluator, decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    // CKKS encoder
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;
    
    // Scale for encoding
    double scale = pow(2.0, 40);
    
    // Encode and encrypt matrix1 (A)
    vector<Plaintext> a_plain(dim1);
    vector<Ciphertext> a_encrypted(dim1);
    for (size_t i = 0; i < dim1; i++) {
        encoder.encode(matrix1[i], scale, a_plain[i]);
        encryptor.encrypt(a_plain[i], a_encrypted[i]);
    }
    
    // Encode and encrypt matrix2 (B) - need to encode columns for matrix multiplication
    vector<Plaintext> b_plain(dim3);
    vector<Ciphertext> b_encrypted(dim3);
    for (size_t j = 0; j < dim3; j++) {
        vector<double> b_column;
        for (size_t i = 0; i < dim2; i++) {
            b_column.push_back(matrix2[i][j]);
        }
        encoder.encode(b_column, scale, b_plain[j]);
        encryptor.encrypt(b_plain[j], b_encrypted[j]);
    }
    
    // Perform matrix multiplication
    vector<Ciphertext> result(dim1 * dim3);
    for (size_t i = 0; i < dim1; i++) {
        for (size_t j = 0; j < dim3; j++) {
            // Multiply row i of A with column j of B
            Ciphertext product;
            evaluator.multiply(a_encrypted[i], b_encrypted[j], product);
            evaluator.relinearize_inplace(product, relin_keys);
            evaluator.rescale_to_next_inplace(product);
            
            // Sum all elements of the product vector
            Ciphertext sum = product;
            for (size_t k = 0; k < log2(dim2); k++) {
                Ciphertext rotated;
                evaluator.rotate_vector(sum, (1 << k), gal_keys, rotated);
                evaluator.add_inplace(sum, rotated);
            }
            
            result[i * dim3 + j] = sum;
        }
    }
    
    // Decrypt and decode results
    vector<vector<double>> output(dim1, vector<double>(dim3));
    for (size_t i = 0; i < dim1; i++) {
        for (size_t j = 0; j < dim3; j++) {
            Plaintext plain_result;
            decryptor.decrypt(result[i * dim3 + j], plain_result);
            
            vector<double> decoded_result;
            encoder.decode(plain_result, decoded_result);
            
            output[i][j] = decoded_result[0]; // First element contains the sum
        }
    }
    
    cout << "Result of homomorphic matrix multiplication:" << endl;
    print_matrix(output, dim1, dim3);
    
    // Verify against plaintext computation
    vector<vector<double>> expected(dim1, vector<double>(dim3));
    for (size_t i = 0; i < dim1; i++) {
        for (size_t j = 0; j < dim3; j++) {
            double sum = 0.0;
            for (size_t k = 0; k < dim2; k++) {
                sum += matrix1[i][k] * matrix2[k][j];
            }
            expected[i][j] = sum;
        }
    }
    
    cout << "Expected result (plaintext computation):" << endl;
    print_matrix(expected, dim1, dim3);
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