#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

// Helper function to print a matrix from a flattened vector
void print_matrix(const vector<double> &vec, size_t rows, size_t cols) {
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; j < cols; j++) {
            cout << vec[i * cols + j] << "\t";
        }
        cout << endl;
    }
}

int main() {
    // Step 1: Set encryption parameters for CKKS
    size_t poly_modulus_degree = 8192;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);

    // Step 2: Key generation and encoder setup
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    // Step 3: Input matrices (4x4)
    size_t dim = 4;
    vector<double> matrix_A = {
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12,
        13, 14, 15, 16
    };

    vector<double> matrix_B = {
        16, 15, 14, 13,
        12, 11, 10, 9,
        8, 7, 6, 5,
        4, 3, 2, 1
    };

    double scale = pow(2.0, 40);

    // Step 4: Encode rows of A and columns of B
    vector<Plaintext> encoded_A_rows(dim);
    vector<Plaintext> encoded_B_cols(dim);

    for (size_t i = 0; i < dim; i++) {
        vector<double> row(slot_count, 0.0);
        for (size_t j = 0; j < dim; j++) {
            row[j] = matrix_A[i * dim + j];
        }
        encoder.encode(row, scale, encoded_A_rows[i]);
    }

    for (size_t j = 0; j < dim; j++) {
        vector<double> col(slot_count, 0.0);
        for (size_t i = 0; i < dim; i++) {
            col[i] = matrix_B[i * dim + j];
        }
        encoder.encode(col, scale, encoded_B_cols[j]);
    }

    // Step 5: Encrypt rows of A
    vector<Ciphertext> encrypted_A_rows(dim);
    for (size_t i = 0; i < dim; i++) {
        encryptor.encrypt(encoded_A_rows[i], encrypted_A_rows[i]);
    }

    // Step 6: Multiply encrypted A rows with B columns
    vector<double> result(dim * dim, 0.0);

    for (size_t i = 0; i < dim; i++) {
        for (size_t j = 0; j < dim; j++) {
            Ciphertext temp;
            evaluator.multiply_plain(encrypted_A_rows[i], encoded_B_cols[j], temp);
            evaluator.relinearize_inplace(temp, relin_keys);
            evaluator.rescale_to_next_inplace(temp);

            // Adjust scale for decoding
            Plaintext plain_result;
            decryptor.decrypt(temp, plain_result);

            vector<double> decoded;
            encoder.decode(plain_result, decoded);

            double dot_product = 0.0;
            for (size_t k = 0; k < dim; k++) {
                dot_product += decoded[k];
            }
            result[i * dim + j] = dot_product;
        }
    }

    // Step 7: Output
    cout << "\nMatrix A:" << endl;
    print_matrix(matrix_A, dim, dim);

    cout << "\nMatrix B:" << endl;
    print_matrix(matrix_B, dim, dim);

    cout << "\nEncrypted Matrix Multiplication Result (A x B):" << endl;
    print_matrix(result, dim, dim);

    return 0;
}
