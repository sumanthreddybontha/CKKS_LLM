#include <iostream>
#include <vector>
#include <chrono>
#include "seal/seal.h"

using namespace std;
using namespace seal;

void print_matrix(const vector<vector<double>> &matrix, size_t rows = 4, size_t cols = 4) {
    for (size_t i = 0; i < rows; i++) {
        cout << "[";
        for (size_t j = 0; j < cols; j++) {
            cout << matrix[i][j] << ((j != cols - 1) ? ", " : "]\n");
        }
    }
}

int main() {
    // Step 1: Set up parameters
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_mod_degree = 8192;
    parms.set_poly_modulus_degree(poly_mod_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_mod_degree, {60, 40, 40, 60}));
    double scale = pow(2.0, 40);

    // Step 2: Create context
    SEALContext context(parms);
    // Replaced print_parameters with manual printing
    cout << "Parameters:" << endl;
    cout << "- Scheme: CKKS" << endl;
    cout << "- Poly modulus degree: " << poly_mod_degree << endl;
    cout << "- Coeff modulus size: " << parms.coeff_modulus().size() << endl;

    // Step 3: Generate keys
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // Step 4: Initialize encryptor, evaluator, decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Step 5: Define matrices (4x4)
    vector<vector<double>> mat1 = {{1, 2, 3, 4}, {5, 6, 7, 8}, {9, 10, 11, 12}, {13, 14, 15, 16}};
    vector<vector<double>> mat2 = {{1, 0, 0, 0}, {0, 1, 0, 0}, {0, 0, 1, 0}, {0, 0, 0, 1}}; // Identity matrix

    cout << "Matrix 1:" << endl;
    print_matrix(mat1);
    cout << "Matrix 2:" << endl;
    print_matrix(mat2);

    // Step 6: Flatten matrices
    vector<double> flat_mat1, flat_mat2;
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            flat_mat1.push_back(mat1[i][j]);
            flat_mat2.push_back(mat2[j][i]); // Transpose for multiplication
        }
    }

    // Step 7: Encode & Encrypt
    Plaintext plain1, plain2;
    encoder.encode(flat_mat1, scale, plain1);
    encoder.encode(flat_mat2, scale, plain2);
    Ciphertext enc1, enc2;
    encryptor.encrypt(plain1, enc1);
    encryptor.encrypt(plain2, enc2);

    // Step 8: Multiply
    Ciphertext result;
    evaluator.multiply(enc1, enc2, result);
    evaluator.relinearize_inplace(result, relin_keys);
    evaluator.rescale_to_next_inplace(result);

    // Step 9: Decrypt & Decode
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    vector<double> decoded_result;
    encoder.decode(plain_result, decoded_result);

    // Step 10: Extract result
    vector<vector<double>> encrypted_result(4, vector<double>(4));
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            encrypted_result[i][j] = decoded_result[i * 4 + j];
        }
    }

    cout << "Encrypted Result:" << endl;
    print_matrix(encrypted_result);

    return 0;
}