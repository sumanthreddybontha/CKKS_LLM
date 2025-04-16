// blend elements from the Row-by-Column Dot Product Approach and the Flattened Vector Encoding Approach
#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <sstream>

using namespace std;
using namespace seal;

int main() {
    // CKKS parameter setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    KeyGenerator keygen(context);

    // Serialize and load public key
    Serializable<PublicKey> public_key_serial = keygen.create_public_key();
    PublicKey public_key;
    std::stringstream public_key_stream;
    public_key_serial.save(public_key_stream);
    public_key.load(context, public_key_stream);

    // Serialize and load relin keys
    Serializable<RelinKeys> relin_keys_serial = keygen.create_relin_keys();
    RelinKeys relin_keys;
    std::stringstream relin_key_stream;
    relin_keys_serial.save(relin_key_stream);
    relin_keys.load(context, relin_key_stream);

    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Input matrices (flattened encoding approach for columns)
    vector<vector<double>> matrix_a = {{1.0, 2.0, 3.0},
                                       {4.0, 5.0, 6.0},
                                       {7.0, 8.0, 9.0}};
    vector<vector<double>> matrix_b = {{9.0, 8.0, 7.0},
                                       {6.0, 5.0, 4.0},
                                       {3.0, 2.0, 1.0}};

    // Flattened encoding of matrix_b
    vector<Plaintext> encoded_columns;
    for (size_t col = 0; col < matrix_b[0].size(); ++col) {
        vector<double> column;
        for (size_t row = 0; row < matrix_b.size(); ++row) {
            column.push_back(matrix_b[row][col]);
        }
        Plaintext plain_column;
        encoder.encode(column, scale, plain_column);
        encoded_columns.push_back(plain_column);
    }

    // Encrypt rows of matrix_a
    vector<Ciphertext> encrypted_rows;
    for (auto &row : matrix_a) {
        Plaintext plain_row;
        encoder.encode(row, scale, plain_row);
        Ciphertext encrypted_row;
        encryptor.encrypt(plain_row, encrypted_row);
        encrypted_rows.push_back(encrypted_row);
    }

    // Compute matrix multiplication (row-by-column logic)
    vector<vector<Ciphertext>> encrypted_result(matrix_a.size(), vector<Ciphertext>(matrix_b[0].size()));
    for (size_t i = 0; i < matrix_a.size(); ++i) {
        for (size_t j = 0; j < matrix_b[0].size(); ++j) {
            Ciphertext dot_product = encrypted_rows[i];
            evaluator.multiply_plain_inplace(dot_product, encoded_columns[j]);
            evaluator.relinearize_inplace(dot_product, relin_keys);
            evaluator.rescale_to_next_inplace(dot_product);
            encrypted_result[i][j] = dot_product;
        }
    }

    // Decrypt and print results
    for (size_t i = 0; i < matrix_a.size(); ++i) {
        for (size_t j = 0; j < matrix_b[0].size(); ++j) {
            Plaintext result_plain;
            decryptor.decrypt(encrypted_result[i][j], result_plain);
            vector<double> result_values;
            encoder.decode(result_plain, result_values);
            cout << result_values[0] << " ";
        }
        cout << endl;
    }

    return 0;
}
