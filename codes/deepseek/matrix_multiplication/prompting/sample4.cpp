#include <seal/seal.h>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>

using namespace std;
using namespace seal;

const size_t MATRIX_SIZE = 2;
mutex cout_mutex;

void initialize_matrix(vector<vector<int>> &matrix, size_t start_row, size_t end_row) {
    for (size_t i = start_row; i < end_row; ++i) {
        for (size_t j = 0; j < MATRIX_SIZE; ++j) {
            matrix[i][j] = rand() % 10;
        }
    }
}

void encode_matrix(const vector<vector<int>> &matrix, vector<vector<Plaintext>> &encoded,
                   BatchEncoder &encoder, size_t start_row, size_t end_row) {
    for (size_t i = start_row; i < end_row; ++i) {
        for (size_t j = 0; j < MATRIX_SIZE; ++j) {
            vector<uint64_t> slot_vec(encoder.slot_count(), 0ULL);
            slot_vec[0] = matrix[i][j];
            encoder.encode(slot_vec, encoded[i][j]);
        }
    }
}

vector<vector<Ciphertext>> encrypted_matrix_multiply(
    const vector<vector<Ciphertext>> &encA,
    const vector<vector<Ciphertext>> &encB,
    Evaluator &evaluator) {

    vector<vector<Ciphertext>> result(MATRIX_SIZE, vector<Ciphertext>(MATRIX_SIZE));

    for (size_t i = 0; i < MATRIX_SIZE; ++i) {
        for (size_t j = 0; j < MATRIX_SIZE; ++j) {
            Ciphertext sum;
            bool first = true;
            for (size_t k = 0; k < MATRIX_SIZE; ++k) {
                Ciphertext tmp;
                evaluator.multiply(encA[i][k], encB[k][j], tmp);
                if (first) {
                    sum = tmp;
                    first = false;
                } else {
                    evaluator.add_inplace(sum, tmp);
                }
            }
            result[i][j] = sum;
        }
    }

    return result;
}

int main() {
    // Step 1: Set up SEAL context
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    
    SEALContext context(parms);
    BatchEncoder encoder(context);
    KeyGenerator keygen(context);

    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Step 2: Initialize matrices A and B in parallel
    vector<vector<int>> A(MATRIX_SIZE, vector<int>(MATRIX_SIZE));
    vector<vector<int>> B(MATRIX_SIZE, vector<int>(MATRIX_SIZE));

    thread t1(initialize_matrix, ref(A), 0, MATRIX_SIZE / 2);
    thread t2(initialize_matrix, ref(A), MATRIX_SIZE / 2, MATRIX_SIZE);
    thread t3(initialize_matrix, ref(B), 0, MATRIX_SIZE / 2);
    thread t4(initialize_matrix, ref(B), MATRIX_SIZE / 2, MATRIX_SIZE);

    t1.join(); t2.join(); t3.join(); t4.join();

    // Step 3: Encode matrices in parallel
    vector<vector<Plaintext>> plainA(MATRIX_SIZE, vector<Plaintext>(MATRIX_SIZE));
    vector<vector<Plaintext>> plainB(MATRIX_SIZE, vector<Plaintext>(MATRIX_SIZE));

    thread t5(encode_matrix, cref(A), ref(plainA), ref(encoder), 0, MATRIX_SIZE / 2);
    thread t6(encode_matrix, cref(A), ref(plainA), ref(encoder), MATRIX_SIZE / 2, MATRIX_SIZE);
    thread t7(encode_matrix, cref(B), ref(plainB), ref(encoder), 0, MATRIX_SIZE / 2);
    thread t8(encode_matrix, cref(B), ref(plainB), ref(encoder), MATRIX_SIZE / 2, MATRIX_SIZE);

    t5.join(); t6.join(); t7.join(); t8.join();

    // Step 4: Encrypt matrices (serial)
    vector<vector<Ciphertext>> encA(MATRIX_SIZE, vector<Ciphertext>(MATRIX_SIZE));
    vector<vector<Ciphertext>> encB(MATRIX_SIZE, vector<Ciphertext>(MATRIX_SIZE));
    for (size_t i = 0; i < MATRIX_SIZE; ++i) {
        for (size_t j = 0; j < MATRIX_SIZE; ++j) {
            encryptor.encrypt(plainA[i][j], encA[i][j]);
            encryptor.encrypt(plainB[i][j], encB[i][j]);
        }
    }

    // Step 5: Multiply encrypted matrices
    auto encResult = encrypted_matrix_multiply(encA, encB, evaluator);

    // Step 6: Decrypt and decode results
    cout << "Decrypted Result Matrix:" << endl;
    for (size_t i = 0; i < MATRIX_SIZE; ++i) {
        for (size_t j = 0; j < MATRIX_SIZE; ++j) {
            Plaintext plain_result;
            decryptor.decrypt(encResult[i][j], plain_result);
            vector<uint64_t> decoded;
            encoder.decode(plain_result, decoded);
            cout << decoded[0] << " ";
        }
        cout << endl;
    }

    return 0;
}
