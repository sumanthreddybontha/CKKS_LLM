#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

// Print SEAL encryption parameters
void print_parameters(const SEALContext &context) {
    auto &context_data = *context.key_context_data();
    cout << "Encryption parameters:" << endl;
    cout << "  Poly modulus degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << "  Coeff moduli size: ";
    for (const auto &mod : context_data.parms().coeff_modulus()) {
        cout << mod.bit_count() << " ";
    }
    cout << endl;
}

int main() {
    size_t poly_modulus_degree = 8192;
    double scale = pow(2.0, 40);

    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // Key generation
    KeyGenerator keygen(context);

    PublicKey public_key;
    keygen.create_public_key(public_key);

    SecretKey secret_key = keygen.secret_key();

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    // Define 2x2 matrices
    vector<double> mat1 = {1.0, 2.0,
                           3.0, 4.0};
    vector<double> mat2 = {5.0, 6.0,
                           7.0, 8.0};
    size_t dim = 2;

    // Encode/encrypt rows and columns
    vector<Plaintext> plain_mat1_rows(dim);
    vector<Plaintext> plain_mat2_cols(dim);
    vector<Ciphertext> encrypted_mat1_rows(dim);
    vector<Ciphertext> encrypted_mat2_cols(dim);

    for (size_t i = 0; i < dim; ++i) {
        vector<double> row(dim), col(dim);
        for (size_t j = 0; j < dim; ++j) {
            row[j] = mat1[i * dim + j];
            col[j] = mat2[j * dim + i];
        }

        encoder.encode(row, scale, plain_mat1_rows[i]);
        encoder.encode(col, scale, plain_mat2_cols[i]);
        encryptor.encrypt(plain_mat1_rows[i], encrypted_mat1_rows[i]);
        encryptor.encrypt(plain_mat2_cols[i], encrypted_mat2_cols[i]);
    }

    // Multiply and relinearize
    vector<Ciphertext> result_ct(dim * dim);
    for (size_t i = 0; i < dim; ++i) {
        for (size_t j = 0; j < dim; ++j) {
            Ciphertext mult;
            evaluator.multiply(encrypted_mat1_rows[i], encrypted_mat2_cols[j], mult);
            evaluator.relinearize_inplace(mult, relin_keys);
            evaluator.rescale_to_next_inplace(mult);
            result_ct[i * dim + j] = mult;
        }
    }

    // Decrypt and decode
    cout << "Result Matrix (approximate values):" << endl;
    for (size_t i = 0; i < dim; ++i) {
        for (size_t j = 0; j < dim; ++j) {
            Plaintext plain_result;
            vector<double> decoded;
            decryptor.decrypt(result_ct[i * dim + j], plain_result);
            encoder.decode(plain_result, decoded);
            cout << decoded[0] << "\t";
        }
        cout << endl;
    }

    return 0;
}
