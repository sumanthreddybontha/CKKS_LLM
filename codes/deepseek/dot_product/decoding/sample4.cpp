#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

void print_parameters(const SEALContext &context) {
    auto &context_data = *context.key_context_data();
    cout << "Encryption parameters:" << endl;
    cout << "  scheme: CKKS" << endl;
    cout << "  poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << endl;
    cout << "  coeff_modulus size: " << context_data.total_coeff_modulus_bit_count() << " bits" << endl;
    cout << "  scale: " << context_data.parms().coeff_modulus().back().bit_count() << " bits" << endl;
}

int main() {
    // Step 1: CKKS setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    SEALContext context(parms);
    print_parameters(context);

    // Step 2: Keys and helpers
    KeyGenerator keygen(context);
    PublicKey public_key;
    SecretKey secret_key = keygen.secret_key();
    keygen.create_public_key(public_key);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);

    // Step 3: Flattened 4x4 matrix
    vector<double> matrix = {
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12,
        13, 14, 15, 16
    };

    // Step 4: Encode and encrypt matrix
    Plaintext plain_matrix;
    encoder.encode(matrix, scale, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);

    // Step 5: Row-wise sum using rotation and masking
    vector<Ciphertext> row_sums;
    for (int i = 0; i < 4; i++) {
        vector<double> mask(16, 0.0);
        for (int j = 0; j < 4; j++) {
            mask[i * 4 + j] = 1.0;
        }

        Plaintext plain_mask;
        encoder.encode(mask, scale, plain_mask);
        evaluator.mod_switch_to_inplace(plain_mask, encrypted_matrix.parms_id());

        Ciphertext masked;
        evaluator.multiply_plain(encrypted_matrix, plain_mask, masked);
        evaluator.rescale_to_next_inplace(masked);

        Ciphertext row_sum = masked;
        for (int j = 1; j < 4; j++) {
            Ciphertext rotated;
            evaluator.rotate_vector(row_sum, j, gal_keys, rotated);
            evaluator.add_inplace(row_sum, rotated);
        }

        row_sums.push_back(row_sum);
    }

    // Step 6: Decrypt and decode results
    for (int i = 0; i < 4; i++) {
        Plaintext plain_sum;
        decryptor.decrypt(row_sums[i], plain_sum);
        vector<double> result;
        encoder.decode(plain_sum, result);
        cout << "Row " << i << " sum: " << result[0] << endl;
    }

    return 0;
}