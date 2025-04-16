#include <seal/seal.h>
#include <iostream>
#include <vector>
#include <cmath>
using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
    SEALContext context(parms);

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
    double scale = pow(2.0, 40);

    vector<double> input = {1.0, 2.0, 1.0};
    vector<double> kernel = {0.25, 0.5, 0.25};

    Plaintext pt_input;
    encoder.encode(input, scale, pt_input);
    Ciphertext ct_input;
    encryptor.encrypt(pt_input, ct_input);

    vector<Ciphertext> weighted_parts(kernel.size());
    parms_id_type target_parms_id;

    for (size_t i = 0; i < kernel.size(); ++i) {
        Ciphertext rotated;
        int rot = static_cast<int>(i) - 1;
        if (rot != 0)
            evaluator.rotate_vector(ct_input, rot, gal_keys, rotated);
        else
            rotated = ct_input;

        Plaintext k_plain;
        encoder.encode(kernel[i], scale, k_plain);
        evaluator.multiply_plain(rotated, k_plain, weighted_parts[i]);
        evaluator.rescale_to_next_inplace(weighted_parts[i]);

        if (i == 0) target_parms_id = weighted_parts[0].parms_id();
        else evaluator.mod_switch_to_inplace(weighted_parts[i], target_parms_id);
    }

    Ciphertext result = weighted_parts[0];
    for (size_t i = 1; i < weighted_parts.size(); ++i)
        evaluator.add_inplace(result, weighted_parts[i]);

    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    vector<double> output;
    encoder.decode(plain_result, output);

    cout << "Smoothed output: ";
    for (double val : output) cout << val << " ";
    cout << endl;
    return 0;
}
