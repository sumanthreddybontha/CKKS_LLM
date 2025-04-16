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

    vector<double> input = {3.0, 6.0, 9.0};
    vector<double> kernel = {0.2, 0.5, 0.3};

    Plaintext pt_input;
    encoder.encode(input, scale, pt_input);
    Ciphertext ct_input;
    encryptor.encrypt(pt_input, ct_input);

    vector<Ciphertext> parts(kernel.size());
    parms_id_type target_parms_id;

    for (size_t i = 0; i < kernel.size(); ++i) {
        Ciphertext shifted;
        int rot = static_cast<int>(i) - 1;
        if (rot != 0)
            evaluator.rotate_vector(ct_input, rot, gal_keys, shifted);
        else
            shifted = ct_input;

        Plaintext k_plain;
        encoder.encode(kernel[i], scale, k_plain);
        evaluator.multiply_plain(shifted, k_plain, parts[i]);
        evaluator.rescale_to_next_inplace(parts[i]);

        if (i == 0)
            target_parms_id = parts[0].parms_id();
        else
            evaluator.mod_switch_to_inplace(parts[i], target_parms_id);
    }

    Ciphertext result = parts[0];
    for (size_t i = 1; i < parts.size(); ++i)
        evaluator.add_inplace(result, parts[i]);

    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    vector<double> output;
    encoder.decode(plain_result, output);

    cout << "Self-improvement convolution result: ";
    for (double val : output) cout << val << " ";
    cout << endl;
    return 0;
}
