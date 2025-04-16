#include <seal/seal.h>
#include <iostream>
#include <vector>
#include <numeric>
#include <cmath>
using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey pub_key;
    keygen.create_public_key(pub_key);
    SecretKey sec_key = keygen.secret_key();
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, pub_key);
    Decryptor decryptor(context, sec_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);
    vector<double> input = {4.0, 8.0, 4.0};
    vector<double> kernel = {1.0, 2.0, 1.0};

    // Normalize kernel
    double sum = accumulate(kernel.begin(), kernel.end(), 0.0);
    for (auto &w : kernel) w /= sum;

    Plaintext pt_input;
    encoder.encode(input, scale, pt_input);
    Ciphertext ct_input;
    encryptor.encrypt(pt_input, ct_input);

    vector<Ciphertext> parts(3);
    parms_id_type base_pid;

    for (int i = 0; i < 3; i++) {
        Ciphertext rotated;
        int shift = i - 1;
        if (shift != 0)
            evaluator.rotate_vector(ct_input, shift, gal_keys, rotated);
        else
            rotated = ct_input;

        Plaintext k_plain;
        encoder.encode(kernel[i], scale, k_plain);
        evaluator.multiply_plain(rotated, k_plain, parts[i]);
        evaluator.rescale_to_next_inplace(parts[i]);

        if (i == 0) base_pid = parts[0].parms_id();
        else evaluator.mod_switch_to_inplace(parts[i], base_pid);
    }

    Ciphertext result = parts[0];
    evaluator.add_inplace(result, parts[1]);
    evaluator.add_inplace(result, parts[2]);

    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    vector<double> output;
    encoder.decode(plain_result, output);

    cout << "Normalized convolution output: ";
    for (double val : output) cout << val << " ";
    cout << endl;
    return 0;
}
