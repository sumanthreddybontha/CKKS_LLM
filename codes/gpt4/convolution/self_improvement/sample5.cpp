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
    vector<double> input = {5.0, 7.0, 11.0};
    vector<double> kernel = {0.2, 0.3, 0.5};

    Plaintext pt_input;
    encoder.encode(input, scale, pt_input);
    Ciphertext ct_input;
    encryptor.encrypt(pt_input, ct_input);

    vector<Ciphertext> rotated(3);
    evaluator.rotate_vector(ct_input, -1, gal_keys, rotated[0]);
    rotated[1] = ct_input;
    evaluator.rotate_vector(ct_input, 1, gal_keys, rotated[2]);

    vector<Ciphertext> products(3);
    for (int i = 0; i < 3; ++i) {
        Plaintext k_plain;
        encoder.encode(kernel[i], scale, k_plain);
        evaluator.multiply_plain(rotated[i], k_plain, products[i]);
        evaluator.rescale_to_next_inplace(products[i]);
        if (i > 0)
            evaluator.mod_switch_to_inplace(products[i], products[0].parms_id());
    }

    Ciphertext result = products[0];
    evaluator.add_inplace(result, products[1]);
    evaluator.add_inplace(result, products[2]);

    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);
    vector<double> output;
    encoder.decode(plain_result, output);

    cout << "Cached rotation output: ";
    for (double val : output) cout << val << " ";
    cout << endl;
    return 0;
}
