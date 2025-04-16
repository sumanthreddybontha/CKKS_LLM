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

    Encryptor encryptor(context, pub_key);
    Decryptor decryptor(context, sec_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = pow(2.0, 40);
    vector<double> input = {4.0, 8.0, 12.0};

    Plaintext pt_input;
    encoder.encode(input, scale, pt_input);
    Ciphertext ct_input;
    encryptor.encrypt(pt_input, ct_input);

    Plaintext kernel_center;
    encoder.encode(1.0, scale, kernel_center);
    evaluator.multiply_plain_inplace(ct_input, kernel_center);
    evaluator.rescale_to_next_inplace(ct_input);

    Plaintext plain_result;
    decryptor.decrypt(ct_input, plain_result);
    vector<double> output;
    encoder.decode(plain_result, output);

    cout << "Identity (center-only) output: ";
    for (double val : output) cout << val << " ";
    cout << endl;
    return 0;
}
