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
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    double scale = pow(2.0, 40);

    vector<double> input = {1.0, 2.0, 3.0};
    Plaintext pt_input;
    encoder.encode(input, scale, pt_input);
    Ciphertext ct_input;
    encryptor.encrypt(pt_input, ct_input);

    Ciphertext rotated;
    evaluator.rotate_vector(ct_input, 5, gal_keys, rotated); // Out-of-bounds rotate

    Plaintext pt_out;
    decryptor.decrypt(rotated, pt_out);
    vector<double> decoded;
    encoder.decode(pt_out, decoded);

    cout << "Rotated output: ";
    for (double d : decoded) cout << d << " ";
    cout << endl;

    return 0;
}
