// Element-wise multiply (single convolution window)
#include "seal/seal.h"
#include <iostream>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey pk; keygen.create_public_key(pk);
    SecretKey sk = keygen.secret_key();
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, sk);
    CKKSEncoder encoder(context);
    Evaluator evaluator(context);
    double scale = pow(2.0, 40);

    vector<double> input = {1.0, 2.0, 3.0};
    vector<double> kernel = {0.5, 1.0, -1.0};

    Plaintext pt_input, pt_kernel;
    encoder.encode(input, scale, pt_input);
    encoder.encode(kernel, scale, pt_kernel);

    Ciphertext ct_input, ct_kernel;
    encryptor.encrypt(pt_input, ct_input);
    encryptor.encrypt(pt_kernel, ct_kernel);

    Ciphertext ct_result;
    evaluator.multiply(ct_input, ct_kernel, ct_result);

    Plaintext pt_result;
    decryptor.decrypt(ct_result, pt_result);
    vector<double> result;
    encoder.decode(pt_result, result);

    cout << "Decrypted convolution output: ";
    for (auto r : result) cout << r << " ";
    cout << endl;

    return 0;
}
