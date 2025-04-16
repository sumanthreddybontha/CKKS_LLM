// 1D convolution (dot product on sliding window)
#include "seal/seal.h"
#include <iostream>
#include <numeric>

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
    vector<double> kernel = {0.2, 0.5, 0.3};

    // Encode
    Plaintext pt_input, pt_kernel;
    encoder.encode(input, scale, pt_input);
    encoder.encode(kernel, scale, pt_kernel);

    // Encrypt
    Ciphertext ct_input, ct_kernel;
    encryptor.encrypt(pt_input, ct_input);
    encryptor.encrypt(pt_kernel, ct_kernel);

    // Element-wise multiply (simulate 1D convolution)
    Ciphertext ct_mul;
    evaluator.multiply(ct_input, ct_kernel, ct_mul);

    // Decrypt & decode
    Plaintext pt_result;
    decryptor.decrypt(ct_mul, pt_result);
    vector<double> result;
    encoder.decode(pt_result, result);

    cout << "Decrypted convolution output: ";
    for (double r : result) cout << r << " ";
    cout << endl;
    return 0;
}
