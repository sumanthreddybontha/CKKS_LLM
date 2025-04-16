// Version 4
#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(16384);
    parms.set_coeff_modulus(CoeffModulus::Create(16384, {60, 40, 40, 60}));
    double scale = pow(2.0, 40);
    SEALContext context(parms);

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();
    auto relin_keys = keygen.relin_keys();

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    // Matrix and kernel
    vector<double> matrix(100);
    iota(matrix.begin(), matrix.end(), 1);
    vector<double> kernel(9, 1.0); // All-ones kernel (mean filter)

    Plaintext pt_kernel;
    encoder.encode(kernel, scale, pt_kernel);

    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            vector<double> patch;
            for (int r = 0; r < 3; ++r)
                for (int c = 0; c < 3; ++c)
                    patch.push_back(matrix[(i + r) * 10 + (j + c)]);

            Plaintext pt_patch;
            encoder.encode(patch, scale, pt_patch);
            Ciphertext ct;
            encryptor.encrypt(pt_patch, ct);

            evaluator.multiply_plain_inplace(ct, pt_kernel);
            evaluator.relinearize_inplace(ct, relin_keys);
            evaluator.rescale_to_next_inplace(ct);

            Plaintext pt_out;
            decryptor.decrypt(ct, pt_out);
            vector<double> decoded;
            encoder.decode(pt_out, decoded);
            double sum = accumulate(decoded.begin(), decoded.end(), 0.0);
            cout << "Sum: " << sum << endl;
        }
    }

    return 0;
}