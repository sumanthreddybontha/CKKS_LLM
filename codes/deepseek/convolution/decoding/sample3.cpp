#include <iostream>
#include <vector>
#include <seal/seal.h>

using namespace std;
using namespace seal;

vector<double> reference_convolution(const vector<double>& a, const vector<double>& b) {
    size_t n = a.size(), m = b.size();
    vector<double> result(n + m - 1, 0.0);
    for (size_t i = 0; i < n; ++i)
        for (size_t j = 0; j < m; ++j)
            result[i + j] += a[i] * b[j];
    return result;
}

int main() {
    cout << "CKKS Convolution via Rotation\n";

    // Parameter setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 30, 30, 50}));

    SEALContext context(parms);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Slots available: " << slot_count << endl;

    // Key generation
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // Prepare data
    vector<double> vec1{1.0, 2.0, 3.0, 4.0}, vec2{0.5, 0.25, 0.125, 0.0625};
    vec1.resize(slot_count / 2, 0.0);
    vec2.resize(slot_count / 2, 0.0);

    Plaintext pt1, pt2;
    encoder.encode(vec1, pow(2.0, 40), pt1);
    encoder.encode(vec2, pow(2.0, 40), pt2);

    Ciphertext ct1, ct2;
    encryptor.encrypt(pt1, ct1);
    encryptor.encrypt(pt2, ct2);

    // Convolution via rotation and multiplication
    Ciphertext conv_result;
    evaluator.multiply(ct1, ct2, conv_result);
    evaluator.relinearize_inplace(conv_result, relin_keys);
    evaluator.rescale_to_next_inplace(conv_result);

    // Decrypt and compare
    Plaintext pt_result;
    decryptor.decrypt(conv_result, pt_result);
    vector<double> result;
    encoder.decode(pt_result, result);
    result.resize(7); // 4+4-1=7

    auto expected = reference_convolution(
        vector<double>{1.0, 2.0, 3.0, 4.0},
        vector<double>{0.5, 0.25, 0.125, 0.0625}
    );

    cout << "Expected: ";
    for (auto v : expected) cout << v << " ";
    cout << "\nActual:   ";
    for (size_t i = 0; i < expected.size(); ++i) cout << result[i] << " ";
    cout << endl;

    return 0;
}