#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey public_key;
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    GaloisKeys gal_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    double scale = pow(2.0, 40);

    vector<double> A = {1.0, 2.0, 3.0, 4.0}; // A: [1 2; 3 4]
    vector<double> B = {5.0, 6.0, 7.0, 8.0}; // B: [5 6; 7 8]

    Plaintext pA, pB;
    encoder.encode(A, scale, pA);
    encoder.encode(B, scale, pB);

    Ciphertext cA, cB;
    encryptor.encrypt(pA, cA);
    encryptor.encrypt(pB, cB);

    // Matrix multiplication manually
    // c00 = a00*b00 + a01*b10
    // c01 = a00*b01 + a01*b11
    // c10 = a10*b00 + a11*b10
    // c11 = a10*b01 + a11*b11

    // We can just encode and encrypt the elements individually for full control
    vector<double> a = {1.0}, b = {2.0}, c = {3.0}, d = {4.0};
    vector<double> e = {5.0}, f = {6.0}, g = {7.0}, h = {8.0};

    Plaintext pa, pb, pc, pd, pe, pf, pg, ph;
    encoder.encode(a, scale, pa); encoder.encode(b, scale, pb);
    encoder.encode(c, scale, pc); encoder.encode(d, scale, pd);
    encoder.encode(e, scale, pe); encoder.encode(f, scale, pf);
    encoder.encode(g, scale, pg); encoder.encode(h, scale, ph);

    Ciphertext ca, cb, cc, cd;
    encryptor.encrypt(pa, ca); encryptor.encrypt(pb, cb);
    encryptor.encrypt(pc, cc); encryptor.encrypt(pd, cd);

    Ciphertext c00, c01, c10, c11, temp1, temp2;

    // c00 = a*e + b*g
    evaluator.multiply_plain(ca, pe, c00);
    evaluator.multiply_plain(cb, pg, temp1);
    evaluator.add_inplace(c00, temp1);

    // c01 = a*f + b*h
    evaluator.multiply_plain(ca, pf, c01);
    evaluator.multiply_plain(cb, ph, temp1);
    evaluator.add_inplace(c01, temp1);

    // c10 = c*e + d*g
    evaluator.multiply_plain(cc, pe, c10);
    evaluator.multiply_plain(cd, pg, temp1);
    evaluator.add_inplace(c10, temp1);

    // c11 = c*f + d*h
    evaluator.multiply_plain(cc, pf, c11);
    evaluator.multiply_plain(cd, ph, temp1);
    evaluator.add_inplace(c11, temp1);

    Plaintext r00, r01, r10, r11;
    vector<double> v00, v01, v10, v11;
    decryptor.decrypt(c00, r00); encoder.decode(r00, v00);
    decryptor.decrypt(c01, r01); encoder.decode(r01, v01);
    decryptor.decrypt(c10, r10); encoder.decode(r10, v10);
    decryptor.decrypt(c11, r11); encoder.decode(r11, v11);

    cout << "Matrix C = A x B:" << endl;
    cout << v00[0] << " " << v01[0] << endl;
    cout << v10[0] << " " << v11[0] << endl;

    return 0;
}