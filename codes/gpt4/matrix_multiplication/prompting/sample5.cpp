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
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    double scale = pow(2.0, 40);

    /*
     Matrix A = [1 2
                 3 4]
     Matrix B = [5  6
                 7  8]
    */

    // Encode each row of A
    Plaintext plain_row1_A, plain_row2_A;
    encoder.encode(vector<double>{1.0, 2.0}, scale, plain_row1_A);
    encoder.encode(vector<double>{3.0, 4.0}, scale, plain_row2_A);

    // Encode each column of B as a row vector (to align slots)
    Plaintext plain_col1_B, plain_col2_B;
    encoder.encode(vector<double>{5.0, 7.0}, scale, plain_col1_B); // B column 1
    encoder.encode(vector<double>{6.0, 8.0}, scale, plain_col2_B); // B column 2

    // Encrypt
    Ciphertext enc_row1_A, enc_row2_A, enc_col1_B, enc_col2_B;
    encryptor.encrypt(plain_row1_A, enc_row1_A);
    encryptor.encrypt(plain_row2_A, enc_row2_A);
    encryptor.encrypt(plain_col1_B, enc_col1_B);
    encryptor.encrypt(plain_col2_B, enc_col2_B);

    // Multiply corresponding rows and columns element-wise
    Ciphertext dot11, dot12, dot21, dot22;
    evaluator.multiply(enc_row1_A, enc_col1_B, dot11);
    evaluator.multiply(enc_row1_A, enc_col2_B, dot12);
    evaluator.multiply(enc_row2_A, enc_col1_B, dot21);
    evaluator.multiply(enc_row2_A, enc_col2_B, dot22);

    evaluator.rescale_to_next_inplace(dot11);
    evaluator.rescale_to_next_inplace(dot12);
    evaluator.rescale_to_next_inplace(dot21);
    evaluator.rescale_to_next_inplace(dot22);

    // Decode and sum the elements manually (2 elements each)
    Plaintext r11, r12, r21, r22;
    vector<double> v11, v12, v21, v22;

    decryptor.decrypt(dot11, r11); encoder.decode(r11, v11);
    decryptor.decrypt(dot12, r12); encoder.decode(r12, v12);
    decryptor.decrypt(dot21, r21); encoder.decode(r21, v21);
    decryptor.decrypt(dot22, r22); encoder.decode(r22, v22);

    cout << "Result Matrix C = A x B:" << endl;
    cout << (v11[0] + v11[1]) << " " << (v12[0] + v12[1]) << endl;
    cout << (v21[0] + v21[1]) << " " << (v22[0] + v22[1]) << endl;

    return 0;
}