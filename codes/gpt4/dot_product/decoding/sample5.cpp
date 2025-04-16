#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

void print_parameters(const SEALContext &context)
{
    auto &parms = context.key_context_data()->parms();
    cout << "Encryption parameters:" << endl;
    cout << "  Scheme: CKKS" << endl;
    cout << "  Poly modulus degree: " << parms.poly_modulus_degree() << endl;
    cout << "  Coeff modulus size: " 
         << context.key_context_data()->total_coeff_modulus_bit_count() << " bits" << endl;
}

int main() {
    size_t poly_modulus_degree = 8192;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;
    
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    vector<int> steps;
    for (int i = 0; i < 100; i++) 
        steps.push_back(i);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(steps, gal_keys);
    
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    
    const int rows = 10, cols = 10, kernel_size = 3;
    double scale = pow(2.0, 40);
    vector<double> matrix(rows * cols, 1.0);
    vector<double> kernel(kernel_size * kernel_size, 0.5);
    
    Plaintext plain_matrix;
    encoder.encode(matrix, scale, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    
    // Process each row of the kernel window separately:
    Ciphertext conv_result;
    bool first = true;
    for (int krow = 0; krow < kernel_size; ++krow)
    {
        // Rotate to align the beginning of row (for window starting at row 0)
        int row_offset = krow * cols;
        Ciphertext row_rotated;
        evaluator.rotate_vector(encrypted_matrix, row_offset, gal_keys, row_rotated);
        
        // Compute the dot product for this row using the kernel values.
        Ciphertext row_result;
        bool row_first = true;
        for (int kcol = 0; kcol < kernel_size; ++kcol)
        {
            // Further rotate by the column offset.
            Ciphertext cell;
            evaluator.rotate_vector(row_rotated, kcol, gal_keys, cell);
            Plaintext plain_weight;
            encoder.encode(kernel[krow * kernel_size + kcol], scale, plain_weight);
            evaluator.multiply_plain_inplace(cell, plain_weight);
            evaluator.rescale_to_next_inplace(cell);
            if (row_first) {
                row_result = cell;
                row_first = false;
            } else {
                evaluator.mod_switch_to_inplace(row_result, cell.parms_id());
                evaluator.add_inplace(row_result, cell);
            }
        }
        // Sum the row results to form the full window dot product.
        if (first)
        {
            conv_result = row_result;
            first = false;
        } else {
            evaluator.mod_switch_to_inplace(conv_result, row_result.parms_id());
            evaluator.add_inplace(conv_result, row_result);
        }
    }
    
    // Decrypt and decode the result.
    Plaintext plain_result;
    vector<double> result_vector;
    decryptor.decrypt(conv_result, plain_result);
    encoder.decode(plain_result, result_vector);
    cout << "Variant 4 - First 3x3 Dot Product Result: " << result_vector[0] << endl;
    
    return 0;
}