#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

void print_context_data(shared_ptr<SEALContext> context)
{
    auto context_data = context->first_context_data();
    cout << "Encryption parameters:" << endl;
    cout << "  poly_modulus_degree: " << context_data->parms().poly_modulus_degree() << endl;
    cout << "  coeff_modulus size: ";
    for (const auto &q : context_data->parms().coeff_modulus())
    {
        cout << log2(q.value()) << " ";
    }
    cout << "(bits)" << endl;
    cout << "------------------------------------------------------" << endl;
}

int main()
{
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {50, 40, 40}));

    auto context = make_shared<SEALContext>(parms, true, sec_level_type::tc128);

    if (!context->parameters_set())
    {
        cout << "❌ ERROR: Invalid encryption parameters." << endl;
        return 1;
    }

    print_context_data(context);

    auto coeff_modulus = context->first_context_data()->parms().coeff_modulus();
    cout << "\n🔍 Actual coeff_modulus sizes (bits): ";
    for (const auto &q : coeff_modulus)
    {
        cout << log2(q.value()) << " ";
    }
    cout << endl;

    KeyGenerator keygen(*context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    CKKSEncoder encoder(*context);
    Encryptor encryptor(*context, public_key);
    Evaluator evaluator(*context);
    Decryptor decryptor(*context, secret_key);

    vector<double> input = {1.0, 2.0, 3.0};
    Plaintext plain;
    double scale = pow(2.0, 40);
    encoder.encode(input, scale, plain);

    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    cout << "\nInitial noise budget: " << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    cout << "Initial modulus level: " << context->get_context_data(encrypted.parms_id())->chain_index() << endl;

    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted);

    cout << "\nAfter square + rescale:" << endl;
    cout << "Noise budget: " << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    cout << "Modulus level: " << context->get_context_data(encrypted.parms_id())->chain_index() << endl;

    evaluator.mod_switch_to_next_inplace(encrypted);

    cout << "\nAfter explicit modulus switch:" << endl;
    cout << "Noise budget: " << decryptor.invariant_noise_budget(encrypted) << " bits" << endl;
    cout << "Modulus level: " << context->get_context_data(encrypted.parms_id())->chain_index() << endl;

    Plaintext decrypted_result;
    decryptor.decrypt(encrypted, decrypted_result);
    vector<double> result;
    encoder.decode(decrypted_result, result);

    cout << "\nDecrypted result: ";
    for (double val : result)
    {
        cout << val << " ";
    }
    cout << endl;

    return 0;
}
