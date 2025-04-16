#include <seal/seal.h>
#include <vector>  // Need to include vector header
using namespace seal;

int main() {
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
    
    SEALContext context(parms);
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    
    std::vector<double> input{1.1, 2.2}, input2{3.3, 4.4};  // Added std::
    Plaintext plain1, plain2;
    encoder.encode(input, pow(2.0, 40), plain1);  // Fixed input1 to input
    encoder.encode(input2, pow(2.0, 40), plain2);
    
    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    
    std::cout << "Pre-add level: " << encrypted1.coeff_modulus_size()-1 << std::endl;
    evaluator.mod_switch_to_next_inplace(encrypted1);
    evaluator.add_inplace(encrypted1, encrypted2);
    std::cout << "Post-add level: " << encrypted1.coeff_modulus_size()-1 << std::endl;
    
    Decryptor decryptor(context, secret_key);
    Plaintext plain_result;
    decryptor.decrypt(encrypted1, plain_result);
    
    return 0;
}