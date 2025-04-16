// Rotation-Based Accumulation
#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <sstream>

using namespace std;
using namespace seal;

int main() {
    // CKKS parameter setup
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    KeyGenerator keygen(context);

    // Serialize and load public key
    Serializable<PublicKey> public_key_serial = keygen.create_public_key();
    PublicKey public_key;
    std::stringstream public_key_stream;
    public_key_serial.save(public_key_stream);
    public_key.load(context, public_key_stream);

    SecretKey secret_key = keygen.secret_key();

    // Serialize and load Galois keys
    Serializable<GaloisKeys> galois_keys_serial = keygen.create_galois_keys();
    GaloisKeys galois_keys;
    std::stringstream galois_key_stream;
    galois_keys_serial.save(galois_key_stream);
    galois_keys.load(context, galois_key_stream);

    // Serialize and load Relin

}