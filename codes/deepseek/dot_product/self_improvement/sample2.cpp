#include <seal/seal.h>
#include <vector>
#include <numeric>
#include <chrono>
#include <memory>
#include <map>
#include <iostream>
#include <stdexcept>
using namespace seal;
using namespace std;
using namespace chrono;

class SelfImprovingDotProduct {
    enum Method { BASIC, BATCH, PARALLEL, MEMORY_EFFICIENT };
    
    struct PerformanceProfile {
        map<size_t, Method> size_to_method;
        double last_improvement_time;
        size_t batch_threshold;
        size_t parallel_threshold;
    };
    
    unique_ptr<SEALContext> context;
    shared_ptr<PerformanceProfile> profile;
    PublicKey public_key;
    SecretKey secret_key;
    RelinKeys relin_keys;
    
    void initialize_seal() {
        EncryptionParameters parms(scheme_type::ckks);
        parms.set_poly_modulus_degree(8192);
        parms.set_coeff_modulus(CoeffModulus::Create(8192, {50, 30, 50}));
        
        context = make_unique<SEALContext>(parms);
        KeyGenerator keygen(*context);
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);
    }
    
    Method select_method(size_t vector_size) {
        if (vector_size < profile->batch_threshold) return BASIC;
        if (vector_size < profile->parallel_threshold) return BATCH;
        return PARALLEL;
    }
    
    double execute_method(Method method, 
                         const vector<double>& vec1, 
                         const vector<double>& vec2) {
        CKKSEncoder encoder(*context);
        Encryptor encryptor(*context, public_key);
        Evaluator evaluator(*context);
        Decryptor decryptor(*context, secret_key);
        
        const double scale = pow(2.0, 30);
        
        switch(method) {
            case BASIC: {
                Plaintext plain1, plain2;
                encoder.encode(vec1, scale, plain1);
                encoder.encode(vec2, scale, plain2);
                
                Ciphertext encrypted1, encrypted2;
                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                
                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, relin_keys);
                
                Plaintext plain_result;
                decryptor.decrypt(encrypted1, plain_result);
                
                vector<double> result;
                encoder.decode(plain_result, result);
                return accumulate(result.begin(), result.end(), 0.0);
            }
            
            case BATCH: {
                size_t slot_count = encoder.slot_count();
                vector<double> padded1(slot_count), padded2(slot_count);
                copy(vec1.begin(), vec1.end(), padded1.begin());
                copy(vec2.begin(), vec2.end(), padded2.begin());
                
                Plaintext plain1, plain2;
                encoder.encode(padded1, scale, plain1);
                encoder.encode(padded2, scale, plain2);
                
                Ciphertext encrypted1, encrypted2;
                encryptor.encrypt(plain1, encrypted1);
                encryptor.encrypt(plain2, encrypted2);
                
                evaluator.multiply_inplace(encrypted1, encrypted2);
                evaluator.relinearize_inplace(encrypted1, relin_keys);
                
                Plaintext plain_result;
                decryptor.decrypt(encrypted1, plain_result);
                
                vector<double> full_result;
                encoder.decode(plain_result, full_result);
                return accumulate(full_result.begin(), 
                                full_result.begin() + min(vec1.size(), vec2.size()), 
                                0.0);
            }
            
            case PARALLEL: {
                const size_t chunk_size = 512;
                double total = 0.0;
                
                for (size_t i = 0; i < vec1.size(); i += chunk_size) {
                    size_t end = min(i + chunk_size, vec1.size());
                    vector<double> chunk1(vec1.begin() + i, vec1.begin() + end);
                    vector<double> chunk2(vec2.begin() + i, vec2.begin() + end);
                    
                    total += execute_method(BASIC, chunk1, chunk2);
                }
                return total;
            }
            
            default:
                throw logic_error("Unimplemented method");
        }
    }
    
    void update_profile(size_t vector_size, Method method, double exec_time) {
        const double learning_rate = 0.1;
        if (method == BATCH) {
            profile->batch_threshold = static_cast<size_t>(
                profile->batch_threshold * (1 - learning_rate) + 
                vector_size * learning_rate);
        }
        profile->last_improvement_time = duration_cast<seconds>(
            system_clock::now().time_since_epoch()).count();
    }
    
public:
    SelfImprovingDotProduct() {
        initialize_seal();
        profile = make_shared<PerformanceProfile>();
        profile->batch_threshold = 500;
        profile->parallel_threshold = 2000;
        profile->last_improvement_time = 0;
    }
    
    double compute(const vector<double>& vec1, const vector<double>& vec2) {
        if (vec1.size() != vec2.size()) {
            throw invalid_argument("Vectors must be same size");
        }
        
        auto start_time = high_resolution_clock::now();
        Method method = select_method(vec1.size());
        double result = execute_method(method, vec1, vec2);
        auto end_time = high_resolution_clock::now();
        
        double exec_time = duration_cast<milliseconds>(
            end_time - start_time).count();
        update_profile(vec1.size(), method, exec_time);
        
        return result;
    }
    
    void print_profile() const {
        cout << "Current profile:\n"
             << "  Batch threshold: " << profile->batch_threshold << "\n"
             << "  Parallel threshold: " << profile->parallel_threshold << "\n"
             << "  Last improved: " << profile->last_improvement_time << endl;
    }
};

int main() {
    SelfImprovingDotProduct dot_product;
    
    vector<double> vec1(1500, 1.5);
    vector<double> vec2(1500, 2.5);
    
    double result = dot_product.compute(vec1, vec2);
    cout << "Dot product result: " << result << endl;
    
    dot_product.print_profile();
    return 0;
}