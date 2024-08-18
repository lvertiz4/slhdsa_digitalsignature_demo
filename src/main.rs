use slh_dsa::*;
use signature::*;

fn main() {
    //Get a random number
    let mut rng = rand::thread_rng();
    
    //Generate a signing key using the SHAKE128f parameter set. The 'new' method created a new SigningKey struct from a cyrptographic random number generator. 
    //The SLH-DSA crate uses the Rand crate's CryptoRngCore trait to show the input to the 'new' function must be a type that implements Rand's CryptoRng trait to indicate this data type is cryptographically secure 
    let signing_key = SigningKey::<Shake128f>::new(&mut rng);
    
    //Generat the corresponding public key. The public key is used for used to verify digital signatures because it derives from the private key
    //In the SLH-DSA standard, the private key is a lattice-based cryptographic scheme where secret vectors or polynomials for the basis of the lattice
    //For the public key,  public key is derived from the private key through a process involving lattice construction and matrix formation from private key's vectors or polynomials.
    //The public key's lattice structre is used to verify signatures from the private key, while deriving private keys from the public keys is NP-hard - computational infeasible 
    let verifying_key = signing_key.verifying_key();
    
    //Serialize the public key and distribute
    let verifying_key_bytes = verifying_key.to_bytes();
    
    //Sign a message with the private key
    let message = "I Love Somi".as_bytes();
    let signed_message = signing_key.sign_with_rng(&mut rng, message);

    //Deserialize (i.e. return from a stream of bytes to a data object like a String) an encoded message with a verifying key
    let deserialize_message = verifying_key_bytes.try_into().unwrap();

    //Recall that the asserteq! and assert! macro will invoke the panic macro if the provided expression cannot be evaluated to true at runtime.
    assert_eq!(verifying_key, deserialize_message);

    assert!(deserialize_message.verify(message, &signed_message).is_ok())

}