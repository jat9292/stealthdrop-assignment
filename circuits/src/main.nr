global CANDIDATES: Field = 2;

use dep::std;
use dep::ecrecover;

fn main(
  pub_key: [u8; 64],
  signature: [u8; 64],
  hashed_message: pub [u8; 32],
  polynomial: [Field; CANDIDATES + 1],
  polynomial_commitment: pub Field, // made commitment public, to avoid submitting invalid proofs by modifying the polynomial, this parameter will be checked in the smart contract
  nullifier: pub [u8; 32],
  recipient_address_priv: Field,
  recipient_address: pub Field // added recipient address as a public variable to avoid front-running issue, this parameter is also used in the smart contract when sending the airdrop
) {
  // Recover the signer's address from signature, hashed message and public key.
  let key = ecrecover::secp256k1::PubKey::from_unified(pub_key);
  let address = ecrecover::ecrecover(key.pub_x, key.pub_y, signature, hashed_message); // this will correctly fail if signature of hash(message) is invalid, notice that Noir's ECERecover variant is limited because it requires the public key at the moment, for performance

  // Check whether the address is included in the polynomial
  let result = evaluate_polynomial(polynomial,address);
  assert(result==0);

  //Check the given nullifier is a valid hash of signature
  let hash_signature = std::hash::blake2s(signature);
  assert(hash_signature==nullifier); // /!\ WARNING /!\ : vulnerable to ECDSA malleability, see https://twitter.com/zpedrongmi/status/1668629099903070208

  // Check that the hash of the polynomial is the same as the public polynomial hash provided
  let polynomial_hash = std::hash::pedersen(polynomial)[0];
  assert(polynomial_hash==polynomial_commitment);

  // To avoid front-running issue we must add a constraint on the recipient address
  assert(recipient_address == recipient_address_priv); // technically this line is no longer required in newer versions of Noir (but still required in Noir 0.7.1), contrarily to Circom, will always add one constraint for each input, even if unused. However, this line has no impact on complexity of the compiled circuit and improves readability while also muting some warnings about unused variable during compilation, so I decided to keep it
}

fn evaluate_polynomial(polynomial: [Field; CANDIDATES + 1], x: Field) -> Field {
  // Write logic to evaluate polynomial here
  let mut mult: Field = 1;
  let mut evaluation: Field = 0;
  for idx in 0..CANDIDATES+1{
    evaluation = mult * polynomial[idx] + evaluation;
    mult = mult * x;
  }
  evaluation
}

#[test]
fn test_main() {
  let pub_key = [131,  24,  83,  91,  84,  16,  93,  74,  122,  174,  96,  192,  143,  196,  95,  150,  135,  24,  27,  79,  223,  198,  37,  189,  26,  117,  63,  167,  57,  127,  237,  117,  53,  71,  241,  28,  168,  105,  102,  70,  242,  243,  172,  176,  142,  49,  1,  106,  250,  194,  62,  99,  12,  93,  17,  245,  159,  97,  254,  245,  123,  13,  42,  165];
  let signature = [1,  83,  82,  167,  184,  77,  226,  104,  5,  27,  151,  91,  202,  127,  17,  183,  75,  31,  190,  253,  159,  116,  155,  13,  24,  178,  40,  165,  129,  90,  103,  204,  42,  164,  230,  62,  73,  181,  169,  61,  251,  221,  128,  221,  14,  19,  179,  25,  107,  132,  10,  188,  149,  0,  197,  52,  151,  239,  244,  103,  215,  224,  56,  242];

  let hashed_message = [3,  57, 199, 96, 145, 58, 183, 241, 206, 140, 36, 34, 165, 163, 17, 210, 97, 254, 154, 79, 91, 223, 149, 18, 3, 210, 111, 56, 246, 219, 19, 104];

  let polynomial = [
    0x0832c9fedf291cc3adf56eefd21ac09630c66ad67747329385c9fcfc7cbf8d38,
    0x30644e72e131a029b85045b51d480807486e4c754ae9f95bbfba6db6d86a63d3,
    0x01
  ];

  let polynomial_commitment = 0x1eceef64088bbbeb280bee01b3f4e611137e8d0ac5a868f538e4617df5c62ec2;
  let nullifier = [142,  197,  227,  35,  35,  142,  255,  176,  38,  63,  247,  168,  33,  178,  55,  202,  46,  76,  167,  202,  130,  208,  59,  14,  151,  19,  144,  228,  58,  37,  10,  101];
  let recipient_address = 0x4f5F14AF7E1999fa09dD0CEa786B82B4Fc4B9910;
  main(pub_key, signature, hashed_message, polynomial, polynomial_commitment, nullifier,recipient_address,recipient_address);
}

