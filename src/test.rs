use test::Bencher;
use bulletproofs::{PedersenGens, BulletproofGens, RangeProof};

/// see https://doc.dalek.rs/bulletproofs/index.html
#[test]
fn test_bulletproofs_example(b: &Bencher) {
  let pc_gens = PedersenGens::default();
  let bp_gens = BulletproofGens::new(64, 1);
  let secret_value = 1037578891u64;
  let blinding = Scalar::random(&mut thread_rng());
  let mut prover_transcript = Transcript::new(b"doctest example");
  let (proof, committed_value) = RangeProof::prove_single(
    &bp_gens,
    &pc_gens,
    &mut prover_transcript,
    secret_value,
    &blinding,
    32,
  ).expect("A real program could handle errors");
  let mut verifier_transcript = Transcript::new(b"doctest example");
  assert!(
    proof
      .verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_value, 32)
      .is_ok()
  );
}