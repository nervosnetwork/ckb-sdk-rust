use crate::unlock::SphincsPlusPrivateKey;

#[test]
fn test_sphincplus_sk() {
    let sk = SphincsPlusPrivateKey::new();
    assert!(sk.is_ok());
    assert!(sk.unwrap().is_valid().is_ok());
}
