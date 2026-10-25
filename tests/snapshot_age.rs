//! The product's snapshot age limit is defined relative to the issuer's day rounding.

#[test]
fn the_product_snapshot_age_limit_is_two_issuer_days() {
    assert_eq!(cchr::MAXIMUM_SNAPSHOT_AGE, 2 * cplc::DAY);
}
