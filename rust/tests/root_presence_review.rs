use agent_bus::presence::round1_py;

#[test]
fn decimal_rounding_respects_the_original_binary_value() {
    // 1.15 is stored below the exact decimal midpoint 23/20. Multiplying
    // by ten rounds again and incorrectly turns it into an exact tie.
    let below = 1.15_f64;
    let numerator = ((1_u64 << 52) | (below.to_bits() & ((1_u64 << 52) - 1))) as u128;
    assert!(numerator * 20 < 23_u128 * (1_u128 << 52));
    // 2.45 is stored above 49/20 (binary exponent one).
    let above = 2.45_f64;
    let numerator = ((1_u64 << 52) | (above.to_bits() & ((1_u64 << 52) - 1))) as u128;
    assert!(numerator * 20 > 49_u128 * (1_u128 << 51));

    let inputs = [1.15, 2.45, -1.15, -2.45, 1.25, 2.25, 1.75];
    let actual: Vec<_> = inputs.into_iter().map(round1_py).collect();
    assert_eq!(actual, [1.1, 2.5, -1.1, -2.5, 1.2, 2.2, 1.8]);
}

#[test]
fn finite_large_ages_remain_finite_during_rounding() {
    assert_eq!(round1_py(1e308), 1e308);
    assert_eq!(round1_py(-1e308), -1e308);
}

#[test]
fn finite_clocks_with_overflowing_difference_do_not_emit_null_age() {
    let mut presence = agent_bus::presence::PresenceStore::new();
    assert!(presence.touch("worker", Some("active"), -1e308, "test"));
    assert!(presence.agents_snapshot(1e308).is_none());
}

#[test]
fn rounding_preserves_negative_zero() {
    assert_eq!(round1_py(-0.01).to_bits(), (-0.0_f64).to_bits());
}
