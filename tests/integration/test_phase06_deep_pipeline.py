from role_radar.deep_evaluation.policy import calculate_adjustment


def test_adjustment_is_code_owned_and_bounded() -> None:
    assert calculate_adjustment(10, 100, 15) == (15, 25)
    assert calculate_adjustment(95, 0, 15) == (-15, 80)
