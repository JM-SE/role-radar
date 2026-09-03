from role_radar.evaluation.profile_relevant_acquisition.acquisition_runtime import (
    SyntheticTransport,
)


def test_existing_gate_d_offline_delegate_remains_concrete_synthetic() -> None:
    delegate = SyntheticTransport()
    assert type(delegate) is SyntheticTransport
    assert delegate.calls == 0
