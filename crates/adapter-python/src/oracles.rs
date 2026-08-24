use edsa_adapter_sdk::Oracle;
use edsa_core::OracleKind;

#[must_use]
pub fn vulnerability_marker() -> Oracle {
    Oracle {
        kind: OracleKind::StdoutPattern,
        expected: "EDSA_VULNERABLE".into(),
    }
}

#[must_use]
pub fn clean_control_marker() -> Oracle {
    Oracle {
        kind: OracleKind::StdoutPattern,
        expected: "EDSA_CONTROL_CLEAN".into(),
    }
}

#[must_use]
pub fn pytest_passed() -> Oracle {
    Oracle {
        kind: OracleKind::ExitCode,
        expected: "0".into(),
    }
}
