from app import run_command


def test_command_arguments_are_not_interpreted_by_a_shell() -> None:
    value = "hello;printf SHOULD_NOT_EXECUTE"
    assert run_command(value) == value
