from fortimanager_mcp import zone_map


def test_load_zone_map_file_not_found(tmp_path):
    result = zone_map.load_zone_map(tmp_path / "does_not_exist.yaml")
    assert result == {}


def test_load_zone_map_valid_file(tmp_path):
    f = tmp_path / "zone_map.yaml"
    f.write_text(
        "devices:\n"
        "  FGT-OT-01:\n"
        "    port3:\n"
        "      alias: OT_LAN\n"
        "      policy_zone: NSS OT-All\n"
        "      notes: ''\n"
    )
    result = zone_map.load_zone_map(f)
    assert result == {
        "FGT-OT-01": {
            "port3": {
                "alias": "OT_LAN",
                "policy_zone": "NSS OT-All",
                "notes": "",
            }
        }
    }


def test_lookup_policy_zone_found(tmp_path):
    zone_map_data = {
        "FGT-OT-01": {
            "port3": {"alias": "OT_LAN", "policy_zone": "NSS OT-All", "notes": ""}
        }
    }
    result = zone_map.lookup_policy_zone(zone_map_data, "FGT-OT-01", "port3")
    assert result == "NSS OT-All"


def test_lookup_policy_zone_device_missing():
    zone_map_data = {
        "FGT-OT-01": {
            "port3": {"alias": "OT_LAN", "policy_zone": "NSS OT-All", "notes": ""}
        }
    }
    result = zone_map.lookup_policy_zone(zone_map_data, "FGT-MISSING", "port3")
    assert result is None


def test_lookup_policy_zone_interface_missing():
    zone_map_data = {
        "FGT-OT-01": {
            "port3": {"alias": "OT_LAN", "policy_zone": "NSS OT-All", "notes": ""}
        }
    }
    result = zone_map.lookup_policy_zone(zone_map_data, "FGT-OT-01", "port99")
    assert result is None


def test_lookup_policy_zone_null_value():
    zone_map_data = {
        "FGT-OT-01": {
            "port4": {"alias": "IT_TRANSIT", "policy_zone": None, "notes": ""}
        }
    }
    result = zone_map.lookup_policy_zone(zone_map_data, "FGT-OT-01", "port4")
    assert result is None


def test_missing_entries_all_mapped():
    zone_map_data = {
        "FGT-OT-01": {
            "port3": {"alias": "OT_LAN", "policy_zone": "NSS OT-All", "notes": ""},
            "port4": {"alias": "IT_DMZ", "policy_zone": "NSS IT DMZ", "notes": ""},
        }
    }
    result = zone_map.missing_entries(zone_map_data, "FGT-OT-01", ["port3", "port4"])
    assert result == []


def test_missing_entries_some_missing():
    zone_map_data = {
        "FGT-OT-01": {
            "port3": {"alias": "OT_LAN", "policy_zone": "NSS OT-All", "notes": ""},
            "port4": {"alias": "IT_TRANSIT", "policy_zone": None, "notes": ""},
        }
    }
    result = zone_map.missing_entries(zone_map_data, "FGT-OT-01", ["port3", "port4", "port5"])
    assert set(result) == {"port4", "port5"}


def test_missing_entries_device_not_in_map():
    zone_map_data = {}
    result = zone_map.missing_entries(zone_map_data, "FGT-NOT-IN-MAP", ["port1", "port2"])
    assert set(result) == {"port1", "port2"}
