"""Tests for the read-only network-device evidence contract."""

from __future__ import annotations

import unittest
from dataclasses import fields

from nightrecon.infrastructure_models import InfrastructureTransport
from nightrecon.infrastructure_network_device import (
    NetworkDeviceConnectionProfile,
    NetworkDeviceInterfaceObservation,
    NetworkDeviceInterfaceState,
    NetworkDeviceManagementProtocol,
    NetworkDeviceSystemObservation,
    build_network_device_interface_inventory_facts,
    build_network_device_system_identity_facts,
    supported_network_device_actions,
    validate_network_device_action,
)
from nightrecon.infrastructure_registry import (
    get_infrastructure_action_definition,
)


class NetworkDeviceEvidenceContractTests(unittest.TestCase):
    def test_profile_requires_bounded_verified_structured_management(self):
        profile = NetworkDeviceConnectionProfile(
            protocol=NetworkDeviceManagementProtocol.NETCONF_SSH,
            username="audit-user",
            port=830,
            connect_timeout=3.0,
            operation_timeout=4.0,
            max_interfaces=128,
            verify_host_identity=True,
        )

        self.assertEqual(profile.port, 830)
        self.assertTrue(profile.verify_host_identity)

        names = {item.name for item in fields(profile)}
        for forbidden in (
            "password",
            "secret",
            "command",
            "rpc",
            "configuration",
        ):
            self.assertNotIn(forbidden, names)

        for overrides in (
            {"port": 0},
            {"connect_timeout": 0},
            {"operation_timeout": 0},
            {"max_interfaces": 0},
            {"max_interfaces": 8193},
            {"verify_host_identity": False},
            {"username": "bad\nuser"},
        ):
            values = {
                "protocol": NetworkDeviceManagementProtocol.NETCONF_SSH,
                "username": "audit-user",
            }
            values.update(overrides)
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    NetworkDeviceConnectionProfile(**values)

    def test_action_allowlist_is_exact_and_registry_is_read_only(self):
        self.assertEqual(
            supported_network_device_actions(),
            (
                "network_device.system_identity",
                "network_device.interface_inventory",
            ),
        )
        self.assertEqual(
            validate_network_device_action(
                "network_device.system_identity"
            ),
            "network_device.system_identity",
        )

        for action_id in (
            "network_device.run_command",
            "network_device.get_configuration",
            "network_device.interface_inventory; reload",
            "",
        ):
            with self.subTest(action_id=action_id):
                with self.assertRaises(ValueError):
                    validate_network_device_action(action_id)

        for action_id in supported_network_device_actions():
            definition = get_infrastructure_action_definition(action_id)
            self.assertEqual(
                definition.transport,
                InfrastructureTransport.NETWORK_DEVICE,
            )
            self.assertFalse(definition.mutating)

    def test_system_identity_is_typed_bounded_and_deterministic(self):
        facts = build_network_device_system_identity_facts(
            NetworkDeviceSystemObservation(
                vendor="Example Networks",
                model="Edge-48",
                operating_system="ExampleOS",
                version="12.4.7",
            )
        )

        self.assertEqual(
            tuple((fact.key, fact.value) for fact in facts),
            (
                ("network_device.vendor", "Example Networks"),
                ("network_device.model", "Edge-48"),
                ("network_device.operating_system", "ExampleOS"),
                ("network_device.version", "12.4.7"),
            ),
        )

        with self.assertRaises(ValueError):
            build_network_device_system_identity_facts(
                NetworkDeviceSystemObservation(
                    vendor="Bad\nVendor",
                    model="Edge-48",
                    operating_system="ExampleOS",
                    version="12.4.7",
                )
            )

    def test_interface_inventory_is_sorted_bounded_and_typed(self):
        facts = build_network_device_interface_inventory_facts(
            (
                NetworkDeviceInterfaceObservation(
                    name="ge-0/0/2",
                    administrative_state=NetworkDeviceInterfaceState.DOWN,
                    operational_state=NetworkDeviceInterfaceState.DOWN,
                ),
                NetworkDeviceInterfaceObservation(
                    name="ge-0/0/1",
                    administrative_state=NetworkDeviceInterfaceState.UP,
                    operational_state=NetworkDeviceInterfaceState.UP,
                ),
            ),
            max_interfaces=4,
        )

        self.assertEqual(
            tuple((fact.key, fact.value) for fact in facts),
            (
                ("network_device.interface_count", "2"),
                ("network_device.interface_0001.name", "ge-0/0/1"),
                (
                    "network_device.interface_0001.administrative_state",
                    "up",
                ),
                (
                    "network_device.interface_0001.operational_state",
                    "up",
                ),
                ("network_device.interface_0002.name", "ge-0/0/2"),
                (
                    "network_device.interface_0002.administrative_state",
                    "down",
                ),
                (
                    "network_device.interface_0002.operational_state",
                    "down",
                ),
            ),
        )

    def test_interface_inventory_rejects_duplicates_invalid_values_and_overflow(self):
        valid = NetworkDeviceInterfaceObservation(
            name="Ethernet1/1",
            administrative_state=NetworkDeviceInterfaceState.UP,
            operational_state=NetworkDeviceInterfaceState.UNKNOWN,
        )

        with self.assertRaisesRegex(ValueError, "exceed"):
            build_network_device_interface_inventory_facts(
                (valid, valid),
                max_interfaces=1,
            )

        with self.assertRaisesRegex(ValueError, "Duplicate"):
            build_network_device_interface_inventory_facts(
                (
                    valid,
                    NetworkDeviceInterfaceObservation(
                        name="ethernet1/1",
                        administrative_state=NetworkDeviceInterfaceState.UP,
                        operational_state=NetworkDeviceInterfaceState.UP,
                    ),
                ),
                max_interfaces=2,
            )

        with self.assertRaisesRegex(ValueError, "name"):
            build_network_device_interface_inventory_facts(
                (
                    NetworkDeviceInterfaceObservation(
                        name="bad interface",
                        administrative_state=NetworkDeviceInterfaceState.UP,
                        operational_state=NetworkDeviceInterfaceState.UP,
                    ),
                ),
                max_interfaces=2,
            )

        with self.assertRaisesRegex(ValueError, "administrative"):
            build_network_device_interface_inventory_facts(
                (
                    NetworkDeviceInterfaceObservation(
                        name="Ethernet1/2",
                        administrative_state="up",
                        operational_state=NetworkDeviceInterfaceState.UP,
                    ),
                ),
                max_interfaces=2,
            )


if __name__ == "__main__":
    unittest.main()
