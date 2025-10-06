#!/usr/bin/env python3
"""
QKD Vendor Driver Registrar

Dynamically registers new QKD vendor drivers in the registry.

Usage: python tools/qkd_register_vendor.py <vendor_name> <driver_class_path> [--demo]

Example: python tools/qkd_register_vendor.py new_vendor src.qkd.hardware_driver.NewVendorDriver
"""

import json
import argparse
import sys
from pathlib import Path

REGISTRY_FILE = Path("src/qkd/registry.json")

def register_vendor(vendor_name: str, driver_class: str):
    """Add new vendor to registry."""
    with open(REGISTRY_FILE, 'r') as f:
        registry = json.load(f)

    if vendor_name in registry['qkd_drivers']:
        print(f"Vendor {vendor_name} already registered.")
        return False

    registry['qkd_drivers'][vendor_name] = driver_class

    with open(REGISTRY_FILE, 'w') as f:
        json.dump(registry, f, indent=2)

    print(f"Registered vendor {vendor_name} with driver {driver_class}")
    return True

def demo_registration():
    """Demo registrations for acceptance criteria."""
    # Simulate logs
    print("Demo: Registering Huawei QKD driver...")
    register_vendor("huawei", "src.qkd.hardware_driver.HuaweiQKDDriver")
    print("Demo: Registering QuantumXchange Phio driver...")
    register_vendor("quantumxchange_phio", "src.qkd.hardware_driver.QuantumXchangePhioDriver")
    print("Demo: Running registry.json update completed.")

def main():
    parser = argparse.ArgumentParser(description="Register QKD vendor drivers")
    parser.add_argument('vendor_name', nargs='?', help='Name of the vendor')
    parser.add_argument('driver_class', nargs='?', help='Full path to driver class')
    parser.add_argument('--demo', action='store_true', help='Run demo registrations')

    args = parser.parse_args()

    if args.demo:
        demo_registration()
        return

    if not args.vendor_name or not args.driver_class:
        print("Error: vendor_name and driver_class required unless using --demo")
        sys.exit(1)

    register_vendor(args.vendor_name, args.driver_class)

if __name__ == '__main__':
    main()
