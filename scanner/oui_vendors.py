"""
oui_vendors.py — offline MAC-prefix-to-vendor lookup.

This is a curated subset covering vendors that commonly show up on a home network
(phones, laptops, smart home, streaming, gaming) — NOT the full IEEE OUI registry, which
has 40,000+ entries and would be overkill here. Anything not in this table just comes
back as None, which the caller falls back to hostname-only display for.

To extend: add more "xx:xx:xx": "Vendor Name" entries below. The full public registry,
if you ever want to expand this properly, is at https://standards-oui.ieee.org/
"""

_OUI_TABLE = {
    # Apple
    "3c:22:fb": "Apple", "ac:de:48": "Apple", "f0:18:98": "Apple", "a4:83:e7": "Apple",
    "00:1b:63": "Apple", "d0:e1:40": "Apple", "88:66:5a": "Apple", "5c:97:f3": "Apple",
    "dc:a4:ca": "Apple", "f4:5c:89": "Apple",
    # Samsung
    "00:12:47": "Samsung", "5c:0a:5b": "Samsung", "8c:79:67": "Samsung", "e8:50:8b": "Samsung",
    "34:23:87": "Samsung",
    # Amazon (Echo, Fire TV, Kindle, Ring)
    "fc:65:de": "Amazon", "68:37:e9": "Amazon", "f0:d2:f1": "Amazon", "44:65:0d": "Amazon",
    "0c:47:c9": "Amazon (Ring)",
    # Google / Nest
    "f4:f5:d8": "Google", "54:60:09": "Google", "1c:f2:9a": "Google", "18:b4:30": "Nest",
    # Espressif — the chip inside most cheap WiFi smart plugs/bulbs/sensors
    "24:6f:28": "Espressif (IoT device)", "30:ae:a4": "Espressif (IoT device)",
    "a4:cf:12": "Espressif (IoT device)", "cc:50:e3": "Espressif (IoT device)",
    # Raspberry Pi Foundation
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    # Routers / networking gear
    "50:c7:bf": "TP-Link", "b0:4e:26": "TP-Link", "ec:08:6b": "TP-Link",
    "a0:04:60": "Netgear", "20:e5:2a": "Netgear",
    "1c:87:2c": "ASUS", "50:46:5d": "ASUS",
    "00:1b:11": "D-Link", "b8:a3:86": "D-Link",
    "24:5a:4c": "Ubiquiti", "78:8a:20": "Ubiquiti",
    # Phones / other mobile
    "78:11:dc": "Xiaomi", "34:ce:00": "Xiaomi", "f0:b4:29": "Xiaomi",
    "00:1e:10": "Huawei", "f4:9f:f3": "Huawei",
    # Computers
    "3c:a9:f4": "Intel", "a4:c3:f0": "Intel", "94:e6:f7": "Intel",
    "00:15:5d": "Microsoft (Hyper-V virtual adapter)", "7c:1e:52": "Xbox",
    "d4:3d:7e": "Dell", "a4:bb:6d": "Dell",
    "6c:29:95": "HP", "3c:d9:2b": "HP",
    "48:d2:24": "Lenovo",
    # Entertainment
    "5c:aa:fd": "Sonos", "94:9f:3e": "Sonos",
    "7c:bb:8a": "Nintendo Switch", "98:b6:e9": "Nintendo Switch",
    "fc:0f:e6": "PlayStation", "ac:89:95": "PlayStation",
    "b8:3e:59": "Roku", "d8:31:34": "Roku",
    "94:10:3e": "Belkin/WeMo",
}


def lookup_vendor(mac: str) -> str | None:
    """mac should already be lowercase, colon-separated (e.g. 'a4:83:e7:12:34:56')."""
    prefix = mac.lower()[:8]
    return _OUI_TABLE.get(prefix)
