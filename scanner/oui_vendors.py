"""
oui_vendors.py — offline MAC-prefix-to-vendor lookup + device type guessing.

The OUI table is a curated subset for home networks. Anything not in this table
returns None for vendor. Device type is guessed from vendor, hostname patterns,
and network position heuristics — best-effort, not guaranteed accurate.
"""

_OUI_TABLE = {
    # Apple
    "3c:22:fb": ("Apple", "laptop"),   "ac:de:48": ("Apple", "phone"),
    "f0:18:98": ("Apple", "phone"),    "a4:83:e7": ("Apple", "phone"),
    "00:1b:63": ("Apple", "laptop"),   "d0:e1:40": ("Apple", "laptop"),
    "88:66:5a": ("Apple", "phone"),    "5c:97:f3": ("Apple", "phone"),
    "dc:a4:ca": ("Apple", "phone"),    "f4:5c:89": ("Apple", "phone"),
    "98:01:a7": ("Apple", "phone"),    "a8:96:8a": ("Apple", "laptop"),
    # Samsung
    "00:12:47": ("Samsung", "phone"),  "5c:0a:5b": ("Samsung", "phone"),
    "8c:79:67": ("Samsung", "phone"),  "e8:50:8b": ("Samsung", "phone"),
    "34:23:87": ("Samsung", "phone"),  "fc:a1:3e": ("Samsung", "phone"),
    # Amazon
    "fc:65:de": ("Amazon Echo", "smart_speaker"),
    "68:37:e9": ("Amazon Echo", "smart_speaker"),
    "f0:d2:f1": ("Amazon Fire TV", "tv"),
    "44:65:0d": ("Amazon", "device"),
    "0c:47:c9": ("Amazon Ring", "camera"),
    # Google / Nest
    "f4:f5:d8": ("Google", "device"),  "54:60:09": ("Google Chromecast", "tv"),
    "1c:f2:9a": ("Google", "device"),  "18:b4:30": ("Nest", "smart_home"),
    # Espressif — chip inside most cheap WiFi IoT devices
    "24:6f:28": ("Espressif IoT", "iot"),  "30:ae:a4": ("Espressif IoT", "iot"),
    "a4:cf:12": ("Espressif IoT", "iot"),  "cc:50:e3": ("Espressif IoT", "iot"),
    "10:52:1c": ("Espressif IoT", "iot"),  "b4:e6:2d": ("Espressif IoT", "iot"),
    # Raspberry Pi
    "b8:27:eb": ("Raspberry Pi", "pc"),  "dc:a6:32": ("Raspberry Pi", "pc"),
    "e4:5f:01": ("Raspberry Pi", "pc"),
    # Routers / APs / networking
    "50:c7:bf": ("TP-Link", "router"),   "b0:4e:26": ("TP-Link", "router"),
    "ec:08:6b": ("TP-Link", "router"),   "c4:6e:1f": ("TP-Link", "router"),
    "a0:04:60": ("Netgear", "router"),   "20:e5:2a": ("Netgear", "router"),
    "1c:87:2c": ("ASUS", "router"),      "50:46:5d": ("ASUS", "router"),
    "00:1b:11": ("D-Link", "router"),    "b8:a3:86": ("D-Link", "router"),
    "24:5a:4c": ("Ubiquiti", "router"),  "78:8a:20": ("Ubiquiti", "router"),
    "9c:a2:f4": ("Huawei Router", "router"),
    # Phones / mobile
    "78:11:dc": ("Xiaomi", "phone"),     "34:ce:00": ("Xiaomi", "phone"),
    "f0:b4:29": ("Xiaomi", "phone"),     "9c:99:a0": ("Xiaomi", "phone"),
    "00:1e:10": ("Huawei", "phone"),     "f4:9f:f3": ("Huawei", "phone"),
    "5c:51:4f": ("OnePlus", "phone"),
    # PCs / laptops
    "3c:a9:f4": ("Intel", "pc"),         "a4:c3:f0": ("Intel", "pc"),
    "94:e6:f7": ("Intel", "pc"),
    "00:15:5d": ("Microsoft Hyper-V", "vm"),
    "7c:1e:52": ("Xbox", "game_console"),
    "d4:3d:7e": ("Dell", "pc"),          "a4:bb:6d": ("Dell", "pc"),
    "6c:29:95": ("HP", "pc"),            "3c:d9:2b": ("HP", "pc"),
    "48:d2:24": ("Lenovo", "laptop"),    "54:13:79": ("Lenovo", "laptop"),
    "b8:1e:a4": ("Lenovo", "laptop"),
    # Entertainment
    "5c:aa:fd": ("Sonos", "smart_speaker"),  "94:9f:3e": ("Sonos", "smart_speaker"),
    "7c:bb:8a": ("Nintendo Switch", "game_console"),
    "98:b6:e9": ("Nintendo Switch", "game_console"),
    "fc:0f:e6": ("PlayStation", "game_console"),
    "ac:89:95": ("PlayStation", "game_console"),
    "b8:3e:59": ("Roku", "tv"),          "d8:31:34": ("Roku", "tv"),
    "94:10:3e": ("Belkin/WeMo", "smart_home"),
    # Smart TVs
    "78:bd:bc": ("LG TV", "tv"),         "a8:23:fe": ("LG TV", "tv"),
    "74:e5:f9": ("Samsung TV", "tv"),    "8c:77:12": ("Samsung TV", "tv"),
    "cc:6d:a0": ("Sony TV", "tv"),
}

# Hostname keyword → device type
_HOSTNAME_TYPE_HINTS = [
    (["iphone", "ipad"],          "phone"),
    (["android", "pixel", "galaxy", "samsung", "huawei", "xiaomi", "oppo", "oneplus"], "phone"),
    (["macbook", "imac", "mac-mini", "mac-pro"], "laptop"),
    (["laptop", "notebook", "thinkpad", "ideapad", "inspiron", "latitude", "elitebook"], "laptop"),
    (["desktop", "workstation", "pc-", "-pc", "tower"],  "pc"),
    (["xbox", "playstation", "ps4", "ps5", "nintendo"],  "game_console"),
    (["roku", "fire-tv", "chromecast", "appletv", "apple-tv"], "tv"),
    (["echo", "alexa", "google-home", "homepod", "sonos"], "smart_speaker"),
    (["nest", "ring", "wemo", "hue", "shelly", "tasmota"], "smart_home"),
    (["router", "gateway", "modem", "ap-", "-ap", "access-point"], "router"),
    (["printer", "hp-", "epson", "canon", "brother"], "printer"),
    (["nas", "synology", "qnap", "freenas", "unraid"], "nas"),
    (["pi", "raspberrypi", "raspberry"], "pc"),
    (["cam", "camera", "doorbell", "nvr", "dvr"], "camera"),
]

_DEVICE_TYPE_LABELS = {
    "phone":        "📱 Phone",
    "laptop":       "💻 Laptop",
    "pc":           "🖥️ PC",
    "vm":           "🖥️ VM",
    "router":       "🌐 Router / AP",
    "tv":           "📺 TV / Streaming",
    "game_console": "🎮 Game Console",
    "smart_speaker":"🔊 Smart Speaker",
    "smart_home":   "🏠 Smart Home",
    "iot":          "⚡ IoT Device",
    "camera":       "📷 Camera",
    "printer":      "🖨️ Printer",
    "nas":          "🗄️ NAS",
    "device":       "📡 Device",
}


def lookup_vendor(mac: str) -> str | None:
    """Return vendor name for a MAC prefix, or None if unknown / randomized MAC."""
    # Locally administered (randomized) MACs have bit 1 of byte 1 set — skip OUI lookup
    try:
        first_byte = int(mac.split(":")[0], 16)
        if first_byte & 0x02:
            return None  # randomized MAC, no OUI to look up
    except Exception:
        pass
    prefix = mac.lower()[:8]
    entry = _OUI_TABLE.get(prefix)
    return entry[0] if entry else None


def lookup_device_type(mac: str, hostname: str | None = None, ip: str | None = None) -> str | None:
    """
    Best-effort device type inference. Returns a short string like 'phone', 'laptop',
    'router', etc. — or None if we can't guess.

    Priority: OUI table → hostname keywords → IP position heuristic (.1 = router).
    """
    # 1. OUI table (most reliable for non-randomized MACs)
    try:
        first_byte = int(mac.split(":")[0], 16)
        if not (first_byte & 0x02):   # only for global (non-randomized) MACs
            prefix = mac.lower()[:8]
            entry = _OUI_TABLE.get(prefix)
            if entry and entry[1]:
                return entry[1]
    except Exception:
        pass

    # 2. Hostname keyword matching
    if hostname:
        h = hostname.lower()
        for keywords, dtype in _HOSTNAME_TYPE_HINTS:
            if any(kw in h for kw in keywords):
                return dtype

    # 3. IP heuristic — .1 is almost always the router/gateway
    if ip:
        last_octet = ip.rsplit(".", 1)[-1]
        if last_octet == "1":
            return "router"

    return None


def device_type_label(device_type: str | None) -> str:
    """Human-readable label with emoji for a device type string."""
    if not device_type:
        return "Unknown device"
    return _DEVICE_TYPE_LABELS.get(device_type, "📡 Device")
