SCAN_PROFILES = {

    "quick": {
        "ports": [21,22,80,443,8080],
        "services": True,
        "banner": False,
        "headers": False,
        "ssl": False
    },

    "full": {
        "ports": list(range(1,1025)),
        "services": True,
        "banner": True,
        "headers": True,
        "ssl": True
    },

    "web": {
        "ports": [],
        "services": False,
        "banner": True,
        "headers": True,
        "ssl": True
    }

}