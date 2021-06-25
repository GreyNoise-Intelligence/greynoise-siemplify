CODE_MESSAGES = {
    "0x00": "IP has never been observed scanning the Internet",
    "0x01": "IP has been observed by the GreyNoise sensor network",
    "0x02": (
        "IP has been observed scanning the GreyNoise sensor network, "
        "but has not completed a full connection, meaning this can be spoofed"
    ),
    "0x03": (
        "IP is adjacent to another host that has been directly observed "
        "by the GreyNoise sensor network"
    ),
    "0x04": "RESERVED",
    "0x05": "IP is commonly spoofed in Internet-scan activity",
    "0x06": (
        "IP has been observed as noise, but this host belongs to a cloud provider "
        "where IPs can be cycled frequently"
    ),
    "0x07": "IP is invalid",
    "0x08": (
        "IP was classified as noise, but has not been observed "
        "engaging in Internet-wide scans or attacks in over 60 days"
    ),
    "0x09": "IP was found in RIOT",
    "0x10": "IP has been observed by the GreyNoise sensor network and is in RIOT",
    "404": "IP is Invalid",
}
USER_AGENT = "greynoise-siemplify-v2.0"
