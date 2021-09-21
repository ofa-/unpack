#!/usr/bin/env python3

import argparse
import json
import sys
import re

import zlib
import cbor2
from base64 import b64decode
from base45 import b45decode
from cose.messages import CoseMessage
import hashlib


parser = argparse.ArgumentParser(
    add_help=False,
    description="Parse a base45/zlib/cose/cbor QR to json."
)
parser.add_argument(
    "-u", "--uvci", action="store_true", help="Show cert uvci"
)
parser.add_argument(
    "-H", "--hash", action="store_true", help="Show cert hash"
)
parser.add_argument(
    "-n", "--name", action="store_true", help="Show name along with hash"
)
parser.add_argument(
    "-B", "--base64", action="store_true", help="Use base64 instead of base45"
)
parser.add_argument(
    "-h", "--help", action="help", help=argparse.SUPPRESS
)
args = parser.parse_args()


def main():
    for data in sys.stdin:
        unpack(args, data)

def unpack(args, data):
    if args.base64:
        data = b64decode(data)
    else:
        data = re.sub(r"^HC1:?", "", data)
        data = b45decode(data)

    try:
        data = zlib.decompress(data)
    except:
        pass

    decoded = CoseMessage.decode(data)
    payload = cbor2.loads(decoded.payload)

    section = {
            "issuer": 1,
            "time_issued": 6,
            "time_expires": 4,
            "health_claims": -260,
            }

    for k,v in section.items():
        payload[k] = payload.pop(v)

    uvci = payload["health_claims"][1]["v"][0]["ci"]
    name = payload["health_claims"][1]["nam"]
    name = name["gn"] + " " + name["fn"]

    if args.uvci:
        output = uvci
    elif args.hash:
        output = hashlib.sha256(("FR"+uvci).encode('utf-8')).hexdigest()
        if args.name: output += " " + name
    else:
        output = json.dumps(payload, indent=4, sort_keys=True)

    print(output)


main()
