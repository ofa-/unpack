unpack digital green certificates
=================================

Overview
--------

```
$ ./unpack.py --help
usage: unpack.py [-u] [-H] [-n] [-B]

Parse a base45/zlib/cose/cbor QR to json.

optional arguments:
  -u, --uvci    Show cert uvci
  -H, --hash    Show cert hash
  -n, --name    Show name along with hash
  -B, --base64  Use base64 instead of base45
```

```
$ ./unpack.py --hash < manu.qr.txt 
1c5e43ef270a095db057daf058a7aea88eb35734389a848dd361ab9d75b47708
```

Install
-------

```
mkvirtualenv dgc --python `which python3`
pip install -r requirements.txt
```
