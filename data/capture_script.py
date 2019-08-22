import base64 as b64
import sys
import base64
import binascii

def request(flow):
    print(flow.request.method)
    print(flow.request.pretty_url.rstrip("\n"))
    try:
        print(base64.b64encode(bytearray(flow.request.get_text().rstrip("\n"), "utf8")).decode("utf8"))
    except:
        print(base64.b64encode(bytearray("0x" + binascii.hexlify(flow.request.get_content()).decode('utf8'), "utf8")).decode('utf8'))
