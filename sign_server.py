# -*- coding: utf-8 -*-

import rsa
import base64
import struct
from flask import Flask, request, abort, Response
from flask.ext.script import Server, Manager

__author__ = 'florije'

app = Flask(__name__)
manager = Manager(app)

manager.add_command("runserver", Server(host="0.0.0.0", port=9000))


obtain_url = 'L3JwYy9vYnRhaW5UaWNrZXQuYWN0aW9u'
ping_url = 'L3JwYy9waW5nLmFjdGlvbg=='
ping_format = 'PFBpbmdSZXNwb25zZT48bWVzc2FnZT48L21lc3NhZ2U+PHJlc3BvbnNlQ29kZT5PSzwvcmVzcG9uc2VDb2RlPjxzYWx0Pnt9PC9z' \
              'YWx0PjwvUGluZ1Jlc3BvbnNlPg=='
obtain_format = 'PE9idGFpblRpY2tldFJlc3BvbnNlPjxtZXNzYWdlPjwvbWVzc2FnZT48cHJvbG9uZ2F0aW9uUGVyaW9kPntleHBpcmVkfTwvcH' \
                'JvbG9uZ2F0aW9uUGVyaW9kPjxyZXNwb25zZUNvZGU+T0s8L3Jlc3BvbnNlQ29kZT48c2FsdD57c2FsdH08L3NhbHQ+PHRpY2tldE' \
                'lkPjE8L3RpY2tldElkPjx0aWNrZXRQcm9wZXJ0aWVzPmxpY2Vuc2VlPXtuYW1lfQlsaWNlbnNlVHlwZT0wCTwvdGlja2V0UHJvcG' \
                'VydGllcz48L09idGFpblRpY2tldFJlc3BvbnNlPg=='


class license_signer:
    def __init__(self):
        """

        """
        self.private_key_pem = base64.b64decode(
            'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgTUlHYUFnRUFBa0VBdD'
            'V5cmNIQUFqaGdsbkNFbjZ5ZWNNV1BlVVhjTXlvMCtpdFhyTGxrcGNLSUl5cVB3NTQ2YgogICAgICAgICAgICAgICAgICAgICAgICAgICAg'
            'ICAgICAgR1RoaGxiMXBwWDF5U1gvT1VBNGpTYWtIZWtOUDVlV1Bhd0lCQUFKQVc2L2FWRDA1cWJzWkhNdlp1UzJBYTVGcAogICAgICAgIC'
            'AgICAgICAgICAgICAgICAgICAgICAgICAgTk5qMEJEbGYzOGhPdGtoRHp6L2hrWWIrRUJZTEx2bGRoZ3NEME92Uk55OHloejdFamFVcUxD'
            'QjBqdUlONFFJQgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgQUFJQkFBSUJBQUlCQUFJQkFBPT0KICAgICAgICAgICAgIC'
            'AgICAgICAgICAgICAgICAgICAgIC0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0t')

        self.private_key = rsa.PrivateKey.load_pkcs1(keyfile=self.private_key_pem, format='PEM')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    @staticmethod
    def digit_char(d):
        return (48 + d) if d < 10 else (97 + d) - ord('\n')

    def gen_sign(self, msg):
        """

        :param msg:
        :return:
        """
        sign = rsa.sign(message=msg, priv_key=self.private_key, hash='MD5')
        format_bytes = '%ib' % len(sign)
        sign_bytes = struct.unpack(format_bytes, sign)
        hex_sign = []

        for sign_byte in sign_bytes:
            hex_sign.append(self.digit_char(sign_byte >> 4 & 0xF))
            hex_sign.append(self.digit_char(sign_byte & 0xF))

        return '<!-- {} -->\n'.format(''.join(map(chr, hex_sign)))


@app.route('/')
def hello_world():
    return 'Hello Jetbrains!!!'


@app.route(base64.b64decode(obtain_url), methods=['GET', 'POST'])
def obtain_ticket():
    if request.method == 'GET':
        xml_resp = base64.b64decode(obtain_format).format(expired=base64.b64decode('NjA3ODc1NTAw'),
                                                          salt=str(request.args.get('salt')),
                                                          name=str(request.args.get('userName')))

        with license_signer() as signer:
            xml_sign = signer.gen_sign(xml_resp)

        return Response('{sign}{plain}'.format(sign=xml_sign, plain=xml_resp), mimetype='text/xml')
    else:
        abort(401)


@app.route(base64.b64decode(ping_url), methods=['GET', 'POST'])
def ping():
    if request.method == 'GET':
        xml_resp = base64.b64decode(ping_format).format(str(request.args.get('salt', '')))

        with license_signer() as signer:
            xml_sign = signer.gen_sign(xml_resp)
        return Response('{sign}{plain}'.format(sign=xml_sign, plain=xml_resp), mimetype='text/xml')
    else:
        abort(401)


if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=9000)
    manager.run()
