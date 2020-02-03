from Cryptodome import Random
from Cryptodome.PublicKey import RSA
from Cryptodome.Util import number

def generate_server_key():
    pkey=RSA.generate(4096,Random.new().read)
    key=pkey.exportKey('PEM')
    db(db.server).update(privkey=key)
    db(db.campaign_details).update(keye=str(base64.b64encode(number.long_to_bytes(pkey.publickey().e))))
    db(db.campaign_details).update(keyn=str(base64.b64encode(number.long_to_bytes(pkey.publickey().n))))
