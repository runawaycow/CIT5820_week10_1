from flask import Flask, request, jsonify
from flask_restful import Api
import json
import eth_account
import algosdk

app = Flask(__name__)
api = Api(app)
app.url_map.strict_slashes = False

@app.route('/verify', methods=['GET','POST'])
def verify():
    content = request.get_json(silent=True)

# YOUR CODE BELOW
   
    # Extract payload and signature from request
    print('here')
    payload = content['payload']
    signature = content['sig']

    # Serialize payload dictionary to a string
    payload_str = json.dumps(payload, sort_keys=True)

    # Check platform to use appropriate verification algorithm
    platform = payload['platform']
    if platform == 'Ethereum':
        eth_account.Account.enable_unaudited_hdwallet_features()
        acct, mnemonic = eth_account.Account.create_with_mnemonic()

        eth_pk = acct.address
        eth_sk = acct.key

        eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)
        eth_sig_obj = eth_account.Account.sign_message(eth_encoded_msg,eth_sk)
        try: eth_account.Account.recover_message(eth_encoded_msg,signature=eth_sig_obj.signature.hex()) == eth_pk:
            print( "ETH sig verifies!" )
            result = True #Should only be true if signature validates
            return jsonify(result)
        except:
            return jsonify(False)

    elif platform == 'Algorand':
        # Extract public key from payload
        pk = payload['pk']

        # Convert payload string to bytes
        message = payload_str.encode('utf-8')

        try:
            # Verify signature using Algorand encoding library
            public_key = algosdk.encoding.decode_address(pk)
            algosdk.sign.verify(message, signature, public_key)
            return jsonify(True)
        except:
            return jsonify(False)
    else:
        # Invalid platform
        return jsonify(False)


if __name__ == '__main__':
    app.run(port='5002')
