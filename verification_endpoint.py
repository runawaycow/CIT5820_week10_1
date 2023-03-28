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
    payload = content['payload']
    signature = content['sig']

    # Serialize payload dictionary to a string
    payload_str = json.dumps(payload, sort_keys=True)

    # Check platform to use appropriate verification algorithm
    platform = payload['platform']
    if platform == 'Ethereum':
        # Extract public key from payload and convert to lowercase
        pk = payload['pk'].lower()

        # Hash payload string using Ethereum message encoding
        message = eth_account.messages.encode_defunct(text=payload_str)

        try:
            # Verify signature using Ethereum account library
            eth_account.Account.recover_message(message, signature=signature) == pk
            return jsonify(True)
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
