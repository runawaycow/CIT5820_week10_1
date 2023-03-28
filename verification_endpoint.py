from flask import Flask, request, jsonify
from flask_restful import Api
import json
import eth_account
import algosdk
import sys

app = Flask(__name__)
api = Api(app)
app.url_map.strict_slashes = False

@app.route('/verify', methods=['GET','POST'])
def verify():
    content = request.get_json(silent=True)

# YOUR CODE BELOW
   
    # Extract payload and signature from request
    print("Test Print", file=sys.stderr)
    print(content, file=sys.stderr)
    try:

        payload = content['payload']
        signature = content['sig']
        pk = payload['pk']
    except:

        return jsonify(False)
    print(payload , file=sys.stderr)
    print(payload['platform'], file=sys.stderr) 
    print(signature , file=sys.stderr)        
    # Serialize payload dictionary to a string
    payload_str = json.dumps(payload)
    # Check platform to use appropriate verification algorithm
    platform = payload['platform']


    if platform == 'Ethereum':
        print("ssssssssssssssssssssssssssssssssss" , file=sys.stderr)
        # Extract public key from payload and convert to lowercase
        
        # Hash payload string using Ethereum message encoding
        message = eth_account.messages.encode_defunct(text=payload_str)
        print(message, file=sys.stderr)
        try:
            # Verify signature using Ethereum account library
            eth_account.Account.recover_message(message, signature=signature) == pk
            print( "ETH sig verifies!" )
            return jsonify(True)
        except:
            return jsonify(False)

    elif platform == 'Algorand':
        print("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" , file=sys.stderr)
        # Extract public key from payload
        # Convert payload string to bytes
        message = payload_str.encode('utf-8')
        print(message , file=sys.stderr)
        if algosdk.util.verify_bytes(message,signature,pk):
            print( "Algo sig verifies!" )
            return jsonify(True)
    else:
        # Invalid platform
        return jsonify(False)


if __name__ == '__main__':
    app.run(port='5002')
