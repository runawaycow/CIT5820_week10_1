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
    Print('start checking')
    Print(content)
    if 'sig' not in content:
        result = False
        return jsonify(result)
    if 'payload' not in content:
        result = False
        return jsonify(result)
    if 'message' or 'pk' or 'platform' not in content['payload']:
        result = False
        return jsonify(result)
    if content['payload']['platform'] == 'Ethereum' or 'Algorand':
        signature_type = 'Ethereum'
    elif content['payload']['platform'] == 'Algorand':
        signature_type = 'Algorand'
    else:
        result = False
        return jsonify(result)

    signature = content['sig']
    payload = json.dump(content['payload'])

    #-----------verify ETH--------------------

    eth_account.Account.enable_unaudited_hdwallet_features()
    acct, mnemonic = eth_account.Account.create_with_mnemonic()

    eth_pk = acct.address
    eth_sk = acct.key

    eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)
    eth_sig_obj = eth_account.Account.sign_message(eth_encoded_msg,eth_sk)
    if eth_account.Account.recover_message(eth_encoded_msg,signature=eth_sig_obj.signature.hex()) == eth_pk:
        print( "ETH sig verifies!" )
        result = True #Should only be true if signature validates
        return jsonify(result)

    #-----------verify algosdk--------------------
    algo_sk, algo_pk = algosdk.account.generate_account()
    algo_sig_str = algosdk.util.sign_bytes(payload.encode('utf-8'),algo_sk)

    if algosdk.util.verify_bytes(payload.encode('utf-8'),algo_sig_str,algo_pk):
        print( "Algo sig verifies!" )
        result = True #Should on
        return jsonify(result)
    

    #Check if signature is valid
    result = False #Should only be true if signature validates
    return jsonify(result)

if __name__ == '__main__':
    app.run(port='5002')
