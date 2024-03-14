from Crypto.Cipher import AES
from Crypto import Random
import sys, time, json, os, hashlib
from ecdsa import VerifyingKey, SigningKey
from p2pnetwork.node import Node

SERVER_ADDR = "zachcoin.net"
SERVER_PORT = 9067

class ZachCoinClient (Node):
    
    #ZachCoin Constants
    BLOCK = 0
    TRANSACTION = 1
    BLOCKCHAIN = 2
    UTXPOOL = 3
    COINBASE = 50
    DIFFICULTY = 0x0000007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    #Hardcoded gensis block
    blockchain = [
        {
            "type": BLOCK,
            "id": "b4b9b8f78ab3dc70833a19bf7f2a0226885ae2416d41f4f0f798762560b81b60",
            "nonce": "1950b006f9203221515467fe14765720",
            "pow": "00000027e2eb250f341b05ffe24f43adae3b8181739cd976ea263a4ae0ff8eb7",
            "prev": "b4b9b8f78ab3dc70833a19bf7f2a0226885ae2416d41f4f0f798762560b81b60",
            "tx": {
                "type": TRANSACTION,
                "input": {
                    "id": "0000000000000000000000000000000000000000000000000000000000000000",
                    "n": 0
                },
                "sig": "adf494f10d30814fd26c6f0e1b2893d0fb3d037b341210bf23ef9705479c7e90879f794a29960d3ff13b50ecd780c872",
                "output": [
                    {
                        "value": 50,
                        "pub_key": "c26cfef538dd15b6f52593262403de16fa2dc7acb21284d71bf0a28f5792581b4a6be89d2a7ec1d4f7849832fe7b4daa"
                    }
                ]
            }
        }
    ]
    utx = []
#   create transactions first, input the person's public key, and the amount of coins you want to send
    def __init__(self, host, port, id=None, callback=None, max_connections=0):
        super(ZachCoinClient, self).__init__(host, port, id, callback, max_connections)

    def outbound_node_connected(self, connected_node):
        print("outbound_node_connected: " + connected_node.id)
        
    def inbound_node_connected(self, connected_node):
        print("inbound_node_connected: " + connected_node.id)

    def inbound_node_disconnected(self, connected_node):
        print("inbound_node_disconnected: " + connected_node.id)

    def outbound_node_disconnected(self, connected_node):
        print("outbound_node_disconnected: " + connected_node.id)

    def node_message(self, connected_node, data):
        #print("node_message from " + connected_node.id + ": " + json.dumps(data,indent=2))
        print("node_message from " + connected_node.id)

        if data != None:
            if 'type' in data:
                if data['type'] == self.TRANSACTION:
                    self.utx.append(data)
                elif data['type'] == self.BLOCKCHAIN:
                    self.blockchain = data['blockchain']
                elif data['type'] == self.UTXPOOL:
                    self.utx = data['utxpool']
                #TODO: Validate blocks

    def node_disconnect_with_outbound_node(self, connected_node):
        print("node wants to disconnect with oher outbound node: " + connected_node.id)
        
    def node_request_to_stop(self):
        print("node is requested to stop!")


def main():

    if len(sys.argv) < 3:
        print("Usage: python3", sys.argv[0], "CLIENTNAME PORT")
        quit()

    #Load keys, or create them if they do not yet exist
    keypath = './' + sys.argv[1] + '.key'
    if not os.path.exists(keypath):
        sk = SigningKey.generate()
        vk = sk.verifying_key
        with open(keypath, 'w') as f:
            f.write(sk.to_string().hex())
            f.close()
    else:
        with open(keypath) as f:
            try:
                sk = SigningKey.from_string(bytes.fromhex(f.read()))
                vk = sk.verifying_key
            except Exception as e:
                print("Couldn't read key file", e)

    #Create a client object
    client = ZachCoinClient("127.0.0.1", int(sys.argv[2]), sys.argv[1])
    client.debug = False

    time.sleep(1)

    client.start()

    time.sleep(1)

    #Connect to server 
    client.connect_with_node(SERVER_ADDR, SERVER_PORT)
    print("Starting ZachCoin™ Client:", sys.argv[1])
    time.sleep(2)

    def createTransaction(client, recipient, amount):
        # key is the id of the block, value is the (output, idx)
        transactionsList = {}
        # latestTransaction, ltidx = None, None

        # need to check inputID 
        for block in client.blockchain:
            inputID = block['tx']['input']['id']
            inputIDX = block['tx']['input']['n']

            # print("inputID: ", inputID)
            # print("inputIDX: ", inputIDX)

            outputs = block['tx']['output']

            for outputIdx in range(len(outputs)):
                # if (outputs[outputIdx]['pub_key'] == "c26cfef538dd15b6f52593262403de16fa2dc7acb21284d71bf0a28f5792581b4a6be89d2a7ec1d4f7849832fe7b4daa"):
                if (outputs[outputIdx]['pub_key'] == vk.to_string().hex()):
                    curID = block['id']
                    # print("curID: ", curID)
                    if transactionsList == {}:
                        transactionsList[curID] = (outputs[outputIdx]['value'], outputIdx)
                    elif outputIdx == inputIDX:
                        transactionsList[curID] = (outputs[outputIdx]['value'], outputIdx)
                        if inputID in transactionsList:
                            del transactionsList[inputID]
        
        transactionsDictValues = list(transactionsList.values())
        transactionsDictKeys = list(transactionsList.keys())

        validPrevTransaction = None
        validPrevTransactionIdx = None
        myMoney = 0
        for i in range(len(transactionsDictValues)):
            if transactionsDictValues[i][0] >= int(amount):
                validPrevTransaction = transactionsDictKeys[i]
                validPrevTransactionIdx = transactionsDictValues[i][1]
                myMoney = transactionsDictValues[i][0]
                break

        if validPrevTransaction == None:
            print("Error: No valid previous transaction found.")
            return
        
        print("validPrevTransaction: ", validPrevTransaction)
        print("validPrevTransactionIdx: ", validPrevTransactionIdx)
        print("Money in Transaction: ", myMoney)

        newTransaction = {}
        input = {
                    "input": 
                        {
                            "id": validPrevTransaction,
                            "n": validPrevTransactionIdx
                        }
                }

        # create a transaction
        if myMoney - int(amount) > 0:
            newTransaction = {
                "type": client.TRANSACTION,
                "input": 
                    {
                        "id": validPrevTransaction,
                        "n": validPrevTransactionIdx
                    },
                "sig": sk.sign(json.dumps(input).encode()).hex(),
                "output": [
                    {
                        "value": int(amount),
                        "pub_key": recipient
                    },
                    {
                        "value": myMoney - int(amount),
                        "pub_key": vk.to_string().hex()
                    }
                ]
            } 
        else:
            newTransaction = {
                "type": client.TRANSACTION,
                "input": {
                    "id": validPrevTransaction,
                    "n": validPrevTransactionIdx
                },
                "sig": sk.sign(json.dumps(input).encode()).hex(),
                "output": [
                    {
                        "value": int(amount),
                        "pub_key": recipient
                    }
                ]
            } 
            
        # add the transaction to the UTX pool
        client.utx.append(newTransaction)
        print("Transaction created: ", newTransaction)
        client.send_to_nodes(newTransaction)
        print("Transaction broadcasted to the network.")
        return
        
    def fieldsValidation(client, utx):
        # check if the fields in the transaction exist
        neededFields = {'type', 'input', 'sig', 'output'}
        inputFields = {'id', 'n'}
        outputFields = {'value', 'pub_key'}
        print("Validating Fields...")
        print(utx)
        for field in neededFields:
            if field not in utx:
                print("Error: Missing field in transaction.")
                return False
        for field in inputFields:
            if field not in utx['input']:
                print("Error: Missing field in input.")
                return False
        for output in utx['output']:
            for field in outputFields:
                if field not in output:
                    print("Error: Missing field in output.")
                    return False
        
        print("Validating Transaction Type...")
        # Check if the type is TRANSACTION
        if utx['type'] != client.TRANSACTION:
            return False
        
        print("Validating Input Block...")
        # Check if the input is a valid block in the blockchain
        inputID = utx['input']['id']
        inputIDX = utx['input']['n']
        blockchain = client.blockchain
        blkChainPtr = 0
        refBlock = None

        for block in blockchain:
            blkChainPtr += 1
            if block['id'] == inputID:
                # get pk paid to, look at input look at sig of utx and try to verify
                    if len(block['tx']['output']) - 1 <= inputIDX:
                        outputReferenced = block['tx']['output'][inputIDX]
                        pub_key = outputReferenced['pub_key']
                        vk = VerifyingKey.from_string(bytes.fromhex(pub_key))

                        try: 
                            # Maybe assert
                            assert vk.verify(bytes.fromhex(utx['sig']), json.dumps(utx['input'], sort_keys=True).encode('utf8'))
                            # validBlock = True
                            refBlock = block
                            break
                        except Exception as e:
                            print("Error: Signature verification failed.")
                            continue
                    else:
                        "print fails at output index."
                        return False
        
        if refBlock == None:
            print("ref block failure")
            return False
        
        # check if the input is unspent
        for block in blockchain[blkChainPtr:]:
            inputID = block['id']
            inputIDX = utx['input']['n']
            if inputID == refBlock['id'] and inputIDX == utx['input']['n']:
                print("Input is spent.")
                return False
            
        # check if the input val is equal to the sum of the output
        inputVal = refBlock['tx']['output'][inputIDX]['value']
        outputSum = 0

        for output in utx['output']:
            outputVal = output['value']
            if outputVal <= 0:
                print("One or more outpur values is less than or equal to 0.")
                return False
            outputSum += outputVal
        print("InputVal: ", inputVal)
        print("OutputSum: ", outputSum)
        if inputVal != outputSum:
            print("Input coins and output coins do not match.")
            return False
    
        if (len(utx['output']) >= 2 or len(utx['output']) == 0):
            print("Invalid number of outputs in transaction.")
            return False
        # check number of outputs AND each output is greater than 0

        return True
        
    def mine_transaction(utx, prev):
        nonce = Random.new().read(AES.block_size).hex()
        while( int( hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf8') + prev.encode('utf-8') + nonce.encode('utf-8')).hexdigest(), 16) > client.DIFFICULTY):
            nonce = Random.new().read(AES.block_size).hex()
        pow = hashlib.sha256(json.dumps(utx, sort_keys=True).encode('utf8') + prev.encode('utf-8') + nonce.encode('utf-8')).hexdigest()
        return pow, nonce
    
    def mineBlock(client):
        serverUTX = client.utx
        clientBlock = client.blockchain
        lastBlock = clientBlock[-1]
        prev = lastBlock['id']
        curUtx = None

        # curUtx = serverUTX[-1]

        # curUtx = {"tx": {
        #         "type": 1,
        #         "input": {
        #             "id": "64ee0efe099881924cd5ecc22563bedd47a45d2537de5a08bc0dee6403076490",
        #             "n": 2
        #         },
        #         "sig": "de099e1a8a40d5bfee5a69a2b4b6383bfbfdea26ded8848e065a4031953afabc36da7ef8ce520c0ffe9c88346fd6d373",
        #         "output": [
        #             {
        #             "value": 50,
        #             "pub_key": "3b9306efea63c7cdff03315c11b30c9e4b4c6a1d7f803abf74dbe69b6a4d6bfbd02f25a7990a738618be58da39620480"
        #             }
        #             ]}}
        
        # curUtx = curUtx['tx']
        
        # if fieldsValidation(client, curUtx) == False:
        #     print("Error: Invalid transaction.")
        #     return

        # check if the fields in the transaction exist

        for utx in reversed(serverUTX):
            if fieldsValidation(client, utx) == True:
                curUtx = utx
                break

        if curUtx == None:
            print("Error: No valid transactions to mine.")
            return
        

        # miners must add a coinbase transaction as the final output of the unverified transaction that they are mining
        print(curUtx) 
        coinbase = {
            "value": client.COINBASE,
            "pub_key": vk.to_string().hex()
        }
        curUtx['output'].append(coinbase)
        
        print(curUtx)

        print("Mining transaction...")
        pow, nonce = mine_transaction(curUtx, prev)
        print("POW: ", pow)
        print("Nonce: ", nonce)
        blockId = hashlib.sha256(json.dumps(curUtx, sort_keys=True).encode('utf8')).hexdigest()

        # create a block to sumbit to the blockchain
        newBlock = {
            "type": client.BLOCK,
            "id": blockId,
            "nonce": nonce,
            "pow": pow,
            "prev": prev,
            "tx": curUtx
        }

        # add the block to the blockchain
        client.blockchain.append(newBlock)
        print("Block mined: ", newBlock)
        client.send_to_nodes(newBlock)
        print("Block broadcasted to the network.")
        return

        # Can be generated once tx is made        
    
    def wallet(client):
        transactionsList = {}
        # latestTransaction, ltidx = None, None

        # need to check inputID 
        for block in client.blockchain:
            inputID = block['tx']['input']['id']
            inputIDX = block['tx']['input']['n']

            # print("inputID: ", inputID)
            # print("inputIDX: ", inputIDX)

            outputs = block['tx']['output']

            for outputIdx in range(len(outputs)):
                # if (outputs[outputIdx]['pub_key'] == "c26cfef538dd15b6f52593262403de16fa2dc7acb21284d71bf0a28f5792581b4a6be89d2a7ec1d4f7849832fe7b4daa"):
                if (outputs[outputIdx]['pub_key'] == vk.to_string().hex()):
                    curID = block['id']
                    # print("curID: ", curID)
                    if transactionsList == {}:
                        transactionsList[curID] = (outputs[outputIdx]['value'], outputIdx)
                    elif outputIdx == inputIDX:
                        transactionsList[curID] = (outputs[outputIdx]['value'], outputIdx)
                        if inputID in transactionsList:
                            del transactionsList[inputID]
        
        transactionsDictValues = list(transactionsList.values())
        transactionsDictKeys = list(transactionsList.keys())
        myMoney = 0
        for i in range(len(transactionsDictValues)):
            print("Transaction ID: ", transactionsDictKeys[i])
            print("Transaction Value: ", transactionsDictValues[i][0])
            print()
            myMoney += transactionsDictValues[i][0]
        print("Total ZachCoins™ in the blockchain: ", myMoney)
        return
        
    while True:
        os.system('cls' if os.name=='nt' else 'clear')
        slogan = " You can't spell \"It's a Ponzi scheme!\" without \"ZachCoin\" "
        print("=" * (int(len(slogan)/2) - int(len(' ZachCoin™')/2)), 'ZachCoin™', "=" * (int(len(slogan)/2) - int(len('ZachCoin™ ')/2)))
        print(slogan)
        print("=" * len(slogan),'\n')
        x = input("\t0: Print keys\n\t1: Print blockchain\n\t2: Print UTX pool\n\t3: Create a new transaction\n\t4: Mine a block\n\t5: Look into wallet\n\nEnter your choice -> ")
        try:
            x = int(x)
        except:
            print("Error: Invalid menu option.")
            input()
            continue
        if x == 0:
            print("sk: ", sk.to_string().hex())
            print("vk: ", vk.to_string().hex())
        elif x == 1:
            print(json.dumps(client.blockchain, indent=1))
        elif x == 2:
            print(json.dumps(client.utx, indent=1))
        elif x == 3:
            print("\nEnter the recipient's public key: ")
            recipient = input()
            print("Enter the amount of ZachCoins™ to send: ")
            amount = input()
            print("Creating transaction...")
            #Create a transaction
            createTransaction(client, recipient, amount)
        elif x == 4:
            print("Mining a block...")
            #Mine a block
            mineBlock(client)
        elif x == 5:
            print("Accessing Wallet...")
            wallet(client)
            
        # TODO: Add options for creating and mining transactions
        # as well as any other additional features

        input()
        
if __name__ == "__main__":
    main()