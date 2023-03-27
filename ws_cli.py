from websocket import create_connection
import sys, json

ws_host = 'ws://ws.qreader.htb:5789'

VERSION = '0.0.2'

ws = create_connection(ws_host + '/version')
ws.send(json.dumps({'version': VERSION}))
result = ws.recv()
print(result)
ws.close()
