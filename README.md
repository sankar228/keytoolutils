#keytoolutils

Using this application we can do basic operations on java keystore file like adding, deleting, updating and listing keys
****

|option|description|
|-----------------|------------|
|_-a,--set_|Add if the key does not exist or Set the existing key value, -ka and -kv are required|
|_-d,--delete_|delete the existing key value, option -ka required|
|_-ka,--alias \<arg>_|alias name / key name|
|_-ks,--keystore \<arg>_|keystore file path|
|_-sp,--storepass \<arg>_|keystore password|
|_-kv,--aliasval \<arg>_|alias value / key value|
|_-l,--list_|List all the keys from the keystore|
|_-q,--query_|query key from keystore, -ka required|
|_-h,--help_|keytoolutils CLI options|

###Usage
`java KeyToolUtils -ks /home/user/store/keyStore -sp ***** -h`

`java KeyToolUtils -ks /home/user/store/keyStore -sp ***** -a -ka name.key -kv ----keyvalue----`

 
              