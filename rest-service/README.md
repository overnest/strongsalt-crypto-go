Run the server with:
`go run rest_server.go`

The general JSON format for sending data is the following, though not every field is always used:
```
{
  "transaction": integer,
  "key": serialized key (base64 encoded string, url-safe, padded),
  "plaintext": (base64 encoded string, url-safe, padded),
  "ciphertext": (base64 encoded string, url-safe, padded),
  "mac": (base64 encoded string, url-safe, padded),
}
```

1. Generate a key in the client. If it is an encryption key, you will be sending the key, some plaintext, and the ciphertext.  
If it is a MAC key, you will be sending the key, some ciphertext, and the MAC of the ciphertext.  
Send to:  
`http://localhost:8084/push`

The server will validate the data you sent. It will respond with status code 500 if there is a problem.  
Then the server will respond with more data created from the same key. Use your original copy of the key to verify the data.

2. Choose a key type to test. The types can be found in `strongsalt_key.go`. Send a request such as:
```
{
  "type": "XChaCha20",
}
```
To:  
`http://localhost:8084/pull`

The server will respond with data for you to validate. Deserialize the key, and if it is an encryption key, decrypt the ciphertext and compare it to the plaintext. If it is a MAC key, generate a MAC from the given ciphertext and compare it to the given MAC.

Then create new data to send back to the server, using the same key. The initial response from the server contains a transaction number, which you must send back.  
Send this data to:  
`http://localhost:8084/pullResponse`  
The server will validate the data you sent, and if something doesn't work it will return status code 500.
