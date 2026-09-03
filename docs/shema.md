## Share link

key_and_hash = concat(share_key, signature)
encoded = b64_encode(key_and_hash)
https://${host}/#${key_and_hash}