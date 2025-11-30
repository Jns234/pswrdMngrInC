# pswrdMngrInC
This is a Password Manager project that is written in C.
There are two libraries needed to compile it.

SQLCipher: 
```https://github.com/sqlcipher/sqlcipher?tab=readme-ov-file#compiling```

libsodium: 
```https://libsodium.gitbook.io/doc/installation```


## Compiling
To compile the password manager run the following gcc command:
```
gcc cliPassMngr.c -L. -lsodium -lsqlite3 -DSQLITE_HAS_CODEC -g
```

To compile the tests run the following gcc command:
```
gcc -Wall -Wextra -g -DSQLITE_HAS_CODEC  test_password_manager.c -lsqlite3 -lsodium -o test_password_manager
```