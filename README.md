# pswrdMngrInC
gcc cliPassMngr.c -L. -lsodium -lsqlite3 -DSQLITE_HAS_CODEC -g

gcc -Wall -Wextra -g -DSQLITE_HAS_CODEC  test_password_manager.c -lsqlite3 -lsodium    -o test_password_manager