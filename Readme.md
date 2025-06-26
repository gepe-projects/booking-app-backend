# install golang migrate
[HOW TO INSTALL](https://github.com/golang-migrate/migrate/tree/master/cmd/migrate)

# SQLC 
[how to install](https://docs.sqlc.dev/en/stable/overview/install.html)

or
```sh
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

# generate pem
openssl genpkey -algorithm RSA -out ./key/private.pem -pkeyopt rsa_keygen_bits:2048

openssl rsa -pubout -in ./key/private.pem -out ./key/public.pem
