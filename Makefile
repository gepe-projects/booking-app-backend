MIGRATE_CMD=migrate
DB_URL?=postgresql://root:root@localhost:5432/main_yuk?sslmode=disable
MIGRATION_DIR=internal/db/migrations


dev:
	@air

sqlc:
	sqlc generate

## Jalankan migrasi ke atas (latest)
migrate-up:
	$(MIGRATE_CMD) -path $(MIGRATION_DIR) -database "$(DB_URL)" up

## Jalankan migrasi ke bawah (rollback 1 step)
migrate-down:
	$(MIGRATE_CMD) -path $(MIGRATION_DIR) -database "$(DB_URL)" down 1

## Buat file migrasi baru: make migrate-create name=create_users_table
migrate-create:
ifndef name
	$(error name is required. Usage: make migrate-create name=create_users_table)
endif
	$(MIGRATE_CMD) create -ext sql -dir $(MIGRATION_DIR) -seq $(name)

# generate pem file
priv-key:
	openssl genpkey -algorithm RSA -out ./key/private.pem -pkeyopt rsa_keygen_bits:2048

pub-key:
	openssl rsa -pubout -in ./key/private.pem -out ./key/public.pem



.PHONY: dev sqlc migrate-up migrate-down migrate-create priv-key pub-key