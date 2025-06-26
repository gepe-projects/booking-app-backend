package helper

import (
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

//
// =============================
// PGTYPE TEXT (string helpers)
// =============================
//

// StringToPGTextValid mengubah string menjadi pgtype.Text dengan Valid = true (selalu valid).
// Cocok digunakan untuk field yang wajib (required).
func StringToPGTextValid(s string) pgtype.Text {
	return pgtype.Text{
		String: s,
		Valid:  true,
	}
}

// StringToPGText mengubah string menjadi pgtype.Text dengan Valid = false jika string kosong.
// Cocok digunakan untuk field opsional/nullable.
func StringToPGText(s string) pgtype.Text {
	return pgtype.Text{
		String: s,
		Valid:  s != "",
	}
}

// PGTextToStringOrNil mengembalikan pointer ke string jika Valid = true, jika tidak akan mengembalikan nil.
// Berguna untuk serialisasi JSON agar field bisa dihilangkan (`omitempty`) jika NULL.
func PGTextToStringOrNil(text pgtype.Text) *string {
	if text.Valid {
		return &text.String
	}
	return nil
}

//
// =============================
// PGTYPE INTEGER
// =============================
//

// ToPGInt32 mengubah string ke int32, atau mengembalikan defaultVal jika gagal parse.
// Cocok untuk konversi query parameter atau input user.
func ToPGInt32(s string, defaultVal int32) int32 {
	if s == "" {
		return defaultVal
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return int32(i)
}

//
// =============================
// PGTYPE UUID
// =============================
//

// ToPGUUID mengubah uuid.UUID ke pgtype.UUID. Selalu menghasilkan Valid = true.
func ToPGUUID(id uuid.UUID) pgtype.UUID {
	var pgID pgtype.UUID
	_ = pgID.Scan(id.String())
	return pgID
}

// ToPGUUIDFromString mengubah string ke pgtype.UUID. Return error jika parsing gagal.
func ToPGUUIDFromString(s string) (pgtype.UUID, error) {
	var pgID pgtype.UUID
	err := pgID.Scan(s)
	return pgID, err
}

// NullUUIDFromString mengubah string ke pgtype.UUID. Return Valid = false jika string kosong.
func NullUUIDFromString(s string) pgtype.UUID {
	var pgID pgtype.UUID
	if s == "" {
		return pgtype.UUID{Valid: false}
	}
	_ = pgID.Scan(s)
	return pgID
}

//
// =============================
// PGTYPE BOOLEAN
// =============================
//

// ToPGBool mengubah bool native Go menjadi pgtype.Bool dengan Valid = true.
func ToPGBool(b bool) pgtype.Bool {
	return pgtype.Bool{
		Bool:  b,
		Valid: true,
	}
}

//
// =============================
// PGTYPE TIMESTAMP
// =============================
//

// ToPGTimestamptz mengubah time.Time menjadi pgtype.Timestamptz.
// Jika time.IsZero(), maka Valid = false (NULL di PostgreSQL).
func ToPGTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{
		Time:  t,
		Valid: !t.IsZero(),
	}
}

// PGTimestamptzToTimePtr mengubah pgtype.Timestamptz menjadi *time.Time (nil jika tidak valid).
func PGTimestamptzToTimePtr(t pgtype.Timestamptz) *time.Time {
	if t.Valid {
		return &t.Time
	}
	return nil
}

// PGTimestamptzToTime mengubah pgtype.Timestamptz menjadi time.Time.
// Jika tidak valid, return time.Time{} (zero value).
func PGTimestamptzToTime(t pgtype.Timestamptz) time.Time {
	if t.Valid {
		return t.Time
	}
	return time.Time{}
}

//
// =============================
// PARSING UTILITIES
// =============================
//

// ParseInt32 mengubah string menjadi int32, atau mengembalikan defaultVal jika gagal parse.
func ParseInt32(s string, defaultVal int) int32 {
	if s == "" {
		return int32(defaultVal)
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return int32(defaultVal)
	}
	return int32(i)
}

// ParseInt64 mengubah string menjadi int64, atau mengembalikan defaultVal jika gagal parse.
func ParseInt64(s string, defaultVal int) int64 {
	if s == "" {
		return int64(defaultVal)
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return int64(defaultVal)
	}
	return int64(i)
}

// ParseFloat64 mengubah string menjadi float64, atau mengembalikan defaultVal jika gagal parse.
func ParseFloat64(s string, defaultVal float64) float64 {
	if s == "" {
		return defaultVal
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return defaultVal
	}
	return f
}

// IsEmptyString mengecek apakah string kosong.
func IsEmptyString(s string) bool {
	return s == ""
}

// ParseUUID mengubah string menjadi uuid.UUID. Return error jika format tidak valid.
func ParseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}
