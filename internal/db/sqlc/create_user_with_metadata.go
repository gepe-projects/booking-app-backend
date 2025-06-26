package db

import (
	"context"
	"encoding/json"

	logger "booking-app/pkg"
)

type UserMetadata struct {
	Device string `json:"device"`
}

type CreateuserWithMetadataParams struct {
	CreateUserParams
	UserMetadata
}
type CreateUserTxResult struct {
	User
}

func (s *store) CreateUserWithMetadata(ctx context.Context, arg CreateuserWithMetadataParams) (CreateUserTxResult, error) {
	var result CreateUserTxResult
	err := s.ExecTx(ctx, func(q *Queries) error {
		var err error

		result.User, err = q.CreateUser(ctx, arg.CreateUserParams)
		if err != nil {
			logger.Log.Errorf("failed to create user: %v", err)
			return err
		}

		jsonMeta, err := json.Marshal(arg.UserMetadata)
		if err != nil {
			logger.Log.Errorf("failed to marshal metadata: %v", err)
			return err
		}

		err = q.CreateUserMetadata(ctx, CreateUserMetadataParams{
			UserID:   result.ID,
			Metadata: jsonMeta,
		})
		if err != nil {
			logger.Log.Errorf("failed to create user_metadata: %v", err)
			return err
		}

		return nil
	})
	return result, err
}
