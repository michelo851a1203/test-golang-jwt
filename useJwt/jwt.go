package useJwt

import (
	"github.com/dgrijalva/jwt-go"
)

type UseJwtModel struct {
}

var (
	jwtSecret = "jwt_secret"
)

func NewWithJwtModel() UseJwtModel {
	return UseJwtModel{}
}

type MyClaims struct {
	Account string `json:"account"`
	Role    string `json:"role"`
	jwt.StandardClaims
}

func (useJwtModel *UseJwtModel) CreateTokenCore(myClaims *MyClaims) (string, error) {
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, myClaims)
	token, err := tokenClaims.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}
	return token, nil
}

func (useJwtModel *UseJwtModel) ValidateToken(token string) (*MyClaims, error) {
	tokenClaims, err := jwt.ParseWithClaims(token, &MyClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claimInfo, ok := tokenClaims.Claims.(*MyClaims); ok {
		return claimInfo, nil
	}
	return nil, nil
}

func (useJwtModel *UseJwtModel) GetValidationError(err error) (string, error) {
	if validationError, ok := err.(*jwt.ValidationError); ok {
		resultString := ""
		switch {
		case validationError.Errors&jwt.ValidationErrorMalformed != 0:
			resultString = "token malformed"
		case validationError.Errors&jwt.ValidationErrorNotValidYet != 0:
			resultString = "token not valid yet"
		case validationError.Errors&jwt.ValidationErrorExpired != 0:
			resultString = "token expired"
		case validationError.Errors&jwt.ValidationErrorUnverifiable != 0:
			resultString = "token unverifiable"
		case validationError.Errors&jwt.ValidationErrorSignatureInvalid != 0:
			resultString = "signature invalid"
		}
		return resultString, nil
	}
	return "", err
}
