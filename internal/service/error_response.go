package service

import (
	"context"

	goahttp "goa.design/goa/v3/http"
	goa "goa.design/goa/v3/pkg"

	pkgErr "github.com/eclipse-xfsc/microservice-core-go/pkg/err"
)

func NewErrorResponse(ctx context.Context, err error) goahttp.Statuser {
	if err == nil {
		return nil
	}

	var newerr *pkgErr.Error
	switch e := err.(type) {
	case *pkgErr.Error:
		newerr = e
	case *goa.ServiceError:
		// Use goahttp.ErrorResponse to determine error kind
		goaerr := goahttp.NewErrorResponse(ctx, e)
		kind := pkgErr.GetKind(goaerr.StatusCode())
		newerr = &pkgErr.Error{
			ID:      e.ID,
			Kind:    kind,
			Message: e.Message,
			Err:     e,
		}
	default:
		newerr = &pkgErr.Error{
			ID:      pkgErr.NewID(),
			Kind:    pkgErr.Internal,
			Message: e.Error(),
			Err:     e,
		}
	}

	return newerr
}
