package middleware

import (
	"github.com/raystack/shield-go/pkg"
	shieldv1beta1 "github.com/raystack/shield/proto/v1beta1"
	"net/http"
)

type ResourcePath struct {
	Path   string
	Method string
}

type ResourceControlFunc func(*http.Request) ResourceControl

type ResourceControl struct {
	// Resource should be in the form of "object_namespace:object_id"
	// for e.g. "project:07d00b42-7d5a-46b4-9d57-dda3fb7721b9"
	Resource   string
	Permission string
}

func (ea *AuthHandler) WithAuthorization(base http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get user from context
		_, ok := r.Context().Value(AuthenticatedUserContextKey).(*shieldv1beta1.User)
		if !ok {
			http.Error(w, "user not found", http.StatusUnauthorized)
			return
		}

		// find path to resource mapping
		rc, resourceMappingExist := ea.MapRequestToResource(r)
		if !resourceMappingExist {
			// if no mapping found, should deny the request by default
			if ea.denyByDefault {
				http.Error(w, "not allowed", http.StatusUnauthorized)
				return
			} else {
				base.ServeHTTP(w, r)
				return
			}
		}

		allowed, err := pkg.CheckAccess(r.Context(), ea.httpClient, ea.shieldHost, r.Header, rc.Resource, rc.Permission)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !allowed {
			http.Error(w, "not allowed", http.StatusUnauthorized)
			return
		}

		// authorized
		base.ServeHTTP(w, r)
	}
}

func (ea *AuthHandler) MapRequestToResource(r *http.Request) (ResourceControl, bool) {
	path := ResourcePath{
		Path:   r.URL.Path,
		Method: r.Method,
	}
	rc, mappingExist := ea.resourceControlStore[path]
	return rc(r), mappingExist
}
