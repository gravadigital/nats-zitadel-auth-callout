// Command session imprime la sesión que el callout derivaría para una identidad, y el
// prefijo de inbox que le corresponde.
//
// Existe por dos motivos:
//
//   - Diagnóstico: para leer un subject de un log o del monitoreo y saber de quién es.
//   - Contrato con los clientes: cada cliente tiene que derivar su propia sesión para poder
//     fijar su prefijo de inbox. Este comando es la referencia contra la cual verificar una
//     implementación en otro lenguaje.
//
// Uso:
//
//	session <sub> [instancia]           # a partir del `sub` de Zitadel
//	session --token <access-token>      # a partir de un token (le extrae el `sub`)
//
// El modo --token NO verifica la firma: solo decodifica el payload para sacar el `sub`.
// Verificar es tarea del callout.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/grava/gestion/auth-callout/internal/authz"
)

// defaultInstance es la instancia asumida si no se pasa una. Coincide con el default del
// binario del callout.
const defaultInstance = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "session: %v\n", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("uso: session <sub> [instancia]  |  session --token <access-token> [instancia]")
	}

	var subject string
	instance := defaultInstance

	if args[0] == "--token" {
		if len(args) < 2 {
			return fmt.Errorf("--token necesita el access token")
		}
		var err error
		subject, err = subjectFromToken(args[1])
		if err != nil {
			return err
		}
		if len(args) > 2 {
			instance = args[2]
		}
	} else {
		subject = args[0]
		if len(args) > 1 {
			instance = args[1]
		}
	}

	if instance = strings.TrimSpace(instance); instance == "" {
		instance = defaultInstance
	}

	id := authz.Identity{
		Instance: instance,
		Session:  authz.DeriveSession(subject),
		Type:     authz.UserTypePerson,
		Subject:  subject,
	}

	fmt.Printf("sub       %s\n", id.Subject)
	fmt.Printf("session   %s\n", id.Session)
	fmt.Printf("inbox     %s\n", id.InboxPrefix())
	fmt.Printf("pub       %s.%s.<svc>.<method>\n", id.Instance, id.Session)
	return nil
}

// subjectFromToken saca el `sub` del payload de un JWT. No verifica la firma: es un helper
// de diagnóstico, y el que valida es el callout.
func subjectFromToken(token string) (string, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("no parece un JWT (tiene %d partes en vez de 3): "+
			"si Zitadel emitió un token opaco, poné el tipo de token de acceso en JWT", len(parts))
	}

	// El payload viene en base64url sin padding.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decodificar el payload del token: %w", err)
	}

	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parsear el payload del token: %w", err)
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("el token no trae `sub`")
	}
	return claims.Subject, nil
}
