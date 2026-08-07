package callout

import (
	"fmt"
	"os"
	"strings"

	"github.com/nats-io/nkeys"
)

// LoadKeyPair resuelve un nkey a partir de un valor de configuración que puede ser la
// seed misma o el path a un archivo que la contiene.
//
// Se aceptan las dos formas porque conviven dos estilos de deploy: el bootstrap escribe
// las seeds a archivos (que se montan como secretos), mientras que un orquestador suele
// inyectarlas como variables de entorno. Distinguirlas por el prefijo de la seed evita
// tener dos variables por clave.
func LoadKeyPair(seedOrPath string) (nkeys.KeyPair, error) {
	seed, err := resolveSeed(seedOrPath)
	if err != nil {
		return nil, err
	}
	kp, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return nil, fmt.Errorf("callout: seed inválida: %w", err)
	}
	return kp, nil
}

// LoadCurveKeyPair resuelve un par curve25519 (XKey), cuya seed empieza con SX.
func LoadCurveKeyPair(seedOrPath string) (nkeys.KeyPair, error) {
	seed, err := resolveSeed(seedOrPath)
	if err != nil {
		return nil, err
	}
	kp, err := nkeys.FromCurveSeed([]byte(seed))
	if err != nil {
		return nil, fmt.Errorf("callout: seed de XKey inválida: %w", err)
	}
	return kp, nil
}

// resolveSeed devuelve la seed, leyéndola del archivo si lo que se pasó es un path.
//
// Una seed nkey siempre empieza con `S` y no tiene separadores de path, así que el
// prefijo alcanza para distinguirla sin tocar el filesystem.
func resolveSeed(seedOrPath string) (string, error) {
	value := strings.TrimSpace(seedOrPath)
	if value == "" {
		return "", fmt.Errorf("callout: seed vacía")
	}

	if strings.HasPrefix(value, "S") && !strings.ContainsAny(value, "/\\") {
		return value, nil
	}

	data, err := os.ReadFile(value)
	if err != nil {
		return "", fmt.Errorf("callout: leer la seed de %q: %w", value, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// ReadPubKey lee una pubkey de cuenta, aceptando igual que LoadKeyPair el valor directo
// o un path.
func ReadPubKey(valueOrPath string) (string, error) {
	value := strings.TrimSpace(valueOrPath)
	if value == "" {
		return "", fmt.Errorf("callout: pubkey vacía")
	}
	// Una pubkey de cuenta empieza con `A`.
	if strings.HasPrefix(value, "A") && !strings.ContainsAny(value, "/\\") {
		return value, nil
	}
	data, err := os.ReadFile(value)
	if err != nil {
		return "", fmt.Errorf("callout: leer la pubkey de %q: %w", value, err)
	}
	return strings.TrimSpace(string(data)), nil
}
