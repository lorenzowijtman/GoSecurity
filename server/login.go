/*

Este programa muestra cómo hacer login y registro entre cliente y servidor,
así como el uso de HTTPS (HTTP sobre TLS) mediante certificados (autofirmados).

Conceptos: JSON, AES-CTR, RSA, compresión, Base64, TLS

ejemplos de uso:

go run login.go srv

go run login.go cli

*/

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/crypto/scrypt"
)

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// función para cifrar (con AES en este caso), adjunta el IV al principio
func encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// función para descifrar (con AES en este caso)
func decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}

// función para comprimir
func compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	w.Write(data)           // escribimos los datos
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

// función para descomprimir
func decompress(data []byte) []byte {
	var b bytes.Buffer // b contendrá los datos descomprimidos

	r, err := zlib.NewReader(bytes.NewReader(data)) // lector descomprime al leer

	chk(err)         // comprobamos el error
	io.Copy(&b, r)   // copiamos del descompresor (r) al buffer (b)
	r.Close()        // cerramos el lector (buffering)
	return b.Bytes() // devolvemos los datos descomprimidos
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// respuesta del servidor
type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string) {
	r := resp{Ok: ok, Msg: msg}    // formateamos respuesta
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

func ReadUsersJson(filename string) []user {
	var Users []user
	byteValue, _ := ioutil.ReadFile(filename)
	json.Unmarshal(byteValue, &Users)

	return Users
}

func main() {
	fmt.Println("login.go :: un ejemplo de login mediante TLS/HTTP en Go.")
	s := "Introduce srv para funcionalidad de servidor y cli para funcionalidad de cliente"
	if len(os.Args) > 2 {
		switch os.Args[1] {
		case "srv":
			//Decrypt users.json.enc with password (os.Args[2])
			encryptOrDecryptFileWithKey("D", "AES128", os.Args[2], "users.json.enc", "users.json", true)
			var Users = ReadUsersJson("users.json")

			//_ = os.Remove("users.json")
			fmt.Println("Entrando en modo servidor...")
			server(Users)
		default:
			fmt.Println("Parámetro '", os.Args[1], "' desconocido. ", s)
		}
	} else {
		fmt.Println(s)
	}
}

/***
SERVIDOR
***/

// ejemplo de tipo para un usuario
type user struct {
	Name string            // nombre de usuario
	Hash []byte            // hash de la contraseña
	Salt []byte            // sal para la contraseña
	Data map[string]string // datos adicionales del usuario
}

// mapa con todos los usuarios
// (se podría codificar en JSON y escribir/leer de disco para persistencia)
var gUsers map[int]user

func encryptUsersInMemory() {
	var Users []user
	for i := 0; i < len(gUsers); i++ {
		Users = append(Users, gUsers[i])
	}
	fmt.Println(len(Users))

	file, _ := json.MarshalIndent(Users, "", " ")

	_ = ioutil.WriteFile("users.json", file, 0644)

	encryptOrDecryptFileWithKey("C", "AES128", os.Args[2], "users.json", "users.json.enc", true)

	_ = os.Remove("users.json")

}

func SetupCloseHandler() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal")
		encryptUsersInMemory()
		os.Exit(0)
	}()
}

// gestiona el modo servidor
func server(Users []user) {
	gUsers = make(map[int]user)

	for i := 0; i < len(Users); i++ {
		gUsers[i] = Users[i]
	}

	http.HandleFunc("/", handler)                 // asignamos un handler global
	http.HandleFunc("/saveFile", handlerSaveFile) // asignamos un handler global
	SetupCloseHandler()

	// escuchamos el puerto 10443 con https y comprobamos el error
	// Para generar certificados autofirmados con openssl usar:
	//    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=ES/ST=Alicante/L=Alicante/O=UA/OU=Org/CN=www.ua.com"
	chk(http.ListenAndServeTLS(":10443", "cert.pem", "key.pem", nil))
}

func userAlreadyExists(un string, index *int) bool {

	for i := 0; i < len(gUsers); i++ {
		if gUsers[i].Name == un {
			if index != nil {
				*index = i
			}
			fmt.Println(gUsers[i].Name)

			return true
		}
	}
	return false
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "register": // ** registro
		fmt.Println(len(gUsers))
		u := user{}
		u.Name = req.Form.Get("user")              // nombre
		u.Salt = make([]byte, 16)                  // sal (16 bytes == 128 bits)
		rand.Read(u.Salt)                          // la sal es aleatoria
		u.Data = make(map[string]string)           // reservamos mapa de datos de usuario
		u.Data["private"] = req.Form.Get("prikey") // clave privada
		u.Data["public"] = req.Form.Get("pubkey")  // clave pública
		password := decode64(req.Form.Get("pass")) // contraseña (keyLogin)

		// "hasheamos" la contraseña con scrypt
		u.Hash, _ = scrypt.Key(password, u.Salt, 16384, 8, 1, 32)

		if userAlreadyExists(req.Form.Get("user"), nil) {
			response(w, false, "Usuario ya registrado")
		} else {
			gUsers[len(gUsers)] = u
			response(w, true, "Usuario registrado")
		}

	case "login": // ** login
		var index int

		if !userAlreadyExists(req.Form.Get("user"), &index) {
			response(w, false, "Usuario inexistente")
		}

		password := decode64(req.Form.Get("pass"))                           // obtenemos la contraseña
		hash, _ := scrypt.Key(password, gUsers[index].Salt, 16384, 8, 1, 32) // scrypt(contraseña)
		if bytes.Compare(gUsers[index].Hash, hash) != 0 {                    // comparamos
			response(w, false, "Credenciales inválidas")
		} else {
			response(w, true, "Credenciales válidas")
		}

	case "retrieveFiles": // ** login
		//var user = req.Form.Get("user")

	default:
		response(w, false, "Comando inválido")
	}
}
func handlerSaveFile(w http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	chk(err)

	var username = req.Header.Get("username")
	var name = req.Header.Get("name")
	fmt.Println(username)
	fmt.Println(name)

	absPath, _ := filepath.Abs("data")

	var userFolder = absPath + "/" + username

	if _, err := os.Stat(userFolder); os.IsNotExist(err) {
		os.Mkdir(userFolder, os.ModeDir)
	}

	var filename = name + ".tar.gzip.enc"

	var fileInFolderPath = userFolder + "/" + filename

	var fout *os.File
	fout, err = os.Create(fileInFolderPath)
	defer fout.Close()

	_ = ioutil.WriteFile(fileInFolderPath, body, 600)
}
