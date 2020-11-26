//go:generate go run -tags generate gen.go
//Es necesario hacer un go get github.com/zserge/lorca para cargarlo

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"

	"github.com/zserge/lorca"
)

// Go types that are bound to the UI must be thread-safe, because each binding
// is executed in its own goroutine. In this simple case we may use atomic
// operations, but for more complex cases one should use proper synchronization.
type user struct {
	usnername string
	password  string
}

// respuesta del servidor
type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

// TODO? -- Delete?
type fileStruct struct {
	Filename  string
	Data      string
	typeFile  string
	extension string
}

type policy struct {
	Folder string
	Cycle  string // Daily, Weekly, Monthly
	Scheme string //Full, Incremental, Differential
}

// Function to check errors.
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func retrieveFiles() [][]string {
	var arr [][]string

	fmt.Println(len(gPolicy))
	for _, f := range gPolicy {
		var arr2 []string
		arr2 = append(arr2, f.Folder)
		arr2 = append(arr2, f.Cycle)
		arr2 = append(arr2, f.Scheme)
		arr = append(arr, arr2)
	}
	return arr
}

//function to encrypt files (TWOFISH)
func encryptF(data []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

//function to decrypt files
func decryptF(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func encryptFile(filename, data, filetype, extension string, key []byte) []byte {

	//encryptedData := encryptF(fileData, key)

	FileJSON := &fileStruct{Filename: filename, Data: data, typeFile: filetype, extension: extension}

	file, err := json.Marshal(FileJSON)
	chk(err)

	return file
}

//helper function for decryptic files
func decryptFile(filename string, key []byte) []byte {
	data, _ := ioutil.ReadFile(filename)
	return decryptF(data, key)
}

func pack(src string, buf io.Writer) error {
	// tar > gzip > buf
	zr := gzip.NewWriter(buf)
	tw := tar.NewWriter(zr)

	// walk through every file in the folder
	filepath.Walk(src, func(file string, fi os.FileInfo, err error) error {
		// generate tar header
		header, err := tar.FileInfoHeader(fi, file)
		if err != nil {
			return err
		}

		// must provide real name
		// (see https://golang.org/src/archive/tar/common.go?#L626)
		header.Name = filepath.ToSlash(file)

		// write header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		// if not a dir, write file content
		if !fi.IsDir() {
			data, err := os.Open(file)
			if err != nil {
				return err
			}
			if _, err := io.Copy(tw, data); err != nil {
				return err
			}
		}
		return nil
	})

	// produce tar
	if err := tw.Close(); err != nil {
		return err
	}
	// produce gzip
	if err := zr.Close(); err != nil {
		return err
	}
	//
	return nil
}

//1. get base data storage file.
func saveAndStore(user, fileLocation, cycle, scheme string) {

	var buf bytes.Buffer
	err := pack(fileLocation, &buf)

	// write the .tar.gzip
	fileToWrite, err := os.OpenFile("./compress.tar.gzip", os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(600))
	if err != nil {
		panic(err)
	}
	if _, err := io.Copy(fileToWrite, &buf); err != nil {
		panic(err)
	}
	defer fileToWrite.Close()
	encryptOrDecryptFileWithKey("C", "AES128", "abcd", "compress.tar.gzip", "compress.tar.gzip.enc", false)

	encryptedFile, err := os.Open("compress.tar.gzip.enc")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("POST", "https://localhost:10443/saveFile", encryptedFile)
	req.Header.Add("username", user)
	req.Header.Add("name", filepath.Base(fileLocation))
	r, err := client.Do(req)

	chk(err)
	_ = os.Remove("compress.tar.gzip")
	_ = os.Remove("compress.tar.gzip.enc")
	println(r.Body)

	policy := policy{}
	policy.Folder = fileLocation
	policy.Cycle = cycle   // Default
	policy.Scheme = scheme // Default
	gPolicy[len(gPolicy)] = policy
}

func createBackup(fileInFolderPath, backupFileInFolderPath string) {
	var bin *os.File
	var err error
	bin, err = os.Open(fileInFolderPath)
	chk(err)
	defer bin.Close()

	data, err := ioutil.ReadAll(bin)
	chk(err)

	//create backup of object and save as backup file - ?TODO use date as identifier?
	_ = ioutil.WriteFile(backupFileInFolderPath, data, 0644)
}

//handle file input
func (u *user) handleFiles(filelocation, cycle, scheme string) {
	saveAndStore(u.usnername, filelocation, cycle, scheme)
}

// fuction to encrypt (AES)
func encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// function to decrypt (AES)
func decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}

// function to compress
func compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	w.Write(data)           // escribimos los datos
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

// function to decompress
func decompress(data []byte) []byte {
	var b bytes.Buffer // b contendrá los datos descomprimidos

	r, err := zlib.NewReader(bytes.NewReader(data)) // lector descomprime al leer

	chk(err)         // comprobamos el error
	io.Copy(&b, r)   // copiamos del descompresor (r) al buffer (b)
	r.Close()        // cerramos el lector (buffering)
	return b.Bytes() // devolvemos los datos descomprimidos
}

// function to encode from []bytes to string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// function to decode from string to []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

func (u *user) Login(un string, p string) bool {
	var response resp

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(p))
	keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
	keyData := keyClient[32:64] // la otra para los datos (256 bits)

	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // aceleramos su uso con un precálculo

	pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
	chk(err)

	keyPub := pkClient.Public()           // extraemos la clave pública por separado
	pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
	chk(err)

	// ** ejemplo de registro
	data := url.Values{}                 // estructura para contener los valores
	data.Set("cmd", "login")             // comando (string)
	data.Set("user", un)                 // usuario (string)
	data.Set("pass", encode64(keyLogin)) // "contraseña" a base64

	// comprimimos y codificamos la clave pública
	data.Set("pubkey", encode64(compress(pubJSON)))

	// comprimimos, ciframos y codificamos la clave privada
	data.Set("prikey", encode64(encrypt(compress(pkJSON), keyData)))

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)

	fmt.Println(r.Body)
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}

	u.usnername = un
	json.Unmarshal(bodyBytes, &response)
	fmt.Println(response.Msg)
	fmt.Println(response.Ok)
	return response.Ok
}

func (u *user) Register(un string, p string) bool {
	var response resp
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(p))
	keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
	keyData := keyClient[32:64] // la otra para los datos (256 bits)

	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // aceleramos su uso con un precálculo

	pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
	chk(err)

	keyPub := pkClient.Public()           // extraemos la clave pública por separado
	pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
	chk(err)

	// ** ejemplo de registro
	data := url.Values{}                 // estructura para contener los valores
	data.Set("cmd", "register")          // comando (string)
	data.Set("user", un)                 // usuario (string)
	data.Set("pass", encode64(keyLogin)) // "contraseña" a base64

	// comprimimos y codificamos la clave pública
	data.Set("pubkey", encode64(compress(pubJSON)))

	// comprimimos, ciframos y codificamos la clave privada
	data.Set("prikey", encode64(encrypt(compress(pkJSON), keyData)))

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}
	json.Unmarshal(bodyBytes, &response)

	if response.Ok {
		_, err = os.Create("config.json")
		encryptOrDecryptFileWithKey("C", "AES128", "abcd", "config.json", "config.json.enc", false)
	}
	return response.Ok
}

func (u *user) getUser() string {
	return u.usnername
}

//read policys from json
func readConfigJSON(filename string) []policy {
	var Policy []policy
	byteValue, _ := ioutil.ReadFile(filename)
	json.Unmarshal(byteValue, &Policy)

	return Policy
}

// Create and bind Go object to the UI
var u user
var gPolicy map[int]policy

//save all the policys andencrypt json
func encryptPolicyInMemory() {
	var arrpolicy []policy

	for i := 0; i < len(gPolicy); i++ {
		arrpolicy = append(arrpolicy, gPolicy[i])
	}

	file, _ := json.MarshalIndent(arrpolicy, "", "")

	_ = ioutil.WriteFile("config.json", file, 0644)

	encryptOrDecryptFileWithKey("C", "AES128", "abcd", "config.json", "config.json.enc", true)

	_ = os.Remove("users.json")
}

func main() {
	//ui args
	args := []string{}
	if runtime.GOOS == "linux" {
		args = append(args, "--class=Lorca")
	}
	ui, err := lorca.New("", "", 800, 500, args...)
	if err != nil {
		log.Fatal(err)
	}
	defer ui.Close()

	// A simple way to know when UI is ready (uses body.onload event in JS)
	ui.Bind("start", func() {
		log.Println("UI is ready")
	})

	// Binding the backup menu html for switching the page when login is OK.
	ui.Bind("menu", func() {
		b2, err := ioutil.ReadFile("./www/menu.html") // just pass the file name
		if err != nil {
			fmt.Print(err)
		}
		html2 := string(b2) // convert content to a 'string'
		ui.Load("data:text/html," + url.PathEscape(html2))
	})
	// Create and bind Go object to the UI
	u := &user{}

	ui.Bind("login", u.Login)
	ui.Bind("register", u.Register)

	ui.Bind("filesToGo", u.handleFiles)
	ui.Bind("getUser", u.getUser)
	ui.Bind("getFilesArr", retrieveFiles)

	b, err := ioutil.ReadFile("./www/index.html") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	html := string(b) // convert content to a 'string'
	ui.Load("data:text/html," + url.PathEscape(html))

	encryptOrDecryptFileWithKey("D", "AES128", "abcd", "config.json.enc", "config.json", true)
	var Config = readConfigJSON("config.json")

	gPolicy = make(map[int]policy)

	for i := 0; i < len(Config); i++ {
		gPolicy[i] = Config[i]
	}

	// Wait until the interrupt signal arrives or browser window is closed
	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}
	encryptPolicyInMemory()
	log.Println("exiting...")
}
