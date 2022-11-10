package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	UsernameHash []byte
	// the keys for the public key encription
	EncryptionPublicKey  userlib.PKEEncKey
	EncryptionPrivateKey userlib.PKEDecKey
	// the keys for the digital signature
	DSSignKey   userlib.DSSignKey
	DSVerifykey userlib.DSVerifyKey

	// the uuid of the file owns and its corrsponding PrivateKey
	OwnedFiles map[uuid.UUID][]byte

	// the sharklinksthat has been accept
	// the input is a hash of the file name and output is the UUID of its corresponding share link
	SharedFiles map[[64]byte]uuid.UUID

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	// the struct of the file

	//the list of contents
	Contents []uuid.UUID
}

type ShareLink struct {
	// the struct of the share link

	FromUserHash [64]byte
	ToUserHash   [64]byte
	FileUUID     uuid.UUID
	FileKey      []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	// check if the username is empty
	if username == "" {
		return userdataptr, errors.New("The given username is empty!")
	}

	var userdata User
	//store the name hash
	UsernameHash := userlib.Hash([]byte(username))
	userdata.UsernameHash = UsernameHash

	//get the keys for public key enription
	userdata.EncryptionPublicKey, userdata.EncryptionPrivateKey, _ = userlib.PKEKeyGen()

	//store the public key in key store
	store_error := userlib.KeystoreSet(username+"Encription", userdata.EncryptionPublicKey)

	// if the username already exists
	if store_error != nil {
		return userdataptr, errors.New("The given username already exists!")
	}

	// get the keys for the digital signature
	userdata.DSSignKey, userdata.DSVerifykey, _ = userlib.DSKeyGen()

	store_error = userlib.KeystoreSet(username+"Signature", userdata.DSVerifykey)

	// if the username already exists
	if store_error != nil {
		return userdataptr, errors.New("The given username already exists!")
	}

	userdata.OwnedFiles = make(map[uuid.UUID][]byte)
	userdata.SharedFiles = make(map[[64]byte]uuid.UUID)

	// get the UUID of user struct
	UUID_data, _ := uuid.FromBytes([]byte(username + "This is a sepatator to satisfy minimum 16 length " + password + "For User Struct"))

	// get the symmetric encryption key
	user_encryption_key := userlib.Argon2Key([]byte(password), []byte(username), 16)

	// encrypte the user struct

	userdataptr = &userdata

	user_struct_bytes,err := json.Marshaler(&userdata)
	if err != nil{
		return userdataptr, err
	}

	iv := userlib.RandomBytes(16)

	user_struct_ciper := userlib.SymEnc(user_encryption_key, iv, user_struct_bytes)

	userlib.DatastoreSet(UUID_data, user_struct_ciper)

	// generate the mac for the user struct to provide integrity
	UUID_mac, _ := uuid.FromBytes([]byte(username + "This is a sepatator to satisfy minimum 16 length " + password + "For Mac"))

	mac_key := userlib.Argon2Key([]byte(password), []byte(username+"MAC"), 16)

	mac, _ := userlib.HMACEval(mac_key, user_struct_ciper)

	userlib.DatastoreSet(UUID_mac, mac)

	// store the hash for the username and password
	UUID_password, _ := uuid.FromBytes([]byte(username + "This is a sepatator to satisfy minimum 16 length "))

	password_hash := userlib.Hash([]byte(password))
	userlib.DatastoreSet(UUID_password,password_hash)

	return userdataptr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// first, check if the user exists
	UUID_password, _ := uuid.FromBytes([]byte(username + "This is a sepatator to satisfy minimum 16 length "))
	password_hash, ok := userlib.DatastoreGet(UUID_password)

	if ok == false{
		return userdataptr, errors.New("The given User doesn't exist")
	}

	// then check if the password is correct
	new_password_hash := userlib.Hash([]byte(password))
	correct_flag := userlib.HMACEqual(password_hash,new_password_hash)
	if correct_flag == false{
		return userdataptr,errors.New("Uncorrect Password!")
	}

	// then check the integrity
	UUID_mac, _ := uuid.FromBytes([]byte(username + "This is a sepatator to satisfy minimum 16 length " + password + "For Mac"))

	UUID_data, _ := uuid.FromBytes([]byte(username + "This is a sepatator to satisfy minimum 16 length " + password + "For User Struct"))

	mac, ok := userlib.DatastoreGet(UUID_mac)
	if ok == false{
		return userdataptr, errors.New("The mac of User struct doesn't exist")
	}
	data, ok := userlib.DatastoreGet(UUID_data)
	if ok == false{
		return userdataptr, errors.New("The data of User struct doesn't exist")
	}

	mac_key := userlib.Argon2Key([]byte(password), []byte(username+"MAC"), 16)

	new_mac,_ := userlib.HMACEval(mac_key, data)

	integrity_flag := userlib.HMACEqual(mac,new_mac)

	if integrity_flag == false{
		return userdataptr, errors.New("Warning! The User struct has been tampered!")
	}

	// everything is checked, get the user struct

	user_encryption_key := userlib.Argon2Key([]byte(password), []byte(username), 16)

	user_struct_bytes := userlib.SymDec(user_encryption_key, data)

	err = json.Unmarshal(user_struct_bytes, &userdata)
	if err != nil{
		return userdataptr, err
	}
	
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
