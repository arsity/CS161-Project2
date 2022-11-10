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

	FileRootKey []byte

	// the UUID and key of the File Space
	FileSpaceUUID    uuid.UUID
	FileSpaceMacUUID uuid.UUID

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// the file space of a user
type FileSpace struct {

	// the UUID of File struct
	OwnedFilesUUIDs map[[64]byte]uuid.UUID

	// the UUID of File struct Mac
	OwnedFilesMacUUIDs map[[64]byte]uuid.UUID

	// the key of File struct encription Key
	OwnedFilesKeys map[[64]byte][]byte

	// the key of File struct Mac Key
	OwnedFilesMacKeys map[[64]byte][]byte

	// the sharklinksthat has been accept
	// the input is a hash of the file name and output is the UUID of its corresponding share link
	SharedFiles map[[64]byte]uuid.UUID
}

type File struct {
	// the struct of the file

	//the list of contents
	Contents []uuid.UUID

	// the macs of contents
	Macs []uuid.UUID
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

	// initialize the file space
	userdata.FileRootKey = userlib.Argon2Key([]byte(username+"File"+password), userlib.RandomBytes(64), 16)

	// generate some keys
	filespace_mac_key, _ := userlib.HashKDF(userdata.FileRootKey, []byte("mac"))
	filespace_mac_key = filespace_mac_key[:16]

	filespace_encrpt_key, _ := userlib.HashKDF(userdata.FileRootKey, []byte("encription"))
	filespace_encrpt_key = filespace_encrpt_key[:16]

	var filespace FileSpace
	filespace.OwnedFilesUUIDs = make(map[[64]byte][]byte)
	filespace.OwnedFilesKeys = make(map[[64]byte][]byte)
	filespace.SharedFiles = make(map[[64]byte]uuid.UUID)

	// store the file space
	UUID_filespace := uuid.New()
	userdata.FileSpaceUUID = UUID_filespace

	filespace_bytes, _ := json.Marshal(&filespace)
	filespace_ciper := userlib.SymEnc(filespace_encrpt_key, userlib.RandomBytes(16), filespace_bytes)

	userlib.DatastoreSet(UUID_filespace, filespace_ciper)

	// store the mac of the file space
	filespace_mac, _ := userlib.HMACEval(filespace_mac_key, filespace_ciper)

	UUID_filespace_mac := uuid.New()
	userdata.FileSpaceMacUUID = UUID_filespace_mac

	userlib.DatastoreSet(UUID_filespace_mac, filespace_mac)

	// get the UUID of user struct
	UUID_data, _ := uuid.FromBytes([]byte(username + "This is a sepatator to satisfy minimum 16 length " + password + "For User Struct"))

	// get the symmetric encryption key
	user_encryption_key := userlib.Argon2Key([]byte(password), []byte(username), 16)

	// encrypte the user struct

	userdataptr = &userdata

	user_struct_bytes, err := json.Marshal(&userdata)
	if err != nil {
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
	userlib.DatastoreSet(UUID_password, password_hash)

	return userdataptr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// first, check if the user exists
	UUID_password, _ := uuid.FromBytes([]byte(username + "This is a sepatator to satisfy minimum 16 length "))
	password_hash, ok := userlib.DatastoreGet(UUID_password)

	if ok == false {
		return userdataptr, errors.New("The given User doesn't exist")
	}

	// then check if the password is correct
	new_password_hash := userlib.Hash([]byte(password))
	correct_flag := userlib.HMACEqual(password_hash, new_password_hash)
	if correct_flag == false {
		return userdataptr, errors.New("Uncorrect Password!")
	}

	// then check the integrity
	UUID_mac, _ := uuid.FromBytes([]byte(username + "This is a sepatator to satisfy minimum 16 length " + password + "For Mac"))

	UUID_data, _ := uuid.FromBytes([]byte(username + "This is a sepatator to satisfy minimum 16 length " + password + "For User Struct"))

	mac, ok := userlib.DatastoreGet(UUID_mac)
	if ok == false {
		return userdataptr, errors.New("The mac of User struct doesn't exist")
	}
	data, ok := userlib.DatastoreGet(UUID_data)
	if ok == false {
		return userdataptr, errors.New("The data of User struct doesn't exist")
	}

	mac_key := userlib.Argon2Key([]byte(password), []byte(username+"MAC"), 16)

	new_mac, _ := userlib.HMACEval(mac_key, data)

	integrity_flag := userlib.HMACEqual(mac, new_mac)

	if integrity_flag == false {
		return userdataptr, errors.New("Warning! The User struct has been tampered!")
	}

	// everything is checked, get the user struct

	user_encryption_key := userlib.Argon2Key([]byte(password), []byte(username), 16)

	user_struct_bytes := userlib.SymDec(user_encryption_key, data)

	err = json.Unmarshal(user_struct_bytes, &userdata)
	if err != nil {
		return userdataptr, err
	}

	return userdataptr, nil
}

// check if the filespace has been tampered
func (userdata *User) CheckFileSpace() (err error) {
	// fetch the mac and file space
	filespace_ciper, ok := userlib.DatastoreGet(userdata.FileSpaceUUID)
	if ok == false {
		return errors.New("The filespace doesn't exist")
	}

	filespace_mac, ok := userlib.DatastoreGet(userdata.FileSpaceMacUUID)

	if ok == false {
		return errors.New("The filespace Mac doesn't exist")
	}

	// check the mac ~

	// generate the keys
	filespace_mac_key, _ := userlib.HashKDF(userdata.FileRootKey, []byte("mac"))
	filespace_mac_key = filespace_mac_key[:16]

	new_filespace_mac, _ := userlib.HMACEval(filespace_mac_key, filespace_ciper)

	integrity_flag := userlib.HMACEqual(filespace_mac, new_filespace_mac)

	if integrity_flag == false {
		return errors.New("The filespace has been tampered!")
	}

	return nil
}

// get the file space if it is not tampered
func (userdata *User) GetFileSpace() (filespace FileSpace, err error) {
	// check if the file has been tampered
	integrity_flag := userdata.CheckFileSpace()
	if integrity_flag != nil {
		return filespace, integrity_flag
	}

	filespace_encrpt_key, _ := userlib.HashKDF(userdata.FileRootKey, []byte("encription"))
	filespace_encrpt_key = filespace_encrpt_key[:16]

	filespace_ciper, ok := userlib.DatastoreGet(userdata.FileSpaceUUID)

	if ok == false {
		return filespace, errors.New("The given filespace doesn't exist")
	}

	// decript the filespace

	json.Unmarshal(filespace_ciper, &filespace)

	return filespace, nil

}

// update the mac and content of the file space
func (userdata *User) UpdateFileSpace(filespace FileSpace) {

	filespace_bytes, _ := json.Marshal(&filespace)

	filespace_encrpt_key, _ := userlib.HashKDF(userdata.FileRootKey, []byte("encription"))
	filespace_encrpt_key = filespace_encrpt_key[:16]

	// store the file space
	filespace_ciper := userlib.SymEnc(filespace_encrpt_key, userlib.RandomBytes(16), filespace_bytes)

	userlib.DatastoreSet(userdata.FileSpaceUUID, filespace_ciper)

	// store the mac
	filespace_mac_key, _ := userlib.HashKDF(userdata.FileRootKey, []byte("mac"))
	filespace_mac_key = filespace_mac_key[:16]

	filespace_mac, _ := userlib.HMACEval(filespace_mac_key, filespace_ciper)

	userlib.DatastoreSet(userdata.FileSpaceMacUUID, filespace_mac)

}

// store a new file
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	filespace, err := userdata.GetFileSpace()

	if err != nil {
		return err
	}

	var filename_hash [64]byte
	copy(filename_hash[:], userlib.Hash([]byte(filename)))

	// generate keys
	file_key, _ := userlib.HashKDF(userdata.FileRootKey, filename_hash[:])
	mac_key, _ := userlib.HashKDF(userdata.FileRootKey, userlib.Hash([]byte(filename+"mac")))

	UUID_file := uuid.New()

	filespace.OwnedFilesKeys[filename_hash] = file_key
	filespace.OwnedFilesUUIDs[filename_hash] = UUID_file
	filespace.OwnedFilesMacKeys[filename_hash] = mac_key

	var newFile File

	// encrpt the file content, store the content
	content_ciper := userlib.SymEnc(file_key, userlib.RandomBytes(64), content)

	UUID_file_content := uuid.New()
	newFile.Contents = append(newFile.Contents, UUID_file_content)
	userlib.DatastoreSet(UUID_file_content, content_ciper)

	// store the mac
	file_mac, _ := userlib.HMACEval(mac_key, content_ciper)
	UUID_file_mac := uuid.New()
	newFile.Macs = append(newFile.Macs, UUID_file_mac)
	userlib.DatastoreSet(UUID_file_mac, file_mac)

	// store the file structure

	newFile_bytes, _ := json.Marshal(newFile)

	// store the file struct itself
	newFile_ciper := userlib.SymEnc(file_key, userlib.RandomBytes(64), newFile_bytes)
	userlib.DatastoreSet(UUID_file, newFile_ciper)

	// store the mac of the file struct
	newFile_mac, _ := userlib.HMACEval(mac_key, newFile_ciper)

	UUID_file_strct_mac := uuid.New()
	userlib.DatastoreSet(UUID_file_strct_mac, newFile_mac)

	userdata.UpdateFileSpace(filespace)

	return nil

}

// get the file header if it is not tampered
func (filespace FileSpace) GetFileStruct(filename string) (file File, err error) {
	var filename_hash [64]byte
	copy(filename_hash[:], userlib.Hash([]byte(filename)))

	FileUUID := filespace.OwnedFilesUUIDs[filename_hash]
	FileMacUUID := filespace.OwnedFilesMacUUIDs[filename_hash]
	FileKey := filespace.OwnedFilesKeys[filename_hash]
	FileMacKey := filespace.OwnedFilesMacKeys[filename_hash]

	// first, check if the File struct's integrity

	ciper_file, ok := userlib.DatastoreGet(FileUUID)
	if ok == false {
		return file, errors.New("The File struct doesn't exist!")
	}

	file_mac, ok := userlib.DatastoreGet(FileMacUUID)

	if ok == false {
		return file, errors.New("The File struct Mac doesn't exist!")
	}

	new_file_mac, _ := userlib.HMACEval(FileMacKey, ciper_file)
	file_struct_integrity := userlib.HMACEqual(file_mac, new_file_mac)

	if file_struct_integrity == false {
		return file, errors.New("The File struct Mac has been tampered!")
	}

	// decript the file struct
	bytes_file_struct := userlib.SymDec(FileKey, ciper_file)
	json.Unmarshal(bytes_file_struct, file)

	return file, nil
}

// check inside the file
func (file File) CheckFile(FileMacKey []byte) (err error) {

	err = nil

	for i := range file.Contents {
		content, ok := userlib.DatastoreGet(file.Contents[i])
		if ok == false {
			return errors.New("Some content of the file does not exist!")
		}

		content_mac, ok := userlib.DatastoreGet(file.Macs[i])
		if ok == false {
			return errors.New("Some Mac of the file does not exist!")
		}

		new_content_mac, _ := userlib.HMACEval(FileMacKey, content)

		flag := userlib.HMACEqual(content_mac, new_content_mac)

		if flag == false {
			return errors.New("Some content of the file has been tampered!")
		}

	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	var filename_hash [64]byte
	copy(filename_hash[:], userlib.Hash([]byte(filename)))
	filespace, err := userdata.GetFileSpace()

	FileUUID := filespace.OwnedFilesUUIDs[filename_hash]
	FileMacUUID := filespace.OwnedFilesMacUUIDs[filename_hash]
	FileKey := filespace.OwnedFilesKeys[filename_hash]
	FileMacKey := filespace.OwnedFilesMacKeys[filename_hash]

	if err != nil {
		return err
	}

	// get the file header

	file, err := filespace.GetFileStruct(filename)

	if err != nil {
		return err
	}

	// prepare the new content
	ciper_content := userlib.SymEnc(FileKey, userlib.RandomBytes(64), content)
	mac_content, _ := userlib.HMACEval(FileMacKey, ciper_content)

	UUID_content := uuid.New()
	UUID_mac := uuid.New()

	// refresh data store
	userlib.DatastoreSet(UUID_content, ciper_content)
	userlib.DatastoreSet(UUID_mac, mac_content)

	// refresh the file
	file.Contents = append(file.Contents, UUID_content)
	file.Macs = append(file.Macs, UUID_mac)

	file_bytes, _ := json.Marshal(file)

	file_ciper := userlib.SymEnc(FileKey, userlib.RandomBytes(64), file_bytes)

	userlib.DatastoreSet(FileUUID, file_ciper)

	file_mac, _ := userlib.HMACEval(FileMacKey, file_ciper)
	userlib.DatastoreSet(FileMacUUID, file_mac)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var filename_hash [64]byte
	copy(filename_hash[:], userlib.Hash([]byte(filename)))
	filespace, err := userdata.GetFileSpace()
	// FileUUID := filespace.OwnedFilesUUIDs[filename_hash]
	// FileMacUUID := filespace.OwnedFilesMacUUIDs[filename_hash]
	FileKey := filespace.OwnedFilesKeys[filename_hash]
	FileMacKey := filespace.OwnedFilesMacKeys[filename_hash]

	if err != nil {
		return content, err
	}

	file, err := filespace.GetFileStruct(filename)

	if err != nil {
		return content, err
	}

	err = file.CheckFile(FileMacKey)

	if err != nil {
		return content, err
	}

	// everything is good now, decription and change file

	result := []byte{}
	for i := range file.Contents {
		ciper_content, ok := userlib.DatastoreGet(file.Contents[i])
		if ok == false {
			return content, errors.New("Missing File Content")
		}

		result = userlib.SymDec(FileKey, ciper_content)
		for j := range result {
			content = append(content, result[j])
		}

	}
	return content, nil
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
