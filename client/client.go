package client

// package main

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"bytes"
	"encoding/hex"
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
// everything that will change during the process will  be stored here
type FileSpace struct {

	// the UUID of File struct
	OwnedFilesUUIDs map[string]uuid.UUID

	// the UUID of File struct Mac
	OwnedFilesMacUUIDs map[string]uuid.UUID

	// the key of File struct encription Key
	OwnedFilesKeys map[string][]byte

	// the key of File struct Mac Key
	OwnedFilesMacKeys map[string][]byte

	// the sharklinksthat has been accept
	// the input is a hash of the file name and output is the UUID of its corresponding share link

	GivenSharedLinkUUID map[string]uuid.UUID
	GivenSharedLinkKey  map[string][]byte

	// maping username to a sharelink UUID created by the user
	OwnedFileInvitor      map[string][]string
	OwnedShareLinkUUID    map[string]uuid.UUID
	OwnedShareLinkKey     map[string][]byte
	OwnedShareLinkMacUUID map[string]uuid.UUID
	OwnedShareLinkMacKey  map[string][]byte
}

type File struct {
	// the struct of the file

	//the list of contents
	Contents []uuid.UUID

	// the macs of contents
	Macs []uuid.UUID
}

type ShareLinkHead struct {
	ShareLinkUUID uuid.UUID
	ShareLinkKey  []byte
}

type ShareLink struct {
	FromUserHashString     string
	ToUserHashString       string
	ShareLinkContentUUID   uuid.UUID
	ShareLinkMacUUID       uuid.UUID
	ShareLinkContentKey    []byte
	ShareLinkContentMackey []byte
	Sign                   []byte
}

// it is like a small file space, provided everything needed for the file operation
type ShareLinkContent struct {
	// the struct of the share link

	FileUUID    uuid.UUID
	FileMacUUID uuid.UUID
	FileKey     []byte
	FileMacKey  []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func getUUIDbytes(str string) (result []byte) {
	hash := userlib.Hash([]byte(str))

	return hash[:16]
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	// check if the username is empty
	if username == "" {
		return userdataptr, errors.New("the given username is empty")
	}

	var userdata User
	//store the name hash
	UsernameHash := userlib.Hash([]byte(username))
	userdata.UsernameHash = UsernameHash
	UsernameHashString := hex.EncodeToString(UsernameHash)

	//get the keys for public key enription
	userdata.EncryptionPublicKey, userdata.EncryptionPrivateKey, _ = userlib.PKEKeyGen()

	//store the public key in key store
	store_error := userlib.KeystoreSet(UsernameHashString+"Encription", userdata.EncryptionPublicKey)

	// if the username already exists
	if store_error != nil {
		return userdataptr, errors.New("the given username already exists")
	}

	// get the keys for the digital signature
	userdata.DSSignKey, userdata.DSVerifykey, _ = userlib.DSKeyGen()

	store_error = userlib.KeystoreSet(UsernameHashString+"Signature", userdata.DSVerifykey)

	// if the username already exists
	if store_error != nil {
		return userdataptr, errors.New("the given username already exists")
	}

	// initialize the file space
	userdata.FileRootKey = userlib.Argon2Key([]byte(username+"File"+password), userlib.RandomBytes(64), 16)

	// generate some keys
	filespace_mac_key, err := userlib.HashKDF(userdata.FileRootKey, []byte("mac"))

	if err != nil {
		return userdataptr, err
	}

	filespace_mac_key = filespace_mac_key[:16]

	filespace_encrpt_key, err := userlib.HashKDF(userdata.FileRootKey, []byte("encription"))
	if err != nil {
		return userdataptr, err
	}

	filespace_encrpt_key = filespace_encrpt_key[:16]

	var filespace FileSpace
	filespace.OwnedFilesUUIDs = make(map[string]uuid.UUID, 10)
	filespace.OwnedFilesKeys = make(map[string][]byte, 10)
	filespace.OwnedFilesMacUUIDs = make(map[string]uuid.UUID, 10)
	filespace.OwnedFilesMacKeys = make(map[string][]byte, 10)
	filespace.OwnedShareLinkUUID = make(map[string]uuid.UUID, 10)
	filespace.GivenSharedLinkUUID = make(map[string]uuid.UUID, 10)
	filespace.GivenSharedLinkKey = make(map[string][]byte, 10)
	filespace.OwnedShareLinkKey = make(map[string][]byte, 10)
	filespace.OwnedFileInvitor = make(map[string][]string, 10)
	filespace.OwnedShareLinkMacUUID = make(map[string]uuid.UUID, 10)
	filespace.OwnedShareLinkMacKey = make(map[string][]byte, 10)

	// store the file space
	UUID_filespace := uuid.New()
	userdata.FileSpaceUUID = UUID_filespace

	filespace_bytes, _ := json.Marshal(&filespace)
	filespace_ciper := userlib.SymEnc(filespace_encrpt_key, userlib.RandomBytes(16), filespace_bytes)

	userlib.DatastoreSet(UUID_filespace, filespace_ciper)

	// store the mac of the file space
	filespace_mac, err := userlib.HMACEval(filespace_mac_key, filespace_ciper)
	if err != nil {
		return userdataptr, nil
	}

	UUID_filespace_mac := uuid.New()
	userdata.FileSpaceMacUUID = UUID_filespace_mac

	userlib.DatastoreSet(UUID_filespace_mac, filespace_mac)

	// get the UUID of user struct
	UUID_data, _ := uuid.FromBytes(getUUIDbytes(username + "|" + password + "For User Struct"))

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
	UUID_mac, _ := uuid.FromBytes(getUUIDbytes(username + "|" + password + "For Mac"))

	mac_key := userlib.Argon2Key([]byte(password), []byte(username+"MAC"), 16)

	mac, err := userlib.HMACEval(mac_key, user_struct_ciper)

	if err != nil {
		return userdataptr, err
	}

	userlib.DatastoreSet(UUID_mac, mac)

	// store the hash for the username and password
	UUID_password, _ := uuid.FromBytes(getUUIDbytes(username))

	password_hash := userlib.Hash([]byte(password))
	userlib.DatastoreSet(UUID_password, password_hash)

	return userdataptr, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// first, check if the user exists
	UUID_password, _ := uuid.FromBytes(getUUIDbytes(username))
	password_hash, ok := userlib.DatastoreGet(UUID_password)

	if !ok {
		return userdataptr, errors.New("the given User doesn't exist")
	}

	// then check if the password is correct
	new_password_hash := userlib.Hash([]byte(password))
	correct_flag := userlib.HMACEqual(password_hash, new_password_hash)
	if !correct_flag {
		return userdataptr, errors.New("uncorrect password")
	}

	// then check the integrity
	UUID_mac, _ := uuid.FromBytes(getUUIDbytes(username + "|" + password + "For Mac"))

	UUID_data, _ := uuid.FromBytes(getUUIDbytes(username + "|" + password + "For User Struct"))

	mac, ok := userlib.DatastoreGet(UUID_mac)
	if !ok {
		return userdataptr, errors.New("the mac of User struct doesn't exist")
	}
	data, ok := userlib.DatastoreGet(UUID_data)
	if !ok {
		return userdataptr, errors.New("the data of User struct doesn't exist")
	}

	mac_key := userlib.Argon2Key([]byte(password), []byte(username+"MAC"), 16)

	new_mac, err := userlib.HMACEval(mac_key, data)

	if err != nil {
		return userdataptr, err
	}

	integrity_flag := userlib.HMACEqual(mac, new_mac)
	// fmt.Print(integrity_flag, "\n", mac, "\n", new_mac, "\n")

	if !integrity_flag {
		return userdataptr, errors.New("the User struct has been tampered")
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
		return errors.New("the filespace doesn't exist")
	}

	filespace_mac, ok := userlib.DatastoreGet(userdata.FileSpaceMacUUID)

	if ok == false {
		return errors.New("the filespace Mac doesn't exist")
	}

	// check the mac ~

	// generate the keys
	filespace_mac_key, _ := userlib.HashKDF(userdata.FileRootKey, []byte("mac"))
	filespace_mac_key = filespace_mac_key[:16]

	new_filespace_mac, err := userlib.HMACEval(filespace_mac_key, filespace_ciper)

	if err != nil {
		return err
	}

	integrity_flag := userlib.HMACEqual(filespace_mac, new_filespace_mac)

	if integrity_flag == false {
		return errors.New("the filespace has been tampered")
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

	if !ok {
		return filespace, errors.New("the given filespace doesn't exist")
	}

	// decript the filespace
	filespace_bytes := userlib.SymDec(filespace_encrpt_key, filespace_ciper)

	json.Unmarshal(filespace_bytes, &filespace)

	return filespace, nil

}

// update the mac and content of the file space
func (userdata *User) UpdateFileSpace(filespace FileSpace) {

	filespace_bytes, _ := json.Marshal(filespace)

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

	// some testing code
	// var new FileSpace
	// data,_ := userlib.DatastoreGet(userdata.FileSpaceUUID)
	// json.Unmarshal(data,&new)

	// fmt.Print(filespace.OwnedFilesUUIDs,"\n")
	// fmt.Print(new.OwnedFilesUUIDs,"\n")

}

// store a new file
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	filespace, err := userdata.GetFileSpace()
	// bug place

	if err != nil {
		return err
	}

	// check whether the file already exist

	var filename_hash [64]byte
	copy(filename_hash[:], userlib.Hash([]byte(filename)))

	filename_hash_string := hex.EncodeToString(filename_hash[:])

	// if this is totally a new file
	if (filespace.OwnedFilesUUIDs[filename_hash_string] == uuid.Nil) &&
		(filespace.GivenSharedLinkUUID[filename_hash_string] == uuid.Nil) {

		// generate keys
		// file_key, err := userlib.HashKDF(userdata.FileRootKey, filename_hash[:])

		// if err != nil {
		// 	return err
		// }

		// mac_key, err := userlib.HashKDF(userdata.FileRootKey, userlib.Hash([]byte(filename+"mac")))

		// if err != nil {
		// 	return err
		// }

		file_key := userlib.RandomBytes(16)
		mac_key := userlib.RandomBytes(16)

		UUID_file := uuid.New()

		filespace.OwnedFilesKeys[filename_hash_string] = file_key
		filespace.OwnedFilesUUIDs[filename_hash_string] = UUID_file
		filespace.OwnedFilesMacKeys[filename_hash_string] = mac_key

		var newFile File

		// encrpt the file content, store the content
		content_ciper := userlib.SymEnc(file_key, userlib.RandomBytes(16), content)

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
		newFile_ciper := userlib.SymEnc(file_key, userlib.RandomBytes(16), newFile_bytes)
		userlib.DatastoreSet(UUID_file, newFile_ciper)

		// store the mac of the file struct
		newFile_mac, err := userlib.HMACEval(mac_key, newFile_ciper)

		if err != nil {
			return err
		}

		UUID_file_strct_mac := uuid.New()
		userlib.DatastoreSet(UUID_file_strct_mac, newFile_mac)

		filespace.OwnedFilesMacUUIDs[filename_hash_string] = UUID_file_strct_mac

		userdata.UpdateFileSpace(filespace)
		return nil
	}

	// if want to overide a existing file

	// get everthing needed
	var UUID_file uuid.UUID
	var UUID_file_struct_mac uuid.UUID
	var file_key []byte
	var mac_key []byte

	// if the user is the owner of the file
	if filespace.OwnedFilesUUIDs[filename_hash_string] != uuid.Nil {
		UUID_file = filespace.OwnedFilesUUIDs[filename_hash_string]
		UUID_file_struct_mac = filespace.OwnedFilesMacUUIDs[filename_hash_string]
		file_key = filespace.OwnedFilesKeys[filename_hash_string]
		mac_key = filespace.OwnedFilesMacKeys[filename_hash_string]

	} else if filespace.GivenSharedLinkUUID[filename_hash_string] != uuid.Nil {
		// if the user is shared with the file
		share_link_content, err := filespace.GetShareLinkContent(filename, userdata.EncryptionPrivateKey)
		if err != nil {
			return err
		}
		UUID_file = share_link_content.FileUUID
		UUID_file_struct_mac = share_link_content.FileMacUUID
		file_key = share_link_content.FileKey
		mac_key = share_link_content.FileMacKey
	}

	var newFile File

	// encrpt the file content, store the content
	content_ciper := userlib.SymEnc(file_key, userlib.RandomBytes(16), content)
	UUID_file_content := uuid.New()
	newFile.Contents = append(newFile.Contents, UUID_file_content)
	userlib.DatastoreSet(UUID_file_content, content_ciper)

	// store the mac
	file_mac, err := userlib.HMACEval(mac_key, content_ciper)

	if err != nil {
		return err
	}
	UUID_file_mac := uuid.New()
	newFile.Macs = append(newFile.Macs, UUID_file_mac)
	userlib.DatastoreSet(UUID_file_mac, file_mac)

	// store the file structure

	newFile_bytes, _ := json.Marshal(newFile)

	// store the file struct itself
	newFile_ciper := userlib.SymEnc(file_key, userlib.RandomBytes(16), newFile_bytes)
	userlib.DatastoreSet(UUID_file, newFile_ciper)

	// store the mac of the file struct
	newFile_mac, err := userlib.HMACEval(mac_key, newFile_ciper)

	if err != nil {
		return nil
	}

	userlib.DatastoreSet(UUID_file_struct_mac, newFile_mac)

	return nil

}

// get the sharelink_content with checking
func (filespace FileSpace) GetShareLinkContent(filename string, PrivateKey userlib.PKEDecKey) (share_link_content ShareLinkContent, err error) {
	filename_hash_string := hex.EncodeToString(userlib.Hash([]byte(filename)))

	sharelink_ciper, ok := userlib.DatastoreGet(filespace.GivenSharedLinkUUID[filename_hash_string])

	if !ok {
		return share_link_content, errors.New("the sharelink does not exist")
	}

	sharelink_bytes := userlib.SymDec(filespace.GivenSharedLinkKey[filename_hash_string], sharelink_ciper)

	var sharelink ShareLink
	err = json.Unmarshal(sharelink_bytes, &sharelink)
	if err != nil {
		return share_link_content, err
	}

	// check the sharelink
	senderPublicSignKey, ok := userlib.KeystoreGet(sharelink.FromUserHashString + "Signature")

	if !ok {
		return share_link_content, errors.New("cannot get sender's public sign key")
	}

	// verify the sign
	SignContent := bytes.Join([][]byte{
		[]byte(sharelink.FromUserHashString),
		[]byte(sharelink.ToUserHashString),
		sharelink.ShareLinkContentUUID[:],
		sharelink.ShareLinkMacUUID[:],
		sharelink.ShareLinkContentKey,
		sharelink.ShareLinkContentMackey}, []byte(","))

	err = userlib.DSVerify(senderPublicSignKey, SignContent, sharelink.Sign)
	if err != nil {
		return share_link_content, errors.New("digital sign verification fails")
	}
	// everything about the sharelink is checked

	share_link_content_ciper, ok := userlib.DatastoreGet(sharelink.ShareLinkContentUUID)

	if !ok {
		return share_link_content, errors.New("the share link content does not exist in the Datastore")
	}

	share_link_content_mac, ok := userlib.DatastoreGet(sharelink.ShareLinkMacUUID)

	if !ok {
		return share_link_content, errors.New("the share link content Mac does not exist in the Datastore")
	}

	new_mac, err := userlib.HMACEval(sharelink.ShareLinkContentMackey, share_link_content_ciper)

	if err != nil {
		return share_link_content, err
	}

	integrity_flag := userlib.HMACEqual(share_link_content_mac, new_mac)

	if !integrity_flag {
		return share_link_content, errors.New("the sharelink content has been tampered")
	}

	share_link_content_bytes := userlib.SymDec(sharelink.ShareLinkContentKey, share_link_content_ciper)

	err = json.Unmarshal(share_link_content_bytes, &share_link_content)

	if err != nil {
		return share_link_content, err
	}

	return share_link_content, err

}

// get the file header if it is not tampered
func (filespace FileSpace) GetFileStruct(filename string) (file File, err error) {
	var filename_hash [64]byte
	copy(filename_hash[:], userlib.Hash([]byte(filename)))

	filename_hash_string := hex.EncodeToString(filename_hash[:])

	FileUUID := filespace.OwnedFilesUUIDs[filename_hash_string]
	FileMacUUID := filespace.OwnedFilesMacUUIDs[filename_hash_string]
	FileKey := filespace.OwnedFilesKeys[filename_hash_string]
	FileMacKey := filespace.OwnedFilesMacKeys[filename_hash_string]

	if FileUUID == uuid.Nil {
		return file, errors.New("the given file doesn't exist in this filespace")
	}

	// first, check if the File struct's integrity

	// fmt.Print(FileUUID,"\n")

	ciper_file, ok := userlib.DatastoreGet(FileUUID)
	if ok == false {
		return file, errors.New("the File struct doesn't exist")
	}

	file_mac, ok := userlib.DatastoreGet(FileMacUUID)

	// fmt.Print(file_mac,"\n")
	if ok == false {
		return file, errors.New("the File struct Mac doesn't exist")
	}

	new_file_mac, err := userlib.HMACEval(FileMacKey, ciper_file)
	if err != nil {
		return file, err
	}
	file_struct_integrity := userlib.HMACEqual(file_mac, new_file_mac)
	// fmt.Print(new_file_mac,"\n")

	if !file_struct_integrity {
		return file, errors.New("the File struct has been tampered")
	}

	// decript the file struct
	bytes_file_struct := userlib.SymDec(FileKey, ciper_file)
	err = json.Unmarshal(bytes_file_struct, &file)

	if err != nil {
		return file, err
	}

	return file, nil
}

func (share_link_content ShareLinkContent) GetFileStruct() (file File, err error) {

	FileUUID := share_link_content.FileUUID
	FileMacUUID := share_link_content.FileMacUUID
	FileKey := share_link_content.FileKey
	FileMacKey := share_link_content.FileMacKey

	// first, check if the File struct's integrity

	ciper_file, ok := userlib.DatastoreGet(FileUUID)
	if !ok {
		return file, errors.New("the File struct doesn't exist")
	}

	file_mac, ok := userlib.DatastoreGet(FileMacUUID)

	if !ok {
		return file, errors.New("the File struct Mac doesn't exist")
	}

	new_file_mac, err := userlib.HMACEval(FileMacKey, ciper_file)

	if err != nil {
		return file, err
	}

	file_struct_integrity := userlib.HMACEqual(file_mac, new_file_mac)

	if !file_struct_integrity {
		return file, errors.New("the File struct has been tampered")
	}

	// decript the file struct
	bytes_file_struct := userlib.SymDec(FileKey, ciper_file)
	err = json.Unmarshal(bytes_file_struct, &file)

	if err != nil {
		return file, err
	}

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

		new_content_mac, err := userlib.HMACEval(FileMacKey, content)

		if err != nil {
			return err
		}

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

	filename_hash_string := hex.EncodeToString(filename_hash[:])

	// get everthing needed
	var file File
	var FileUUID uuid.UUID
	var FileMacUUID uuid.UUID
	var FileKey []byte
	var FileMacKey []byte

	// if the user is the owner of the file
	if filespace.OwnedFilesUUIDs[filename_hash_string] != uuid.Nil {
		FileUUID = filespace.OwnedFilesUUIDs[filename_hash_string]
		FileMacUUID = filespace.OwnedFilesMacUUIDs[filename_hash_string]
		FileKey = filespace.OwnedFilesKeys[filename_hash_string]
		FileMacKey = filespace.OwnedFilesMacKeys[filename_hash_string]

		file, err = filespace.GetFileStruct(filename)

		if err != nil {
			return err
		}

	} else if filespace.GivenSharedLinkUUID[filename_hash_string] != uuid.Nil {
		// if the user is shared with the file
		share_link_content, err := filespace.GetShareLinkContent(filename, userdata.EncryptionPrivateKey)
		if err != nil {
			return err
		}
		FileUUID = share_link_content.FileUUID
		FileMacUUID = share_link_content.FileMacUUID
		FileKey = share_link_content.FileKey
		FileMacKey = share_link_content.FileMacKey

		file, err = share_link_content.GetFileStruct()

		if err != nil {
			return err
		}

	} else {
		return errors.New("the given file does not exists")
	}

	// get the file header

	// prepare the new content
	ciper_content := userlib.SymEnc(FileKey, userlib.RandomBytes(16), content)
	mac_content, err := userlib.HMACEval(FileMacKey, ciper_content)

	if err != nil {
		return err
	}

	UUID_content := uuid.New()
	UUID_mac := uuid.New()

	// refresh data store
	userlib.DatastoreSet(UUID_content, ciper_content)
	userlib.DatastoreSet(UUID_mac, mac_content)

	// refresh the file
	file.Contents = append(file.Contents, UUID_content)
	file.Macs = append(file.Macs, UUID_mac)

	file_bytes, err := json.Marshal(file)
	if err != nil {
		return err
	}

	file_ciper := userlib.SymEnc(FileKey, userlib.RandomBytes(16), file_bytes)

	userlib.DatastoreSet(FileUUID, file_ciper)

	file_mac, err := userlib.HMACEval(FileMacKey, file_ciper)

	if err != nil {
		return err
	}
	userlib.DatastoreSet(FileMacUUID, file_mac)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var filename_hash [64]byte
	copy(filename_hash[:], userlib.Hash([]byte(filename)))
	filename_hash_string := hex.EncodeToString(filename_hash[:])

	filespace, err := userdata.GetFileSpace()

	var file File
	var FileKey []byte
	var FileMacKey []byte

	// the file is owned
	if filespace.OwnedFilesUUIDs[filename_hash_string] != uuid.Nil {
		FileKey = filespace.OwnedFilesKeys[filename_hash_string]
		FileMacKey = filespace.OwnedFilesMacKeys[filename_hash_string]

		if err != nil {
			return content, err
		}

		file, err = filespace.GetFileStruct(filename)

		if err != nil {
			return content, err
		}
	} else if filespace.GivenSharedLinkUUID[filename_hash_string] != uuid.Nil {
		share_link_content, err := filespace.GetShareLinkContent(filename, userdata.EncryptionPrivateKey)

		if err != nil {
			return content, err
		}
		file, err = share_link_content.GetFileStruct()

		if err != nil {
			return content, err
		}

		FileKey = share_link_content.FileKey
		FileMacKey = share_link_content.FileMacKey

	} else {
		return content, errors.New("the file trying to load does not exist")
	}

	err = file.CheckFile(FileMacKey)

	if err != nil {
		return content, err
	}

	// everything is good now, decription and change file

	var result []byte
	for i := range file.Contents {
		ciper_content, ok := userlib.DatastoreGet(file.Contents[i])
		if !ok {
			return content, errors.New("missing file content")
		}

		result = userlib.SymDec(FileKey, ciper_content)
		for j := range result {
			content = append(content, result[j])
		}

	}
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// check if the recipientUsername exists
	recipientUsername_hash_string := hex.EncodeToString(userlib.Hash([]byte(recipientUsername)))

	recipient_public_encryption_key, ok := userlib.KeystoreGet(recipientUsername_hash_string + "Encription")

	if !ok {
		return invitationPtr, errors.New("the given recipient doesn't exist")
	}

	// first, check if the invitor is the owner
	filespace, err := userdata.GetFileSpace()
	if err != nil {
		return invitationPtr, err
	}

	filename_hash_string := hex.EncodeToString(userlib.Hash([]byte(filename)))

	var sharelink_head ShareLinkHead

	sharelink_head.ShareLinkUUID = uuid.New()
	sharelink_head.ShareLinkKey = userlib.RandomBytes(16)

	var sharelink ShareLink
	sharelink.FromUserHashString = hex.EncodeToString(userdata.UsernameHash)
	sharelink.ToUserHashString = recipientUsername_hash_string

	UUIDFile := filespace.OwnedFilesUUIDs[filename_hash_string]

	// if the invitor is the owner of the file
	if UUIDFile != uuid.Nil {
		// get everything needed for the file sharing
		var share_link_content ShareLinkContent
		share_link_content.FileUUID = filespace.OwnedFilesUUIDs[filename_hash_string]
		share_link_content.FileMacUUID = filespace.OwnedFilesMacUUIDs[filename_hash_string]
		share_link_content.FileKey = filespace.OwnedFilesKeys[filename_hash_string]
		share_link_content.FileMacKey = filespace.OwnedFilesMacKeys[filename_hash_string]

		// now the share_link_content get everything it needed
		// update sharelink
		sharelink.ShareLinkContentUUID = uuid.New()
		sharelink.ShareLinkMacUUID = uuid.New()
		sharelink.ShareLinkContentKey = userlib.RandomBytes(16)
		sharelink.ShareLinkContentMackey = userlib.RandomBytes(16)

		// ciper and store the shark_link_content
		share_link_content_bytes, _ := json.Marshal(share_link_content)
		share_link_content_ciper := userlib.SymEnc(sharelink.ShareLinkContentKey, userlib.RandomBytes(16), share_link_content_bytes)

		userlib.DatastoreSet(sharelink.ShareLinkContentUUID, share_link_content_ciper)

		share_link_content_mac, err := userlib.HMACEval(sharelink.ShareLinkContentMackey, share_link_content_ciper)

		if err != nil {
			return invitationPtr, err
		}

		userlib.DatastoreSet(sharelink.ShareLinkMacUUID, share_link_content_mac)

		// sign something to provided authuority and integrity

		SignContent := bytes.Join([][]byte{
			[]byte(sharelink.FromUserHashString),
			[]byte(sharelink.ToUserHashString),
			sharelink.ShareLinkContentUUID[:],
			sharelink.ShareLinkMacUUID[:],
			sharelink.ShareLinkContentKey,
			sharelink.ShareLinkContentMackey}, []byte(","))
		sign, err := userlib.DSSign(userdata.DSSignKey, SignContent)
		if err != nil {
			return invitationPtr, err
		}
		sharelink.Sign = sign

		// ciper the share link and store in datastore

		share_link_bytes, _ := json.Marshal(sharelink)
		share_link_ciper := userlib.SymEnc(sharelink_head.ShareLinkKey, userlib.RandomBytes(16), share_link_bytes)

		userlib.DatastoreSet(sharelink_head.ShareLinkUUID, share_link_ciper)

		// store the sharelinkhead
		sharelink_head_bytes, err := json.Marshal(sharelink_head)

		if err != nil {
			return invitationPtr, err
		}

		sharelink_head_ciper, err := userlib.PKEEnc(recipient_public_encryption_key, sharelink_head_bytes)

		if err != nil {
			return invitationPtr, err
		}

		invitationPtr = uuid.New()

		userlib.DatastoreSet(invitationPtr, sharelink_head_ciper)

		// update the filespace
		invitors := filespace.OwnedFileInvitor[filename_hash_string]
		invitors = append(invitors, recipientUsername_hash_string)
		filespace.OwnedFileInvitor[filename_hash_string] = invitors

		filespace.OwnedShareLinkUUID[recipientUsername_hash_string+filename_hash_string] = sharelink.ShareLinkContentUUID
		filespace.OwnedShareLinkKey[recipientUsername_hash_string+filename_hash_string] = sharelink.ShareLinkContentKey

		filespace.OwnedShareLinkMacUUID[recipientUsername_hash_string+filename_hash_string] = sharelink.ShareLinkMacUUID

		filespace.OwnedShareLinkMacKey[recipientUsername_hash_string+filename_hash_string] = sharelink.ShareLinkContentMackey

		userdata.UpdateFileSpace(filespace)
	} else if filespace.GivenSharedLinkUUID[filename_hash_string] != uuid.Nil {
		// if the user is shared with the file
		sharelink_ciper, ok := userlib.DatastoreGet(filespace.GivenSharedLinkUUID[filename_hash_string])
		if !ok {
			return invitationPtr, errors.New("the sharelink does not exist")
		}
		sharelink_bytes := userlib.SymDec(filespace.GivenSharedLinkKey[filename_hash_string], sharelink_ciper)

		var old_sharelink ShareLink

		err = json.Unmarshal(sharelink_bytes, &old_sharelink)

		if err != nil {
			return invitationPtr, err
		}

		// update sharelink
		sharelink.ShareLinkContentUUID = old_sharelink.ShareLinkContentUUID
		sharelink.ShareLinkMacUUID = old_sharelink.ShareLinkMacUUID
		sharelink.ShareLinkContentKey = old_sharelink.ShareLinkContentKey
		sharelink.ShareLinkContentMackey = old_sharelink.ShareLinkContentMackey

		// sign something to provided authuority and integrity

		SignContent := bytes.Join([][]byte{
			[]byte(sharelink.FromUserHashString),
			[]byte(sharelink.ToUserHashString),
			sharelink.ShareLinkContentUUID[:],
			sharelink.ShareLinkMacUUID[:],
			sharelink.ShareLinkContentKey,
			sharelink.ShareLinkContentMackey}, []byte(","))
		sign, err := userlib.DSSign(userdata.DSSignKey, SignContent)
		if err != nil {
			return invitationPtr, err
		}
		sharelink.Sign = sign

		// ciper the share link and store in datastore

		share_link_bytes, _ := json.Marshal(sharelink)
		share_link_ciper := userlib.SymEnc(sharelink_head.ShareLinkKey, userlib.RandomBytes(16), share_link_bytes)

		userlib.DatastoreSet(sharelink_head.ShareLinkUUID, share_link_ciper)

		// store the sharelinkhead
		sharelink_head_bytes, err := json.Marshal(sharelink_head)

		if err != nil {
			return invitationPtr, err
		}

		sharelink_head_ciper, err := userlib.PKEEnc(recipient_public_encryption_key, sharelink_head_bytes)

		if err != nil {
			return invitationPtr, err
		}

		invitationPtr = uuid.New()

		userlib.DatastoreSet(invitationPtr, sharelink_head_ciper)

		// update the filespace
		filespace.OwnedShareLinkUUID[recipientUsername_hash_string+filename_hash_string] = sharelink.ShareLinkContentUUID
		userdata.UpdateFileSpace(filespace)

	} else {
		return invitationPtr, errors.New("the provided file does not exist in the filespace")
	}

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// check if the owner already have the given filename in his filespace
	filename_hash_string := hex.EncodeToString(userlib.Hash([]byte(filename)))

	filespace, err := userdata.GetFileSpace()
	if err != nil {
		return err
	}

	if (filespace.OwnedFilesUUIDs[filename_hash_string] != uuid.Nil) || (filespace.GivenSharedLinkUUID[filename_hash_string] != uuid.Nil) {
		return errors.New("the given filename already exists")
	}

	// check whether the invitation is still valid
	sharelink_head_ciper, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("the given sharelink head does not exist in the Datastore")
	}

	sharelink_head_bytes, err := userlib.PKEDec(userdata.EncryptionPrivateKey, sharelink_head_ciper)

	if err != nil {
		return errors.New("here")
	}

	var sharelink_head ShareLinkHead
	err = json.Unmarshal(sharelink_head_bytes, &sharelink_head)
	if err != nil {
		return err
	}

	// get the sharelink

	sharelink_ciper, ok := userlib.DatastoreGet(sharelink_head.ShareLinkUUID)

	if !ok {
		return errors.New("the given sharelink does not exist in the Datastore")
	}

	sharelink_bytes := userlib.SymDec(sharelink_head.ShareLinkKey, sharelink_ciper)

	var sharelink ShareLink
	err = json.Unmarshal(sharelink_bytes, &sharelink)

	if err != nil {
		return err
	}

	// check authority and integrity by check the sign

	senderUsernameHashString := hex.EncodeToString(userlib.Hash([]byte(senderUsername)))
	senderPublicSignKey, ok := userlib.KeystoreGet(senderUsernameHashString + "Signature")
	if !ok {
		return errors.New("cannot get sender's public sign key")
	}

	// verify the sign
	SignContent := bytes.Join([][]byte{
		[]byte(sharelink.FromUserHashString),
		[]byte(sharelink.ToUserHashString),
		sharelink.ShareLinkContentUUID[:],
		sharelink.ShareLinkMacUUID[:],
		sharelink.ShareLinkContentKey,
		sharelink.ShareLinkContentMackey}, []byte(","))

	err = userlib.DSVerify(senderPublicSignKey, SignContent, sharelink.Sign)
	if err != nil {
		return errors.New("digital sign verification fails")
	}

	// check if the invitation still valid

	_, ok = userlib.DatastoreGet(sharelink.ShareLinkContentUUID)

	if !ok {
		return errors.New("the invitation has been revoked")
	}

	// everthing is checked, accept the invitation

	filespace.GivenSharedLinkUUID[filename_hash_string] = sharelink_head.ShareLinkUUID
	filespace.GivenSharedLinkKey[filename_hash_string] = sharelink_head.ShareLinkKey

	userdata.UpdateFileSpace(filespace)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// first, check if the user is the fileowner
	filespace, err := userdata.GetFileSpace()

	if err != nil {
		return err
	}

	filename_hash_string := hex.EncodeToString(userlib.Hash([]byte(filename)))

	if filespace.OwnedFilesUUIDs[filename_hash_string] == uuid.Nil {
		return errors.New("the user is not the owner of the file")
	}

	recipientUsername_hash_string := hex.EncodeToString(userlib.Hash([]byte(recipientUsername)))

	if filespace.OwnedShareLinkUUID[recipientUsername_hash_string+filename_hash_string] == uuid.Nil {
		return errors.New("the given filename is not currently shared with recipientUsername")
	}

	userlib.DatastoreDelete(filespace.OwnedShareLinkUUID[recipientUsername_hash_string+filename_hash_string])

	// delete(filespace.OwnedFileInvitor, recipientUsername_hash_string)

	vistors := filespace.OwnedFileInvitor[filename_hash_string]

	new_vistors := []string{}

	for _, vistor := range vistors {
		if vistor != recipientUsername_hash_string {
			new_vistors = append(new_vistors, vistor)
		}
	}
	filespace.OwnedFileInvitor[filename_hash_string] = new_vistors

	delete(filespace.OwnedShareLinkUUID, recipientUsername_hash_string+filename_hash_string)
	delete(filespace.OwnedShareLinkKey, recipientUsername_hash_string+filename_hash_string)
	delete(filespace.OwnedShareLinkMacUUID, recipientUsername_hash_string+filename_hash_string)
	delete(filespace.OwnedShareLinkMacKey, recipientUsername_hash_string+filename_hash_string)

	// refresh every other invitation

	userdata.UpdateFileSpace(filespace)

	if err != nil {
		return err
	}

	content, err := userdata.LoadFile(filename)

	if err != nil {
		return err
	}

	err = userdata.StoreFile(filename, content)

	if err != nil {
		return err
	}
	filespace, err = userdata.GetFileSpace()

	if err != nil {
		return err
	}
	var share_link_content ShareLinkContent

	share_link_content.FileUUID = filespace.OwnedFilesUUIDs[filename_hash_string]
	share_link_content.FileMacUUID = filespace.OwnedFilesMacUUIDs[filename_hash_string]
	share_link_content.FileKey = filespace.OwnedFilesKeys[filename_hash_string]
	share_link_content.FileMacKey = filespace.OwnedFilesMacKeys[filename_hash_string]

	share_link_content_bytes, _ := json.Marshal(share_link_content)

	for _, invitor := range filespace.OwnedFileInvitor[filename_hash_string] {
		key := invitor + filename_hash_string
		// update the share content
		share_link_content_ciper := userlib.SymEnc(filespace.OwnedShareLinkKey[invitor+filename_hash_string], userlib.RandomBytes(16), share_link_content_bytes)

		userlib.DatastoreSet(filespace.OwnedShareLinkUUID[invitor+filename_hash_string], share_link_content_ciper)

		new_mac, _ := userlib.HMACEval(filespace.OwnedShareLinkMacKey[key], share_link_content_ciper)

		userlib.DatastoreSet(filespace.OwnedShareLinkMacUUID[key], new_mac)

	}

	return nil
}

// func main() {
// 	location := uuid.New()
// 	data := []byte("hello world")
// 	userlib.DatastoreSet(location, data)
// 	userlib.DatastoreDelete(location)
// 	_, ok := userlib.DatastoreGet(location)
// 	if ok {
// 		panic("the data should have been deleted")
// 	}
// 	fmt.Print(ok)
// }
