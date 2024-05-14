package client

import (
	"bytes"
	"encoding/json"

	// CS 161 Project 2

	// Only the following imports are allowed! ANY additional imports
	// may break the autograder!
	// - bytes
	// - encoding/hex
	// - encoding/json
	// - errors
	// - fmt
	// - github.com/cs161-staff/project2-userlib
	// - github.com/google/uuid
	// - strconv
	// - strings

	"errors"
	"fmt"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).

	// Useful for creating new error messages to return using errors.New("...")

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
	Username    string
	Password    string
	RSA_private userlib.PKEDecKey
	DS_private  userlib.DSSignKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// NOTE: The following methods have toy (insecure!) implementations.

type MacValue struct {
	Value []byte
	Mac   []byte
}

func CreateMacValue(value []byte, mac []byte) (mac_value_bytes []byte, err error) {
	var mac_value MacValue
	mac_value.Mac = mac
	mac_value.Value = value
	mac_value_bytes, err = json.Marshal(mac_value)
	return mac_value_bytes, err
}

func GetMacValue(mac_value_bytes []byte) (value []byte, mac []byte, err error) {
	var mac_value MacValue
	err = json.Unmarshal(mac_value_bytes, &mac_value)
	return mac_value.Value, mac_value.Mac, err
}

type SignEncrypt struct {
	UUID           userlib.UUID
	Encryption_RSA []byte
	Encryption_DS  []byte
	Mac_RSA        []byte
	Mac_DS         []byte
}

func CreateSignEncrypt(file_uuid userlib.UUID, encryption_rsa []byte, encryption_ds []byte, mac_rsa []byte, mac_ds []byte) (sign_encrypt_bytes []byte, err error) {
	var sign_encrypt SignEncrypt
	sign_encrypt.UUID = file_uuid
	sign_encrypt.Encryption_RSA = encryption_rsa
	sign_encrypt.Encryption_DS = encryption_ds
	sign_encrypt.Mac_RSA = mac_rsa
	sign_encrypt.Mac_DS = mac_ds
	sign_encrypt_bytes, err = json.Marshal(sign_encrypt)
	return sign_encrypt_bytes, err
}

func GetSignEncrypt(sign_encrypt_byes []byte) (file_uuid userlib.UUID, encryption_rsa []byte, encryption_ds []byte, mac_rsa []byte, mac_ds []byte, err error) {
	var sign_encrypt SignEncrypt
	err = json.Unmarshal(sign_encrypt_byes, &sign_encrypt)
	return sign_encrypt.UUID, sign_encrypt.Encryption_RSA, sign_encrypt.Encryption_DS, sign_encrypt.Mac_RSA, sign_encrypt.Mac_DS, err
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	// check if username is null
	if username == "" {
		return nil, errors.New("username is blank")
	}

	// check duplicate username
	var username_uuid userlib.UUID
	var username_bytes []byte
	username_bytes, err = json.Marshal(username)
	username_bytes = userlib.Hash(username_bytes)[:16]
	if err != nil {
		return nil, err
	}
	username_uuid, err = uuid.FromBytes(username_bytes)
	if err != nil {
		return nil, err
	}
	var exists bool
	_, exists = userlib.DatastoreGet(username_uuid)
	if exists {
		return nil, errors.New("username already exists")
	}

	// generate private/public keys
	var RSA_public userlib.PKEEncKey
	var RSA_private userlib.PKEDecKey
	RSA_public, RSA_private, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	var DS_public userlib.DSVerifyKey
	var DS_private userlib.DSSignKey
	DS_private, DS_public, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	// make User struct
	var userdata User
	userdata.Username = username
	userdata.Password = password
	userdata.RSA_private = RSA_private
	userdata.DS_private = DS_private

	// hash password, salt is username,
	var hashed_password []byte
	var password_bytes []byte
	password_bytes, err = json.Marshal(password)
	if err != nil {
		return nil, err
	}

	hashed_password = userlib.Argon2Key(password_bytes, username_bytes, 256)

	// mac password
	var maced_password []byte
	var mac_key []byte
	var username_password_bytes []byte
	var mac_bytes []byte
	username_password_bytes, err = json.Marshal(username + password)
	if err != nil {
		return nil, err
	}
	mac_bytes, err = json.Marshal("mac")
	if err != nil {
		return nil, err
	}
	mac_key = userlib.Argon2Key(username_password_bytes, mac_bytes, 16)
	maced_password, err = userlib.HMACEval(mac_key, hashed_password)
	if err != nil {
		return nil, err
	}

	//store username and password in datstore
	var username_password_maced_bytes []byte
	username_password_maced_bytes, err = CreateMacValue(hashed_password, maced_password)
	if err != nil {
		return nil, err
	}

	userlib.DatastoreSet(username_uuid, username_password_maced_bytes)

	//store username and public key in keystore
	userlib.KeystoreSet(username+"RSA", RSA_public)
	userlib.KeystoreSet(username+"DS", DS_public)

	// encrypt and mac setup
	var user_struct_bytes []byte
	var encrypt_key []byte
	var enc_bytes []byte
	user_struct_bytes, err = json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	enc_bytes, err = json.Marshal(username + "enc")
	if err != nil {
		return nil, err
	}
	mac_bytes, err = json.Marshal(username + "mac")
	if err != nil {
		return nil, err
	}
	encrypt_key = userlib.Argon2Key(username_password_bytes, enc_bytes, 16)
	mac_key = userlib.Argon2Key(username_password_bytes, mac_bytes, 16)

	// encrypt and mac user struct
	var random_bytes []byte
	var encrypted_user_struct []byte
	var maced_user_struct []byte
	random_bytes = userlib.RandomBytes(16)
	encrypted_user_struct = userlib.SymEnc(encrypt_key, random_bytes, user_struct_bytes)
	maced_user_struct, err = userlib.HMACEval(mac_key, encrypted_user_struct)
	if err != nil {
		return nil, err
	}

	// store struct
	var struct_uuid_string_bytes []byte
	var struct_uuid userlib.UUID
	var maced_user_struct_bytes []byte
	struct_uuid_string_bytes, err = json.Marshal(username + "struct")
	struct_uuid_string_bytes = userlib.Hash(struct_uuid_string_bytes)[:16]
	if err != nil {
		return nil, err
	}
	struct_uuid, err = uuid.FromBytes(struct_uuid_string_bytes)
	if err != nil {
		return nil, err
	}
	maced_user_struct_bytes, err = CreateMacValue(encrypted_user_struct, maced_user_struct)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(struct_uuid, maced_user_struct_bytes)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User // user struct
	var exists bool
	var input_password_bytes []byte  // input passowrd
	var hashed_input_password []byte // hashed input passowrd
	var username_bytes []byte        // input username
	var password_maced_bytes []byte  // password bytes stored in DataStore
	var hashed_actual_password []byte
	var check_password_mac []byte
	var given_password_mac []byte

	var username_uuid userlib.UUID

	userdataptr = &userdata

	input_password_bytes, err = json.Marshal(password)
	if err != nil {
		return nil, err
	}
	username_bytes, err = json.Marshal(username)
	if err != nil {
		return nil, err
	}
	username_bytes = userlib.Hash(username_bytes)[:16]
	username_uuid, err = uuid.FromBytes(username_bytes)
	if err != nil {
		return nil, err
	}

	// get password mac bytes from database
	hashed_input_password = userlib.Argon2Key(input_password_bytes, username_bytes, 256)
	password_maced_bytes, exists = userlib.DatastoreGet(username_uuid)
	if !exists {
		return nil, errors.New("username not found")
	}
	hashed_actual_password, given_password_mac, err = GetMacValue(password_maced_bytes)
	if err != nil {
		return nil, err
	}

	// check the mac of password
	var mac_key []byte
	var username_password_bytes []byte
	var mac_bytes []byte
	username_password_bytes, err = json.Marshal(username + password)
	if err != nil {
		return nil, err
	}
	mac_bytes, err = json.Marshal("mac")
	if err != nil {
		return nil, err
	}
	mac_key = userlib.Argon2Key(username_password_bytes, mac_bytes, 16)
	check_password_mac, err = userlib.HMACEval(mac_key, hashed_actual_password)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(given_password_mac, check_password_mac) {
		return nil, errors.New("password mac not equal")
	}

	// check password
	if bytes.Equal(hashed_actual_password, hashed_input_password) {
		var struct_uuid_string_bytes []byte
		var struct_uuid userlib.UUID
		var maced_user_struct_bytes []byte
		var encrypted_user_struct []byte
		var given_struct_mac []byte
		var actual_struct_mac []byte
		var enc_bytes []byte
		var encrypt_key []byte

		struct_uuid_string_bytes, err = json.Marshal(username + "struct")
		if err != nil {
			return nil, err
		}
		struct_uuid_string_bytes = userlib.Hash(struct_uuid_string_bytes)[:16]
		struct_uuid, err = uuid.FromBytes(struct_uuid_string_bytes)
		if err != nil {
			return nil, err
		}

		// get user struct
		maced_user_struct_bytes, exists = userlib.DatastoreGet(struct_uuid)
		if !exists {
			return nil, errors.New("user struct with the specified struct_uuid not in datastore")
		}
		encrypted_user_struct, given_struct_mac, err = GetMacValue(maced_user_struct_bytes)
		if err != nil {
			return nil, err
		}
		enc_bytes, err = json.Marshal(username + "enc")
		if err != nil {
			return nil, err
		}
		mac_bytes, err = json.Marshal(username + "mac")
		if err != nil {
			return nil, err
		}
		mac_key = userlib.Argon2Key(username_password_bytes, mac_bytes, 16)
		actual_struct_mac, err = userlib.HMACEval(mac_key, encrypted_user_struct)
		if err != nil {
			return nil, err
		}

		// check user struct mac
		if !userlib.HMACEqual(given_struct_mac, actual_struct_mac) {
			return nil, errors.New("struct mac not equal")
		}

		// decrypt user struct
		encrypt_key = userlib.Argon2Key(username_password_bytes, enc_bytes, 16)
		json.Unmarshal(userlib.SymDec(encrypt_key, encrypted_user_struct), &userdata)
		return &userdata, nil
	} else {
		return nil, errors.New("password is incorrect")
	}
}

// owner's file struct
type FileStructPointer struct {
	FileStructEncrypt []byte
	FileStructMac     []byte
	FileStructUUID    userlib.UUID
	//list of shared structs
	SharedStructsMap map[string]FileStructPointer
}

type FileStruct struct {
	Owner      string
	UserList   []string
	StartBlock userlib.UUID
	EndBlock   userlib.UUID

	//change at revocation
	BlockEncrypt []byte
	BlockMac     []byte
}

type BlockStruct struct {
	NextBlock userlib.UUID
	Content   []byte
}

func CreateBlocks(content []byte, encryptKey []byte, macKey []byte, blockUUID userlib.UUID) (blockEndUUID userlib.UUID, err error) {
	var blockUUIDBytes []byte
	var new_block_struct BlockStruct
	var new_block_struct_bytes []byte
	var encrypted_block_bytes []byte
	var mac_block_bytes []byte
	var block_new_maced_bytes []byte
	var random_bytes []byte
	var derived_enc_key []byte
	var derived_mac_key []byte

	// store new block
	new_block_struct.NextBlock = uuid.New()
	new_block_struct.Content = content
	new_block_struct_bytes, err = json.Marshal(new_block_struct)
	if err != nil {
		return uuid.UUID{0}, err
	}
	blockUUIDBytes, err = json.Marshal(blockUUID)
	if err != nil {
		return uuid.UUID{0}, err
	}
	derived_enc_key, err = userlib.HashKDF(encryptKey, blockUUIDBytes)
	if err != nil {
		return uuid.UUID{0}, err
	}

	derived_mac_key, err = userlib.HashKDF(macKey, blockUUIDBytes)
	if err != nil {
		return uuid.UUID{0}, err
	}
	random_bytes = userlib.RandomBytes(16)
	encrypted_block_bytes = userlib.SymEnc(derived_enc_key[:16], random_bytes, new_block_struct_bytes)
	mac_block_bytes, err = userlib.HMACEval(derived_mac_key[:16], encrypted_block_bytes)
	if err != nil {
		return uuid.UUID{0}, err
	}

	block_new_maced_bytes, err = CreateMacValue(encrypted_block_bytes, mac_block_bytes)
	if err != nil {
		return uuid.UUID{0}, err
	}

	userlib.DatastoreSet(blockUUID, block_new_maced_bytes)
	return new_block_struct.NextBlock, nil
}

func GetFilePointerKeys(username string, password string, filename string) (encKey []byte, macKey []byte, err error) {
	var username_password_bytes []byte
	var mac_bytes []byte
	var enc_bytes []byte

	username_password_bytes, err = json.Marshal(username + password)
	if err != nil {
		return nil, nil, err
	}
	enc_bytes, err = json.Marshal(username + filename + "enc")
	if err != nil {
		return nil, nil, err
	}
	mac_bytes, err = json.Marshal(username + filename + "mac")
	if err != nil {
		return nil, nil, err
	}

	encKey = userlib.Argon2Key(username_password_bytes, enc_bytes, 16)
	macKey = userlib.Argon2Key(username_password_bytes, mac_bytes, 16)

	return encKey, macKey, nil
}

func GetFileStructHelper(fileUUID userlib.UUID, encKey []byte, macKey []byte) (fileStruct FileStruct, err error) {
	maced_file_struct, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return fileStruct, errors.New("couldnt find file with UUID")
	}

	encrypted_file_struct, given_mac, err := GetMacValue(maced_file_struct)
	if err != nil {
		return fileStruct, err
	}

	check_mac, err := userlib.HMACEval(macKey, encrypted_file_struct)
	if err != nil {
		return fileStruct, err
	}

	if !userlib.HMACEqual(check_mac, given_mac) {
		return fileStruct, errors.New("file mac not equal")
	}

	file_struct_bytes := userlib.SymDec(encKey, encrypted_file_struct)

	err = json.Unmarshal(file_struct_bytes, &fileStruct)
	if err != nil {
		return fileStruct, err
	}
	if len(fileStruct.BlockEncrypt) == 0 {
		var fileStructPointer2 FileStructPointer
		err = json.Unmarshal(file_struct_bytes, &fileStructPointer2)
		if err != nil {
			return fileStruct, err
		}
		return GetFileStructHelper(fileStructPointer2.FileStructUUID, fileStructPointer2.FileStructEncrypt, fileStructPointer2.FileStructMac)
	}

	return fileStruct, nil
}

func GetFileStruct(username string, password string, filename string) (fileStruct FileStruct, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + username))[:16])
	if err != nil {
		return fileStruct, err
	}

	var file_struct_pointer_encrypt_key []byte
	var file_struct_pointer_mac_key []byte

	file_struct_pointer_encrypt_key, file_struct_pointer_mac_key, err = GetFilePointerKeys(username, password, filename)
	if err != nil {
		return fileStruct, err
	}

	currentFileStructPointer, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return fileStruct, errors.New("couldn't find file")
	}

	var encrypted_file_pointer []byte
	var given_file_mac []byte
	var check_file_mac []byte
	encrypted_file_pointer, given_file_mac, err = GetMacValue(currentFileStructPointer)
	if err != nil {
		return fileStruct, err
	}
	check_file_mac, err = userlib.HMACEval(file_struct_pointer_mac_key, encrypted_file_pointer)
	if err != nil {
		return fileStruct, err
	}
	if !userlib.HMACEqual(given_file_mac, check_file_mac) {
		return fileStruct, errors.New("file pointer mac not equal")
	}

	file_struct_pointer_bytes := userlib.SymDec(file_struct_pointer_encrypt_key, encrypted_file_pointer)
	var file_struct_pointer FileStructPointer
	err = json.Unmarshal(file_struct_pointer_bytes, &file_struct_pointer)
	if err != nil {
		return fileStruct, err
	}

	file_struct, err := GetFileStructHelper(file_struct_pointer.FileStructUUID, file_struct_pointer.FileStructEncrypt, file_struct_pointer.FileStructMac)
	if err != nil {
		return fileStruct, err
	}

	return file_struct, nil
}

func GetFilePointerHelper(filePointer FileStructPointer) (fileStructPointer FileStructPointer, err error) {
	fileUUID := filePointer.FileStructUUID
	macKey := filePointer.FileStructMac
	encKey := filePointer.FileStructEncrypt
	maced_file_struct, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return fileStructPointer, errors.New("couldnt find file with UUID")
	}

	encrypted_file_struct, given_mac, err := GetMacValue(maced_file_struct)
	if err != nil {
		return fileStructPointer, err
	}

	check_mac, err := userlib.HMACEval(macKey, encrypted_file_struct)
	if err != nil {
		return fileStructPointer, err
	}

	if !userlib.HMACEqual(check_mac, given_mac) {
		return fileStructPointer, errors.New("file mac not equal")
	}

	file_struct_bytes := userlib.SymDec(encKey, encrypted_file_struct)

	var fileStruct FileStruct
	err = json.Unmarshal(file_struct_bytes, &fileStruct)
	if err != nil {
		return fileStructPointer, err
	}
	if len(fileStruct.BlockEncrypt) == 0 {
		var fileStructPointer2 FileStructPointer
		err = json.Unmarshal(file_struct_bytes, &fileStructPointer2)
		if err != nil {
			return fileStructPointer, err
		}
		return fileStructPointer2, nil
	} else {
		return filePointer, nil
	}
}

func GetFileStructPointer(username string, password string, filename string) (fileStructPointer FileStructPointer, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + username))[:16])
	if err != nil {
		return fileStructPointer, err
	}

	var file_struct_pointer_encrypt_key []byte
	var file_struct_pointer_mac_key []byte

	file_struct_pointer_encrypt_key, file_struct_pointer_mac_key, err = GetFilePointerKeys(username, password, filename)
	if err != nil {
		return fileStructPointer, err
	}

	currentFileStructPointer, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return fileStructPointer, errors.New("couldn't find file")
	}

	var encrypted_file_pointer []byte
	var given_file_mac []byte
	var check_file_mac []byte
	encrypted_file_pointer, given_file_mac, err = GetMacValue(currentFileStructPointer)
	if err != nil {
		return fileStructPointer, err
	}
	check_file_mac, err = userlib.HMACEval(file_struct_pointer_mac_key, encrypted_file_pointer)
	if err != nil {
		return fileStructPointer, err
	}
	if !userlib.HMACEqual(given_file_mac, check_file_mac) {
		return fileStructPointer, errors.New("file pointer mac not equal")
	}

	file_struct_pointer_bytes := userlib.SymDec(file_struct_pointer_encrypt_key, encrypted_file_pointer)
	var original_file_struct_pointer FileStructPointer
	err = json.Unmarshal(file_struct_pointer_bytes, &original_file_struct_pointer)
	if err != nil {
		return fileStructPointer, err
	}
	file_struct_pointer, err := GetFilePointerHelper(original_file_struct_pointer)
	if err != nil {
		return fileStructPointer, err
	}
	return file_struct_pointer, nil
}

func UpdateFile(fileStructUUID userlib.UUID, fileStruct interface{}, encKey []byte, macKey []byte) (err error) {
	file_struct_bytes, err := json.Marshal(fileStruct)
	if err != nil {
		return err
	}
	file_struct_encrypt_bytes := userlib.SymEnc(encKey, userlib.RandomBytes(16), file_struct_bytes)
	file_struct_mac_bytes, err := userlib.HMACEval(macKey, file_struct_encrypt_bytes)
	if err != nil {
		return err
	}
	maced_file_struct_bytes, err := CreateMacValue(file_struct_encrypt_bytes, file_struct_mac_bytes)
	userlib.DatastoreSet(fileStructUUID, maced_file_struct_bytes)
	return err
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	file_struct, err := GetFileStruct(userdata.Username, userdata.Password, filename)
	if err == nil {
		file_struct_pointer, err := GetFileStructPointer(userdata.Username, userdata.Password, filename)
		if err != nil {
			return err
		}

		file_struct.StartBlock = uuid.New()
		file_struct.EndBlock, err = CreateBlocks(content, file_struct.BlockEncrypt, file_struct.BlockMac, file_struct.StartBlock)
		if err != nil {
			return err
		}
		err = UpdateFile(file_struct_pointer.FileStructUUID, file_struct, file_struct_pointer.FileStructEncrypt, file_struct_pointer.FileStructMac)
		if err != nil {
			return err
		}
	} else {
		// create new file struct
		var newFileStruct FileStruct
		newFileStruct.Owner = userdata.Username
		newFileStruct.UserList = append(newFileStruct.UserList, userdata.Username)
		newFileStruct.BlockEncrypt = userlib.RandomBytes(16)
		newFileStruct.BlockMac = userlib.RandomBytes(16)
		newFileStruct.StartBlock = uuid.New()
		newFileStruct.EndBlock, err = CreateBlocks(content, newFileStruct.BlockEncrypt, newFileStruct.BlockMac, newFileStruct.StartBlock)
		if err != nil {
			return err
		}

		// secure and store file struct
		var fileStructUUID userlib.UUID
		var fileEncryptKey []byte
		var fileMacKey []byte

		fileStructUUID = uuid.New()
		fileEncryptKey = userlib.RandomBytes(16)
		fileMacKey = userlib.RandomBytes(16)

		// update file
		err = UpdateFile(fileStructUUID, newFileStruct, fileEncryptKey, fileMacKey)
		if err != nil {
			return err
		}

		var newFileStructPointer FileStructPointer
		newFileStructPointer.FileStructEncrypt = fileEncryptKey
		newFileStructPointer.FileStructMac = fileMacKey
		newFileStructPointer.FileStructUUID = fileStructUUID
		newFileStructPointer.SharedStructsMap = make(map[string]FileStructPointer)

		var file_struct_pointer_bytes []byte
		var encrypted_file_pointer []byte
		var maced_file_pointer []byte
		var file_pointer_mac_struct []byte

		file_struct_pointer_bytes, err = json.Marshal(newFileStructPointer)
		if err != nil {
			return err
		}

		file_struct_pointer_encrypt_key, file_struct_pointer_mac_key, err := GetFilePointerKeys(userdata.Username, userdata.Password, filename)
		if err != nil {
			return err
		}
		encrypted_file_pointer = userlib.SymEnc(file_struct_pointer_encrypt_key, userlib.RandomBytes(16), file_struct_pointer_bytes)
		maced_file_pointer, err = userlib.HMACEval(file_struct_pointer_mac_key, encrypted_file_pointer)
		if err != nil {
			return err
		}

		file_pointer_mac_struct, err = CreateMacValue(encrypted_file_pointer, maced_file_pointer)
		if err != nil {
			return err
		}
		storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
		if err != nil {
			return err
		}

		userlib.DatastoreSet(storageKey, file_pointer_mac_struct)
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	file_struct_pointer, err := GetFileStructPointer(userdata.Username, userdata.Password, filename)
	if err != nil {
		return err
	}

	file_struct, err := GetFileStruct(userdata.Username, userdata.Password, filename)
	if err != nil {
		return err
	}
	file_struct.EndBlock, err = CreateBlocks(content, file_struct.BlockEncrypt, file_struct.BlockMac, file_struct.EndBlock)
	if err != nil {
		return err
	}

	err = UpdateFile(file_struct_pointer.FileStructUUID, file_struct, file_struct_pointer.FileStructEncrypt, file_struct_pointer.FileStructMac)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	file_struct, err := GetFileStruct(userdata.Username, userdata.Password, filename)
	if err != nil {
		return nil, err
	}
	var temp userlib.UUID
	temp = file_struct.StartBlock
	for temp != file_struct.EndBlock {
		currBlockMacedBytes, ok := userlib.DatastoreGet(temp)
		if !ok {
			return nil, errors.New("block with the specified UUID not in datastore")
		}
		encrypted_block, given_block_mac, err := GetMacValue(currBlockMacedBytes)
		if err != nil {
			return nil, err
		}

		blockUUIDBytes, err := json.Marshal(temp)
		if err != nil {
			return nil, err
		}

		derived_enc_key, err := userlib.HashKDF(file_struct.BlockEncrypt, blockUUIDBytes)
		if err != nil {
			return nil, err
		}

		derived_mac_key, err := userlib.HashKDF(file_struct.BlockMac, blockUUIDBytes)
		if err != nil {
			return nil, err
		}

		check_block_mac, err := userlib.HMACEval(derived_mac_key[:16], encrypted_block)
		if err != nil {
			return nil, err
		}

		if !userlib.HMACEqual(given_block_mac, check_block_mac) {
			return nil, errors.New("block mac not equal")
		}
		block_bytes := userlib.SymDec(derived_enc_key[:16], encrypted_block)
		var block_struct BlockStruct
		json.Unmarshal(block_bytes, &block_struct)
		content = append(content, block_struct.Content...)
		temp = block_struct.NextBlock
	}
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	var OwnerfileStructPointer FileStructPointer
	var RecipientfileStructPointer FileStructPointer

	//check if its the owner creating the invitation
	fileStruct, err := GetFileStruct(userdata.Username, userdata.Password, filename)
	if err != nil {
		return uuid.UUID{0}, err
	}
	if fileStruct.Owner != userdata.Username {
		SharedfileStructPointer, err := GetFileStructPointer(userdata.Username, userdata.Password, filename)
		if err != nil {
			return uuid.UUID{0}, err
		}

		ReceipientPK, ok := userlib.KeystoreGet(recipientUsername + "RSA")
		if !ok {
			return uuid.UUID{0}, errors.New("couldn't get recipient RSA public key")
		}
		PKEncryptBytesEncryptKey, err := userlib.PKEEnc(ReceipientPK, SharedfileStructPointer.FileStructEncrypt)
		if err != nil {
			return uuid.UUID{0}, err
		}
		DSBytesEncryptKey, err := userlib.DSSign(userdata.DS_private, PKEncryptBytesEncryptKey)
		if err != nil {
			return uuid.UUID{0}, err
		}
		PKEncryptBytesMacKey, err := userlib.PKEEnc(ReceipientPK, SharedfileStructPointer.FileStructMac)
		if err != nil {
			return uuid.UUID{0}, err
		}
		DSBytesMacKey, err := userlib.DSSign(userdata.DS_private, PKEncryptBytesMacKey)
		if err != nil {
			return uuid.UUID{0}, err
		}

		sign_enc_struct, err := CreateSignEncrypt(SharedfileStructPointer.FileStructUUID, PKEncryptBytesEncryptKey, DSBytesEncryptKey, PKEncryptBytesMacKey, DSBytesMacKey)
		var sign_enc_uuid = uuid.New()
		userlib.DatastoreSet(sign_enc_uuid, sign_enc_struct)

		return sign_enc_uuid, err

	} else {
		OwnerfileStructPointer, err = GetFileStructPointer(userdata.Username, userdata.Password, filename)
		if err != nil {
			return uuid.UUID{0}, err
		}
		RecipientfileStructPointer.FileStructEncrypt = OwnerfileStructPointer.FileStructEncrypt
		RecipientfileStructPointer.FileStructMac = OwnerfileStructPointer.FileStructMac
		RecipientfileStructPointer.FileStructUUID = OwnerfileStructPointer.FileStructUUID
		ReceipientPK, ok := userlib.KeystoreGet(recipientUsername + "RSA")
		if !ok {
			return uuid.UUID{0}, errors.New("couldn't get recipient RSA public key")
		}
		RecipientfileStructPointerBytes, err := json.Marshal(RecipientfileStructPointer)
		if err != nil {
			return uuid.UUID{0}, err
		}
		encrypt_key := userlib.RandomBytes(16)
		mac_key := userlib.RandomBytes(16)
		random_bytes := userlib.RandomBytes(16)

		encrypted_bytes := userlib.SymEnc(encrypt_key, random_bytes, RecipientfileStructPointerBytes)
		maced_bytes, err := userlib.HMACEval(mac_key, encrypted_bytes)
		if err != nil {
			return uuid.UUID{0}, err
		}
		mac_val_file_pointer, err := CreateMacValue(encrypted_bytes, maced_bytes)
		if err != nil {
			return uuid.UUID{0}, err
		}
		new_file_pointer_uuid := uuid.New()
		userlib.DatastoreSet(new_file_pointer_uuid, mac_val_file_pointer)

		var shared_pointer FileStructPointer
		shared_pointer.FileStructEncrypt = encrypt_key
		shared_pointer.FileStructMac = mac_key
		shared_pointer.FileStructUUID = new_file_pointer_uuid

		OwnerfileStructPointer.SharedStructsMap[recipientUsername] = shared_pointer

		storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
		if err != nil {
			return uuid.UUID{0}, err
		}

		file_struct_pointer_encrypt_key, file_struct_pointer_mac_key, err := GetFilePointerKeys(userdata.Username, userdata.Password, filename)
		if err != nil {
			return uuid.UUID{0}, err
		}
		err = UpdateFile(storageKey, OwnerfileStructPointer, file_struct_pointer_encrypt_key, file_struct_pointer_mac_key)

		PKEncryptBytesEncryptKey, err := userlib.PKEEnc(ReceipientPK, encrypt_key)
		if err != nil {
			return uuid.UUID{0}, err
		}
		DSBytesEncryptKey, err := userlib.DSSign(userdata.DS_private, PKEncryptBytesEncryptKey)
		if err != nil {
			return uuid.UUID{0}, err
		}
		PKEncryptBytesMacKey, err := userlib.PKEEnc(ReceipientPK, mac_key)
		if err != nil {
			return uuid.UUID{0}, err
		}
		DSBytesMacKey, err := userlib.DSSign(userdata.DS_private, PKEncryptBytesMacKey)
		if err != nil {
			return uuid.UUID{0}, err
		}

		sign_enc_struct, err := CreateSignEncrypt(new_file_pointer_uuid, PKEncryptBytesEncryptKey, DSBytesEncryptKey, PKEncryptBytesMacKey, DSBytesMacKey)
		var sign_enc_uuid = uuid.New()
		userlib.DatastoreSet(sign_enc_uuid, sign_enc_struct)

		return sign_enc_uuid, err
	}
}

func CheckFilename(username string, filename string) bool {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + username))[:16])
	if err != nil {
		return false
	}
	_, ok := userlib.DatastoreGet(storageKey)
	if ok {
		return false
	} else {
		return true
	}

}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	if !CheckFilename(userdata.Username, filename) {
		return errors.New("filename already exists")
	}
	sign_encrypt_bytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("couldn't get invitation")
	}
	file_uuid, enc_rsa, enc_ds, mac_rsa, mac_ds, err := GetSignEncrypt(sign_encrypt_bytes)
	if err != nil {
		return errors.New("getting sign encrypt error")
	}
	verify_key, ok := userlib.KeystoreGet(senderUsername + "DS")
	if !ok {
		return errors.New("getting verify key error")
	}
	if userlib.DSVerify(verify_key, enc_rsa, enc_ds) != nil {
		return errors.New("couldn't verify encryption key")
	}
	if userlib.DSVerify(verify_key, mac_rsa, mac_ds) != nil {
		return errors.New("couldn't verify mac key")
	}
	enc_key, err := userlib.PKEDec(userdata.RSA_private, enc_rsa)
	if err != nil {
		return errors.New("failed to get encrypt key")
	}
	mac_key, err := userlib.PKEDec(userdata.RSA_private, mac_rsa)
	if err != nil {
		return errors.New("failed to get mac key")
	}

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}

	var file_struct_pointer FileStructPointer
	file_struct_pointer.FileStructUUID = file_uuid
	file_struct_pointer.FileStructEncrypt = enc_key
	file_struct_pointer.FileStructMac = mac_key

	// test the file struct pointer/invitation to still be valid/unrevoked
	_, err = GetFileStructHelper(file_struct_pointer.FileStructUUID, file_struct_pointer.FileStructEncrypt, file_struct_pointer.FileStructMac)
	if err != nil {
		return err
	}

	file_struct_pointer_bytes, err := json.Marshal(file_struct_pointer)
	if err != nil {
		return err
	}

	file_struct_pointer_encrypt_key, file_struct_pointer_mac_key, err := GetFilePointerKeys(userdata.Username, userdata.Password, filename)
	if err != nil {
		return err
	}
	encrypted_file_pointer := userlib.SymEnc(file_struct_pointer_encrypt_key, userlib.RandomBytes(16), file_struct_pointer_bytes)
	maced_file_pointer, err := userlib.HMACEval(file_struct_pointer_mac_key, encrypted_file_pointer)
	if err != nil {
		return err
	}

	file_pointer_mac_struct, err := CreateMacValue(encrypted_file_pointer, maced_file_pointer)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(storageKey, file_pointer_mac_struct)
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//check if receiptUsername is in the shared structs map
	fileStruct, err := GetFileStruct(userdata.Username, userdata.Password, filename)
	if err != nil {
		return err
	}
	if fileStruct.Owner != userdata.Username {
		return err
	}
	fileStructPointer, err := GetFileStructPointer(userdata.Username, userdata.Password, filename)
	if err != nil {
		return err
	}
	_, ok := fileStructPointer.SharedStructsMap[recipientUsername]
	if ok {
		delete(fileStructPointer.SharedStructsMap, recipientUsername)
	} else {
		return errors.New("recipientUsername not in shared structs map")
	}
	newEncryptKey := userlib.RandomBytes(16)
	newMac := userlib.RandomBytes(16)
	err = UpdateFile(fileStructPointer.FileStructUUID, fileStruct, newEncryptKey, newMac)
	if err != nil {
		return err
	}

	fileStructPointer.FileStructEncrypt = newEncryptKey
	fileStructPointer.FileStructMac = newMac

	var new_shared_file_pointer FileStructPointer
	new_shared_file_pointer.FileStructUUID = fileStructPointer.FileStructUUID
	new_shared_file_pointer.FileStructEncrypt = newEncryptKey
	new_shared_file_pointer.FileStructMac = newMac
	new_shared_file_pointer_bytes, err := json.Marshal(new_shared_file_pointer)
	if err != nil {
		return err
	}
	for user := range fileStructPointer.SharedStructsMap {
		new_shared_file_pointer_encrypt := userlib.SymEnc(fileStructPointer.SharedStructsMap[user].FileStructEncrypt, userlib.RandomBytes(16), new_shared_file_pointer_bytes)
		hmac_shared_file_pointer, err := userlib.HMACEval(fileStructPointer.SharedStructsMap[user].FileStructMac, new_shared_file_pointer_encrypt)
		if err != nil {
			return err
		}
		new_shared_file_pointer_bytes, err := CreateMacValue(new_shared_file_pointer_encrypt, hmac_shared_file_pointer)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileStructPointer.SharedStructsMap[user].FileStructUUID, new_shared_file_pointer_bytes)

	}

	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}

	file_struct_pointer_encrypt_key, file_struct_pointer_mac_key, err := GetFilePointerKeys(userdata.Username, userdata.Password, filename)
	if err != nil {
		return err
	}
	UpdateFile(storageKey, fileStructPointer, file_struct_pointer_encrypt_key, file_struct_pointer_mac_key)
	return nil
}
