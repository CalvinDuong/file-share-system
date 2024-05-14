package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.

	_ "encoding/hex"
	_ "errors"
	"fmt"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	// RunSpecs(t, "Client Tests")
	RunSpecs(t, "Failed Tests")
}

func getKeys(m map[uuid.UUID][]byte) []uuid.UUID {
	keys := make([]uuid.UUID, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
func diffSlices(slice1, slice2 []uuid.UUID) []uuid.UUID {
	diff := make([]uuid.UUID, 0)
	for _, v1 := range slice1 {
		found := false
		for _, v2 := range slice2 {
			if v1 == v2 {
				found = true
				break
			}
		}
		if !found {
			diff = append(diff, v1)
		}
	}
	return diff
}

func xorWithSelf(b []byte) []byte {
	result := make([]byte, len(b))
	for i := range b {
		result[i] = b[i] ^ b[i]
	}
	return result
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User
	var bobLaptop *client.User
	var bobDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	aliceFile1 := "aliceFile1.txt"

	bobFile := "bobFile.txt"
	bobFile1 := "bobFile1.txt"

	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charles accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing Sharing + Loading when no access + Loading when access + Revoking", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob trying to load without accepting %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			data, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepted the invitation and now loads.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file with the new appended content.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charles accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepted the invitation and now loads.")
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("We have Alice revoke Bob so Charles should not be able to access.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("We have revoked Bob (direct descendant of owner Alice) try to append to file")
			err = bob.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("We have revoked Charles (indirect descendant of owner Alice) try to load to file")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice (owner) should still be able to access it.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
		})

		Specify("Custom Test: Getting Users that do not exist +  with wrong passwords and confusing passwords between two users", func() {
			userlib.DebugMsg("Initializing user Alice and testing password")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting user Alice with correct password.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting user Alice with wrong password.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword+"3")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting user Bob before initialized")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user Bob and testing password")
			bob, err = client.InitUser("bob", defaultPassword+"5")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting user Bob with wrong password (Alice's password).")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Getting user Bob with right password.")
			bob, err = client.GetUser("bob", defaultPassword+"5")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Getting user BOB with right password.")
			_, err = client.GetUser("BOB", defaultPassword+"5")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Getting user Bob with right password.")
			_, err = client.GetUser("Bob", defaultPassword+"5")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting empty username")
			_, err = client.GetUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing the creation of two users with same username + empty username", func() {
			userlib.DebugMsg("Initializing user with empty username")
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user Alice again")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Initializing user Alice again but this time with different password")
			alice, err = client.InitUser("alice", defaultPassword+"5")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Alice creates two files that is shared to Bob, revoke one file, Bob should still have access to the other one ", func() {
			userlib.DebugMsg("Initializing users Alice, Bob")
			aliceLaptop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice storing another file %s with content: %s", aliceFile1, contentTwo)
			aliceDesktop.StoreFile(aliceFile1, []byte(contentTwo))
			data, err = aliceDesktop.LoadFile(aliceFile1)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under the SAME name %s.", aliceFile1, bobFile)
			invite, err = aliceDesktop.CreateInvitation(aliceFile1, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile) // should give an error because we already have a file with the same name
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under different name %s.", aliceFile1, bobFile1)
			invite, err = aliceDesktop.CreateInvitation(aliceFile1, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile1)
			Expect(err).To(BeNil())

			userlib.DebugMsg("We have Alice revoke Bob from %s.", aliceFile)
			err = aliceLaptop.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			data, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Bob can still load the other file.")
			data, err = bob.LoadFile(bobFile1)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

		})

		Specify("Custom Test: Updating one device updates the others ; also testing that if Bob gets an invitation to file, if Alice's other devices (device other than the one that shared w him) updates Bob gets updated version", func() {
			userlib.DebugMsg("Initializing user Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Sharing with Bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob loads the file and checks it is equal to initial content")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Using aliceLaptop to append file data: %s", contentTwo)
			aliceLaptop.AppendToFile(aliceFile, []byte(contentTwo))
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Checking that alice sees the changes.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Checking to see if Bob gets updated version of file after differnet devices update")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Getting third instance of Alice - aliceDesktop.")
			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Using aliceDesktop to rewrite entire file data with: %s and making sure alice and aliceLaptop and Bob sees the changes", contentThree)
			aliceDesktop.StoreFile(aliceFile, []byte(contentThree))
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

			userlib.DebugMsg("Checking to see if Bob gets updated version of file after differnet devices update")
			data, err = bob.LoadFile(bobFile)            //for some reason bobs file is still contentOne + contentTwo despite being updated by aliceDesktop
			Expect(err).To(BeNil())                      //might have to do something with store ?? because it works for append apparently in the test cases above
			Expect(data).To(Equal([]byte(contentThree))) //line 465 works
		})

		//write test cases for revoking access to one of the direct children of the owner but not the other
		Specify("Custom Test: Revoking access to one of the direct children of the owner but not the other", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Charles for file %s, and Charles accepting invite under name %s.", aliceFile, charlesFile)
			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("We have Alice revoke Bob from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Charles can still load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

		})

		Specify("Custom Test: Same filename between different users", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob storing file %s with content: %s", aliceFile, contentTwo)
			bob.StoreFile(aliceFile, []byte(contentTwo))
			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("Custom Test: Rewriting file because already stored", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentTwo)
			alice.StoreFile(aliceFile, []byte(contentTwo))
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("Custom Test: Getting file that does not exist", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting file that does not exist")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Creating file and then getting it")
			alice.StoreFile(aliceFile, []byte(contentOne))
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Getting another file that does not exist")
			_, err = alice.LoadFile(aliceFile1)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Appending to file that does not exist", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending to file that does not exist")
			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Creating file and then appending to it")
			alice.StoreFile(aliceFile, []byte(contentOne))
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
		})

		Specify("Custom Test: Invitation to file that does not exist / you don't have access to", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file she has not created")
			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice creating invite for Bob for file she has created")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating charles")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob sending invite to charles but Bob has not accepted the invite yet")
			_, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob sending invite to charles")
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting invite from Bob under filename %s.", charlesFile)
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())
		})

		Specify("Custom Test: Revoking access to file that does not exist / you don't have access to", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s, before creating the file", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s, before sending an invite", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s. but invite was alreayd revoked", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revoking Charles's access from %s, but Charles does not exist", aliceFile)
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Creating Charles")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Charles's access from %s, but Charles has not gotten an invite yet", aliceFile)
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, %s but Bob was alreayd revoked.", bobFile, charlesFile)
			_, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, %s.", aliceFile, bobFile)
			invite, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s. so Charles invite is also revoked", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting invite from Bob under filename %s but Alice had already revoked Bob .", bobFile)
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles trying to access file that was revoked")
			err = charles.AppendToFile(charlesFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())

		})

		Specify("Custom Test: Multiple invitations to Bob but Bob only accepts one ", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite1, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file2 %s with content: %s", aliceFile1, contentTwo)
			alice.StoreFile(aliceFile1, []byte(contentTwo))
			data, err = alice.LoadFile(aliceFile1)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Alice creating invite for Bob for file2 %s, and Bob accepting invite under name %s.", aliceFile1, bobFile1)
			invite2, err := alice.CreateInvitation(aliceFile1, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite1, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob trying to load file1 and is successful but load file2 and is unsuccessful ")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob trying to load file2 and is unsuccessful ")
			_, err = bob.LoadFile(bobFile1)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob trying to load file2 based off Alice's file2 name ")
			_, err = bob.LoadFile(aliceFile1)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revoking file2 from bob but bob has not accepted file2 only file1")
			err = alice.RevokeAccess(aliceFile1, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking file1 from bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts file2 but the invite has been revoked")
			err = bob.AcceptInvitation("alice", invite2, bobFile1)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries to load file2 and is not successful ")
			_, err = bob.LoadFile(bobFile1)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries to load file1 and is unsuccessful ")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Custom Test: Revoked user tries using multiple devices to load file", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Creating bob, laptopBob, and desktopBob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			bobLaptop, err = client.InitUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())
			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			bobDesktop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("We have Alice revoke Bob from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can't load the file from all devices.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			_, err = bobLaptop.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			_, err = bobDesktop.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Bob can't append to the file from all devices.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
			err = bobLaptop.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
			err = bobDesktop.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Creating users Alice and alice", func() {
			userlib.DebugMsg("Initializing user alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", defaultPassword+"5")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice with right password.")
			alice, err = client.GetUser("Alice", defaultPassword+"5")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice with right password.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice with wrong password.")
			alice, err = client.GetUser("alice", defaultPassword+"5")
			Expect(err).ToNot(BeNil())
		})
		FSpecify("Custom Test: Tampering Alice's file and getting an error when trying to load it", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			mapBefore := getKeys(userlib.DatastoreGetMap())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			mapAfter := getKeys(userlib.DatastoreGetMap())

			userlib.DebugMsg("Tampering Alice's file.")
			fmt.Println("Before tampering: ", mapBefore)
			fmt.Println("After tampering: ", mapAfter)
			diff := diffSlices(mapAfter, mapBefore)
			fmt.Println("Diff: ", diff)
			userlib.DebugMsg("Tampering file %s.", diff[0])
			userlib.DatastoreSet(diff[0], []byte("tampered"))
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})
		FSpecify("Custom Test: Tampering Alice's file and getting no error when trying to load Bob's", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
			mapBefore := getKeys(userlib.DatastoreGetMap())

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentTwo)
			bob.StoreFile(bobFile, []byte(contentTwo))
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
			mapAfter := getKeys(userlib.DatastoreGetMap())

			userlib.DebugMsg("Tampering Bob's file.")
			fmt.Println("Before tampering: ", mapBefore)
			fmt.Println("After tampering: ", mapAfter)
			diff := diffSlices(mapAfter, mapBefore)
			fmt.Println("Diff: ", diff)
			userlib.DebugMsg("Tampering file %s.", diff[0])
			userlib.DatastoreSet(diff[0], []byte("tampered"))
			_, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})
	})
})

// var _ = FDescribe("Failed Tests", func() {
// 	// A few user declarations that may be used for testing. Remember to initialize these before you
// 	// attempt to use them!
// 	var alice *client.User
// 	var bob *client.User
// 	// var charles *client.User
// 	// var doris *client.User
// 	// var eve *client.User
// 	// var frank *client.User
// 	// var grace *client.User
// 	// var horace *client.User
// 	// var ira *client.User

// 	// These declarations may be useful for multi-session testing.
// 	// var alicePhone *client.User
// 	// var aliceLaptop *client.User
// 	// var aliceDesktop *client.User
// 	// var bobLaptop *client.User
// 	// var bobDesktop *client.User

// 	var err error

// 	// A bunch of filenames that may be useful.
// 	aliceFile := "aliceFile.txt"
// 	aliceFile1 := "aliceFile1.txt"

// 	bobFile := "bobFile.txt"
// 	bobFile1 := "bobFile1.txt"

// 	// charlesFile := "charlesFile.txt"
// 	// dorisFile := "dorisFile.txt"
// 	// eveFile := "eveFile.txt"
// 	// frankFile := "frankFile.txt"
// 	// graceFile := "graceFile.txt"
// 	// horaceFile := "horaceFile.txt"
// 	// iraFile := "iraFile.txt"

// 	BeforeEach(func() {
// 		// This runs before each test within this Describe block (including nested tests).
// 		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
// 		// We also initialize
// 		userlib.DatastoreClear()
// 		userlib.KeystoreClear()
// 	})

// })
