package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
    // Some imports use an underscore to prevent the compiler from complaining
    // about unused imports.
    _ "encoding/hex"
    "errors"
    _ "errors"
    _ "strconv"
    _ "strings"
    "testing"

    // A "dot" import is used here so that the functions in the ginko and gomega
    // modules can be used without an identifier. For example, Describe() and
    // Expect() instead of ginko.Describe() and gomega.Expect().
    . "github.com/onsi/ginkgo"
    . "github.com/onsi/gomega"

    userlib "github.com/cs161-staff/project2-userlib"

    "github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
    RegisterFailHandler(Fail)
    RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const anotherPassword = "anotherPassword"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const contentFour = "I love CS 161!"
const contentFive = "Peyrin is a nice guy."

const content100 = string('a' * 100)
const content10000000 = string('a' * 10000000)

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
    var doris *client.User
    var eve *client.User
    var frank *client.User
    var grace *client.User
    var horace *client.User
    var ira *client.User

    // These declarations may be useful for multi-session testing.
    var alicePhone *client.User
    var aliceLaptop *client.User
    var aliceDesktop *client.User

    var err error

    // A bunch of filenames that may be useful.
    aliceFile := "aliceFile.txt"
    bobFile := "bobFile.txt"
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
            userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())

            bob, err = client.InitUser("bob", defaultPassword)
            Expect(err).To(BeNil())

            charles, err = client.InitUser("charles", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
            err = alice.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())

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

            userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
            invite, err = bob.CreateInvitation(bobFile, "charles")
            Expect(err).To(BeNil())

            err = charles.AcceptInvitation("bob", invite, charlesFile)
            Expect(err).To(BeNil())

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

    })

    Describe("Advanced Tests, proper error return for client API", func() {

        Specify("client API error: InitUser.", func() {
            userlib.DebugMsg("Initializing user Alice.")
            _, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Initializing user Alice once again, error expected.")
            _, err = client.InitUser("alice", defaultPassword)
            Expect(err).NotTo(BeNil())

            userlib.DebugMsg("Initializing user with empty username, error expected.")
            _, err = client.InitUser(emptyString, defaultPassword)
            Expect(err).NotTo(BeNil())
        })

        Specify("client API error: GetUser.", func() {
            userlib.DebugMsg("Initializing user Alice.")
            _, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Getting user Bob, error expected.")
            _, err = client.GetUser("bob", defaultPassword)
            Expect(err).NotTo(BeNil())

            userlib.DebugMsg("Getting user Alice with wrong password, error expected.")
            _, err = client.GetUser("alice", anotherPassword)
            Expect(err).NotTo(BeNil())

            userlib.DebugMsg("Modify user profile of Alice, error expected.")
            datastore := userlib.DatastoreGetMap()
            for _, val := range datastore {
                ori := val
                val[0] ^= 0xff
                _, err = client.GetUser("alice", defaultPassword)
                Expect(err).NotTo(BeNil())
                val[0] ^= 0xff                                    // revoke changes
                _, err = client.GetUser("alice", defaultPassword) // should succeed
                Expect(err).To(BeNil())

                val = append(val, 0x9)
                _, err = client.GetUser("alice", defaultPassword)
                Expect(err).NotTo(BeNil())
                val = ori                                         // revoke changes
                _, err = client.GetUser("alice", defaultPassword) // should succeed
                Expect(err).To(BeNil())

                val = val[0 : len(val)-1]
                _, err = client.GetUser("alice", defaultPassword)
                Expect(err).NotTo(BeNil())
                val = ori                                         // revoke changes
                _, err = client.GetUser("alice", defaultPassword) // should succeed
                Expect(err).To(BeNil())
            }

        })

        Specify("client API error: StoreFile", func() {
            userlib.DebugMsg("Initialize user and file.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())
            bob, err = client.InitUser("bob", defaultPassword)
            Expect(err).To(BeNil())
            err = alice.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())

            userlib.DebugMsg("give and revoke bob's access")
            invite, err := alice.CreateInvitation(aliceFile, "bob")
            Expect(err).To(BeNil())
            err = bob.AcceptInvitation("alice", invite, aliceFile)
            Expect(err).To(BeNil())
            read, err := bob.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(read).To(Equal([]byte(contentOne)))
            err = bob.StoreFile(aliceFile, []byte(contentTwo))
            Expect(err).To(BeNil())
            err = alice.RevokeAccess(aliceFile, "bob")
            Expect(err).To(BeNil())

            userlib.DebugMsg("Now bob try to make malicious store")
            err = bob.StoreFile(aliceFile, []byte(contentThree))
            Expect(err).NotTo(BeNil())
            read, err = alice.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(read).To(Equal([]byte(contentTwo)))
        })

        Specify("client API error: LoadFile.", func() {
            // for testing use
            userProfileUUID := map[userlib.UUID]bool{}
            var fileUUID []userlib.UUID

            userlib.DebugMsg("Initializing user Alice.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())
            for id := range userlib.DatastoreGetMap() {
                userProfileUUID[id] = true
            }

            userlib.DebugMsg("Storing file data: %s", contentOne)
            err = alice.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())
            for id := range userlib.DatastoreGetMap() {
                _, pre := userProfileUUID[id]
                if !pre {
                    fileUUID = append(fileUUID, id)
                }
            }

            userlib.DebugMsg("Loading file with invalid filename, error expected.")
            _, err := alice.LoadFile("invalidFilename")
            Expect(err).NotTo(BeNil())

            userlib.DebugMsg("Loading file without integrity, error expected.")
            datastore := userlib.DatastoreGetMap()
            for _, id := range fileUUID {
                ori := datastore[id]
                datastore[id][0] ^= 0xff
                _, err := alice.LoadFile(aliceFile)
                Expect(err).NotTo(BeNil())
                datastore[id][0] ^= 0xff // revoke changes
                Expect(err).To(BeNil())  // should succeed

                datastore[id] = append(datastore[id], 0x8)
                _, err = alice.LoadFile(aliceFile)
                Expect(err).NotTo(BeNil())
                datastore[id] = ori     // revoke changes
                Expect(err).To(BeNil()) // should succeed

                datastore[id] = datastore[id][0 : len(datastore[id])-1]
                _, err = alice.LoadFile(aliceFile)
                Expect(err).NotTo(BeNil())
                datastore[id] = ori     // revoke changes
                Expect(err).To(BeNil()) // should succeed
            }
        })

        Specify("client API error: AppendToFile", func() {
            userlib.DebugMsg("Initializing user Alice.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Storing file data: %s", contentOne)
            err = alice.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())

            userlib.DebugMsg("Appending file with invalid filename, error expected.")
            err = alice.AppendToFile(bobFile, []byte(contentTwo))
            Expect(err).NotTo(BeNil())
        })

        Specify("client API error: CreateInvitation.", func() {
            userlib.DebugMsg("Initializing user Alice.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Storing file data: %s", contentOne)
            err = alice.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())

            userlib.DebugMsg("Alice creating invite for not-exist user, error expected.")
            _, err := alice.CreateInvitation(aliceFile, "bob")
            Expect(err).NotTo(BeNil())

            userlib.DebugMsg("Initializing user Bob.")
            bob, err = client.InitUser("bob", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Alice creating invite using invalid filename, error expected.")
            _, err = alice.CreateInvitation(bobFile, "bob")
            Expect(err).NotTo(BeNil())
        })

        Specify("client API error: AcceptInvitation.", func() {
            userlib.DebugMsg("Initializing users Alice and Bob.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())

            bob, err = client.InitUser("bob", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Both Alice and Bob storing file %s with content: %s", aliceFile, contentOne)
            err = alice.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())

            err = bob.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())

            userlib.DebugMsg("Alice creating invite for Bob for file %s", aliceFile)
            invite, err := alice.CreateInvitation(aliceFile, "bob")
            Expect(err).To(BeNil())

            userlib.DebugMsg("Bob accepting invite with existing filename %s, error expected.", aliceFile)
            err = bob.AcceptInvitation("alice", invite, aliceFile)
            Expect(err).NotTo(BeNil())

            userlib.DebugMsg("Bob accepting invite with unexpected user, error expected.")
            err = bob.AcceptInvitation("charles", invite, bobFile)
            Expect(err).NotTo(BeNil())

            userlib.DebugMsg("Bob accepting invite with tampered share link, error expected.")
            datastore := userlib.DatastoreGetMap()
            datastore[invite][0] ^= 0xff
            err = bob.AcceptInvitation("alice", invite, bobFile)
            Expect(err).NotTo(BeNil())
            datastore[invite][0] ^= 0xff                         // revoke changes
            err = bob.AcceptInvitation("alice", invite, bobFile) // should succeed
            Expect(err).To(BeNil())

            userlib.DebugMsg("Alice storing file %s with content: %s", bobFile, contentOne)
            err = alice.StoreFile(bobFile, []byte(contentOne))
            Expect(err).To(BeNil())

            userlib.DebugMsg("Alice creating invite for Bob for file %s", bobFile)
            invite, err = alice.CreateInvitation(bobFile, "bob")
            Expect(err).To(BeNil())

            userlib.DebugMsg("Alice revoking Bob's access from %s.", bobFile)
            err = alice.RevokeAccess(bobFile, "bob")
            Expect(err).To(BeNil())

            userlib.DebugMsg("Bob accepting revoked share link, error expected.")
            err = bob.AcceptInvitation("alice", invite, charlesFile)
            Expect(err).NotTo(BeNil())
        })

        Specify("client API error: RevokeAccess.", func() {
            userlib.DebugMsg("Initializing user Alice.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Initializing user Bob.")
            bob, err = client.InitUser("bob", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
            err = alice.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())

            userlib.DebugMsg("Alice creating share link of file %s.", aliceFile)
            _, err := alice.CreateInvitation(aliceFile, "bob")
            Expect(err).To(BeNil())

            userlib.DebugMsg("Alice revoking a share link with invalid filename, error expected.")
            err = alice.RevokeAccess("invalidFile", "bob")
            Expect(err).NotTo(BeNil())

            userlib.DebugMsg("Alice revoking a share link with invalid recipient, error expected.")
            err = alice.RevokeAccess(aliceFile, "charles")
            Expect(err).NotTo(BeNil())
        })
    })

    Describe("Advanced Tests, access management for the file", func() {
        Specify("Tree structure with multiple leaves of access", func() {
            userlib.DebugMsg("Initializing users.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())
            bob, err = client.InitUser("bob", defaultPassword)
            Expect(err).To(BeNil())
            charles, err = client.InitUser("charles", defaultPassword)
            Expect(err).To(BeNil())
            doris, err = client.InitUser("doris", defaultPassword)
            Expect(err).To(BeNil())
            eve, err = client.InitUser("eve", defaultPassword)
            Expect(err).To(BeNil())
            frank, err = client.InitUser("frank", defaultPassword)
            Expect(err).To(BeNil())
            grace, err = client.InitUser("grace", defaultPassword)
            Expect(err).To(BeNil())
            horace, err = client.InitUser("horace", defaultPassword)
            Expect(err).To(BeNil())
            ira, err = client.InitUser("ira", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Initializing the file with with user alice.")
            err = alice.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())

            userlib.DebugMsg("Creating the origin tree structure access of file.")

            invite, err := alice.CreateInvitation(aliceFile, "bob")
            Expect(err).To(BeNil())
            err = bob.AcceptInvitation("alice", invite, aliceFile)
            Expect(err).To(BeNil())
            invite, err = alice.CreateInvitation(aliceFile, "eve")
            Expect(err).To(BeNil())
            err = eve.AcceptInvitation("alice", invite, aliceFile)
            Expect(err).To(BeNil())

            invite, err = bob.CreateInvitation(aliceFile, "charles")
            Expect(err).To(BeNil())
            err = charles.AcceptInvitation("bob", invite, aliceFile)
            Expect(err).To(BeNil())
            invite, err = bob.CreateInvitation(aliceFile, "doris")
            Expect(err).To(BeNil())
            err = doris.AcceptInvitation("bob", invite, aliceFile)
            Expect(err).To(BeNil())

            invite, err = eve.CreateInvitation(aliceFile, "frank")
            Expect(err).To(BeNil())
            err = frank.AcceptInvitation("eve", invite, aliceFile)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Let doris make changes and check consistency.")
            err = doris.AppendToFile(aliceFile, []byte(contentTwo))
            Expect(err).To(BeNil())

            expectedContent := []byte(contentOne + contentTwo)

            readContent, err := charles.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(readContent).To(Equal(expectedContent))

            readContent, err = bob.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(readContent).To(Equal(expectedContent))

            readContent, err = alice.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(readContent).To(Equal(expectedContent))

            readContent, err = eve.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(readContent).To(Equal(expectedContent))

            readContent, err = frank.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(readContent).To(Equal(expectedContent))

            userlib.DebugMsg("Let alice revoke bob's access and then check access.")
            err = alice.RevokeAccess(aliceFile, "bob")
            Expect(err).To(BeNil())

            err = frank.AppendToFile(aliceFile, []byte(contentThree))
            Expect(err).To(BeNil())

            _, err = doris.LoadFile(aliceFile)
            Expect(err).NotTo(BeNil())

            invite, err = eve.CreateInvitation(aliceFile, "grace")
            Expect(err).To(BeNil())
            err = grace.AcceptInvitation("eve", invite, aliceFile)
            Expect(err).To(BeNil())

            invite, err = alice.CreateInvitation(aliceFile, "horace")
            Expect(err).To(BeNil())
            err = horace.AcceptInvitation("alice", invite, aliceFile)
            Expect(err).To(BeNil())

            invite, err = horace.CreateInvitation(aliceFile, "ira")
            Expect(err).To(BeNil())
            err = ira.AcceptInvitation("horace", invite, aliceFile)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Check consistency again.")
            err = grace.AppendToFile(aliceFile, []byte(contentFour))
            Expect(err).To(BeNil())

            err = ira.AppendToFile(aliceFile, []byte(contentFive))
            Expect(err).To(BeNil())

            expectedContent = []byte(contentOne + contentTwo + contentThree + contentFour + contentFive)

            readContent, err = alice.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(readContent).To(Equal(expectedContent))

            readContent, err = eve.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(readContent).To(Equal(expectedContent))

            readContent, err = frank.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(readContent).To(Equal(expectedContent))

            readContent, err = grace.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(readContent).To(Equal(expectedContent))

            readContent, err = horace.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(readContent).To(Equal(expectedContent))

            readContent, err = ira.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(readContent).To(Equal(expectedContent))
        })
        Specify("Isolation of access management across different file", func() {
            userlib.DebugMsg("Initialzing users.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())
            bob, err = client.InitUser("bob", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Creating files.")
            err = alice.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())
            err = alice.StoreFile(bobFile, []byte(contentTwo))
            Expect(err).To(BeNil())

            userlib.DebugMsg("Making proper access.")
            invite, err := alice.CreateInvitation(aliceFile, "bob")
            Expect(err).To(BeNil())
            err = bob.AcceptInvitation("alice", invite, aliceFile)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Testing isolation of access.")
            err = bob.AppendToFile(aliceFile, []byte(contentTwo))
            Expect(err).To(BeNil())
            err = bob.AppendToFile(bobFile, []byte(contentThree))
            Expect(err).NotTo(BeNil())

            data, err := alice.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte(contentOne + contentTwo)))

        })
    })

    Describe("Advanced Tests, bandwidth", func() {
        Specify("Bandwidth tests for client API: AppendToFile", func() {
            userlib.DebugMsg("Initializing user.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("Initializing files.")
            err = alice.StoreFile(aliceFile, []byte(""))
            Expect(err).To(BeNil())

            // Helper function to measure bandwidth of a particular operation
            measureBandwidth := func(probe func()) (bandwidth int) {
                before := userlib.DatastoreGetBandwidth()
                probe()
                after := userlib.DatastoreGetBandwidth()
                return after - before
            }

            bw1 := measureBandwidth(func() {
                err = alice.AppendToFile(aliceFile, []byte(content100))
                Expect(err).To(BeNil())
            })

            err = alice.AppendToFile(aliceFile, []byte(content10000000))
            Expect(err).To(BeNil())

            bw2 := measureBandwidth(func() {
                err = alice.AppendToFile(aliceFile, []byte(content100))
                Expect(err).To(BeNil())
            })

            if bw2-bw1 < 100 {
                err = nil
            } else {
                err = errors.New("bandwidth test failed")
            }
            Expect(err).To(BeNil())
        })
    })

    Describe("Advanced Tests, proper action for client API", func() {

        Specify("proper action for user management 1: case-sensitive username", func() {
            _, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())
            _, err = client.InitUser("Alice", defaultPassword)
            Expect(err).To(BeNil())
        })

        Specify("proper action for user management 2: zero-length password", func() {
            _, err = client.InitUser("alice", "")
            Expect(err).To(BeNil())
        })

        Specify("proper action for client API: StoreFile 1.", func() {
            userlib.DebugMsg("Initializing user.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("try to store empty filename.")
            err = alice.StoreFile("", []byte(contentOne))
            Expect(err).To(BeNil())
            data, err := alice.LoadFile("")
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte(contentOne)))
        })

        Specify("proper action for client API: StoreFile 2.", func() {
            userlib.DebugMsg("Initializing user.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())

            userlib.DebugMsg("try to store empty sequence.")
            err = alice.StoreFile(aliceFile, []byte(""))
            Expect(err).To(BeNil())
            data, err := alice.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte("")))
        })

        Specify("proper action for client API: StoreFile 3.", func() {
            userlib.DebugMsg("Initializing user.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())
            err = alice.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())

            userlib.DebugMsg("Restore, overwritten expected.")
            err = alice.StoreFile(aliceFile, []byte(contentTwo))
            Expect(err).To(BeNil())
            data, err := alice.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte(contentTwo)))
        })

        Specify("proper action for client API: StoreFile 4.", func() {
            userlib.DebugMsg("Initializing user and file.")
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())
            bob, err = client.InitUser("bob", defaultPassword)
            Expect(err).To(BeNil())
            err = alice.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())

            userlib.DebugMsg("create share link to bob")
            invite, err := alice.CreateInvitation(aliceFile, "bob")
            Expect(err).To(BeNil())
            err = bob.AcceptInvitation("alice", invite, aliceFile)
            Expect(err).To(BeNil())

            userlib.DebugMsg("bob could properly read")
            data, err := bob.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte(contentOne)))

            userlib.DebugMsg("alice overwrite the file")
            err = alice.StoreFile(aliceFile, []byte(contentFour))
            Expect(err).To(BeNil())

            userlib.DebugMsg("bob should still have proper content")
            data, err = bob.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(data).To(Equal([]byte(contentFour)))
        })

        Specify("proper action for append: zero-length appending", func() {
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())

            err = alice.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())

            err = alice.AppendToFile(aliceFile, []byte(""))
            Expect(err).To(BeNil())

            read, err := alice.LoadFile(aliceFile)
            Expect(err).To(BeNil())
            Expect(read).To(Equal([]byte(contentOne)))
        })
    })

    // over-cover
    Describe("Multi-session and tampered", func() {
        Specify("Single-user & Multi-session with tampered", func() {
            aliceDesktop, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())
            aliceLaptop, err = client.GetUser("alice", defaultPassword)
            Expect(err).To(BeNil())

            err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())

            for _, val := range userlib.DatastoreGetMap() {
                val[0] ^= 0xff
                _, err = aliceLaptop.LoadFile(aliceFile)
                Expect(err).NotTo(BeNil())
                val[0] ^= 0xff
            }
        })

        Specify("Multi-user with tempered", func() {
            alice, err = client.InitUser("alice", defaultPassword)
            Expect(err).To(BeNil())
            bob, err = client.InitUser("bob", defaultPassword)
            Expect(err).To(BeNil())

            err = alice.StoreFile(aliceFile, []byte(contentOne))
            Expect(err).To(BeNil())

            for _, val := range userlib.DatastoreGetMap() {
                val[0] ^= 0xff
                _, err = alice.CreateInvitation(aliceFile, "bob")
                Expect(err).NotTo(BeNil())
                val[0] ^= 0xff
            }

            invite, err := alice.CreateInvitation(aliceFile, "bob")
            Expect(err).To(BeNil())

            for _, val := range userlib.DatastoreGetMap() {
                val[0] ^= 0xff
                err = bob.AcceptInvitation("alice", invite, aliceFile)
                Expect(err).NotTo(BeNil())
                val[0] ^= 0xff
            }

            err = bob.AcceptInvitation("alice", invite, aliceFile)
            Expect(err).To(BeNil())

            for _, val := range userlib.DatastoreGetMap() {
                val[0] ^= 0xff
                _, err = bob.LoadFile(aliceFile)
                Expect(err).NotTo(BeNil())
                val[0] ^= 0xff
            }
        })
    })

    //Describe("Advanced Tests, IND-CPA", func() {
    //    Specify("IND-CPA test for client API: StoreFile", func() {
    //        userlib.DebugMsg("Initializing user.")
    //        alice, err = client.InitUser("alice", defaultPassword)
    //        Expect(err).To(BeNil())
    //        datastore1 := userlib.DatastoreGetMap()
    //
    //        userlib.DebugMsg("Store file first time.")
    //        err = alice.StoreFile(aliceFile, []byte(contentOne))
    //        Expect(err).To(BeNil())
    //        datastore2 := userlib.DatastoreGetMap()
    //
    //    })
    //})

})
