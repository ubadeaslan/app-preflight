import Foundation
import GoogleSignIn

// Demonstrates IOS-LEGAL-001: account creation with no deletion path,
// and IOS-LEGAL-002: social login (GIDSignIn) without Sign in with Apple.
func signUp(email: String, password: String) {
    createUser(email)
    GIDSignIn.sharedInstance.signIn()
}
