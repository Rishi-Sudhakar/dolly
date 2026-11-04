# Dolly for iOS

SwiftUI app on the iOS 27 SDK. It uses the Swift core in `../../core-swift` (`DollyCore`) for everything
cryptographic and networked; the app adds the screens, the Secure Enclave key custody (`KeyVault`) and an
actor around the encrypted store (`Database`). No third-party packages.

## Build

Open `Untitled Project/Untitled Project.xcodeproj` in Xcode 27. The project uses the local `core-swift`
package (`DollyCore`), so there is nothing to install. Pick your Team under Signing & Capabilities, plug in an
iPhone and run. Minimum deployment is iOS 26. The app needs the local-network permission
(`INFOPLIST_KEY_NSLocalNetworkUsageDescription`).

Run on a real iPhone: the simulator has no Secure Enclave (the app then keeps the key in the Keychain).

## Using it

Tap + on both phones. Each phone makes its own link: Share it, and on the other phone copy the message and
tap Paste. Both phones must be open and each must paste the other's link within about a minute. Compare the
two fingerprints out loud once, then mark the contact as verified. The next time, open the contact and tap
Connect: only that person's link is accepted.

The links are the same base64 text the terminal chat (`dolly`) prints, so an iPhone can talk to the Mac or
Windows command-line tools too.
