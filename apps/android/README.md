# Dolly for Android

Jetpack Compose app for Android 17 (API 37), minimum Android 13 (API 33). The protocol, transport and
encrypted store are the Kotlin core in `../../core-kotlin`, compiled into the app from source (see
`app/build.gradle.kts`), so the app and the command-line tool run the same code. The app adds the screens,
the Android Keystore key custody (`KeyVault`), a serial-dispatcher wrapper around the store (`Database`) and a
foreground service that keeps the socket open while a conversation is running.

Dependencies: Jetpack Compose (UI) and kotlinx-coroutines. Nothing in the cryptography or networking.

## Build

The Gradle wrapper is not committed yet. Create it once (JDK 17 or newer, Gradle 9.6+):

```sh
cd apps/android
gradle wrapper --gradle-version 9.6.0
```

Then open `apps/android` (not the repository root) in Android Studio, let it sync, and run on a phone with
USB debugging on. The SDK needs Platform 37 and Build-Tools 37.

## Using it

Same flow as iOS: tap New conversation on both phones, swap links (Share, then Paste on the other side),
compare the fingerprints out loud once and mark the contact as verified. Links are the same base64 the
terminal chat prints, so the phone can talk to the Mac or Windows tools and to the iPhone app.

Android 17 asks for the "nearby devices" permission the first time: it is only needed to reach a contact on
the same Wi-Fi, and a session works without it. The notification permission only controls whether the
"conversation open" notice is shown.
