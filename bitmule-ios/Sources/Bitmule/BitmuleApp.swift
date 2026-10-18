import SwiftUI

@main
struct BitmuleApp: App {
    /// A link that opened the app (bitmule:// or a pasted/shared https link).
    @State private var incoming: String?

    var body: some Scene {
        WindowGroup {
            ContentView(incoming: $incoming)
                .onOpenURL { url in
                    incoming = Self.shareUrl(from: url)
                }
        }
    }

    /// `bitmule://host/#fragment` -> `https://host/#fragment`; https links pass as they are.
    static func shareUrl(from url: URL) -> String {
        guard url.scheme == "bitmule" else { return url.absoluteString }
        var parts = URLComponents(url: url, resolvingAgainstBaseURL: false)
        parts?.scheme = "https"
        return parts?.string ?? url.absoluteString
    }
}
