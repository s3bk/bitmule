import SwiftUI
import UniformTypeIdentifiers
import UIKit

private let defaultServer = "https://bitmule.qdat.net"

/// Send and receive on one screen, as on Android.
struct ContentView: View {
    @Binding var incoming: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                SendSection()
                Divider()
                ReceiveSection(incoming: $incoming)
            }
            .padding(16)
        }
    }
}

// MARK: - Send

/// Reports the share link from the Rust core's task.
private final class LinkListener: UrlListener, @unchecked Sendable {
    let onLink: @Sendable (String) -> Void
    init(onLink: @escaping @Sendable (String) -> Void) { self.onLink = onLink }
    func onUrl(url: String, sessionHex: String, fileName: String, fileSize: UInt64) { onLink(url) }
}

private struct SendSection: View {
    @State private var importing = false
    @State private var names: [String] = []
    @State private var paths: [String] = []
    @State private var sending = false
    @State private var done = false
    @State private var shareUrl: String?
    @State private var qr: UIImage?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Send").font(.title2)
            Button(pickLabel) { importing = true }
                .buttonStyle(.borderedProminent)
                .disabled(sending)
                .frame(maxWidth: .infinity)
            Button(sending ? "Sending…" : "Share") { Task { await share() } }
                .buttonStyle(.borderedProminent)
                .disabled(paths.isEmpty || sending)
                .frame(maxWidth: .infinity)

            if let url = shareUrl {
                Text(url).font(.footnote).textSelection(.enabled).lineLimit(3)
                HStack {
                    Button("Copy") { UIPasteboard.general.string = url }.buttonStyle(.bordered)
                    ShareLink("Share URL", item: url).buttonStyle(.bordered)
                }
                if let qr {
                    Image(uiImage: qr).resizable().interpolation(.none).scaledToFit()
                        .frame(maxWidth: .infinity, maxHeight: 320)
                }
            }
            if let error { Text("error: \(error)").foregroundStyle(.red) }
            if done { Text("✓ transfer complete").foregroundStyle(.green) }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
            guard case .success(let urls) = result else { return }
            let copies = urls.compactMap(Self.copyToCache)
            names = copies.map(\.0)
            paths = copies.map(\.1)
        }
    }

    private var pickLabel: String {
        switch names.count {
        case 0: return "Pick file(s)"
        case 1: return "Pick file(s) — currently: \(names[0])"
        default: return "Pick file(s) — currently: \(names.count) files"
        }
    }

    /// The Rust core wants plain paths: copy what the picker hands out (a
    /// security-scoped URL) into the app's cache.
    private static func copyToCache(_ url: URL) -> (String, String)? {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("send-\(UUID().uuidString)")
        let target = dir.appendingPathComponent(url.lastPathComponent)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try FileManager.default.copyItem(at: url, to: target)
            return (url.lastPathComponent, target.path)
        } catch {
            return nil
        }
    }

    private func share() async {
        sending = true; done = false; shareUrl = nil; qr = nil; error = nil
        let listener = LinkListener { url in
            Task { @MainActor in
                shareUrl = url
                if let png = try? qrPngBytes(text: url, pixelScale: 12) { qr = UIImage(data: png) }
            }
        }
        do {
            // multi is ignored: a send ends once the receivers that connected are done
            _ = try await sendFile(server: defaultServer, filePaths: paths, multi: false, onUrl: listener)
            done = true
        } catch {
            self.error = "\(error)"
        }
        sending = false
    }
}

// MARK: - Receive

private final class ProgressBox: ProgressListener, @unchecked Sendable {
    let onChange: @Sendable (UInt64, UInt64, String) -> Void
    init(onChange: @escaping @Sendable (UInt64, UInt64, String) -> Void) { self.onChange = onChange }
    func onProgress(sent: UInt64, total: UInt64, name: String) { onChange(sent, total, name) }
}

private struct ReceiveSection: View {
    @Binding var incoming: String?
    @State private var url = ""
    @State private var scanning = false
    @State private var receiving = false
    @State private var progress = 0.0
    @State private var name = ""
    @State private var result: URL?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Receive").font(.title2)
            Button("Scan QR") { scanning = true }.buttonStyle(.bordered).frame(maxWidth: .infinity)
            TextField("bitmule URL", text: $url)
                .textFieldStyle(.roundedBorder)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
            Button(receiving ? "Receiving…" : "Fetch") { Task { await fetch() } }
                .buttonStyle(.borderedProminent)
                .disabled(url.trimmingCharacters(in: .whitespaces).isEmpty || receiving)
                .frame(maxWidth: .infinity)

            if receiving {
                ProgressView(value: progress)
                if !name.isEmpty { Text(name).font(.footnote) }
            }
            if let error { Text("error: \(error)").foregroundStyle(.red) }
            if let result {
                Text("✓ \(result.lastPathComponent)").font(.headline)
                Text(result.path).font(.footnote).textSelection(.enabled)
                ShareLink(item: result).buttonStyle(.bordered)
            }
        }
        .sheet(isPresented: $scanning) {
            QRScannerView { code in
                url = code.trimmingCharacters(in: .whitespacesAndNewlines)
                scanning = false
            } onCancel: { scanning = false }
        }
        .onChange(of: incoming) { _, link in
            guard let link else { return }
            url = link
            incoming = nil
        }
        .onAppear {
            if let link = incoming { url = link; incoming = nil }
        }
    }

    private func fetch() async {
        receiving = true; progress = 0; name = ""; result = nil; error = nil
        let box = ProgressBox { received, total, file in
            Task { @MainActor in
                progress = total > 0 ? Double(received) / Double(total) : 0
                name = file
            }
        }
        do {
            // visible in the Files app under "bitmule" (UIFileSharingEnabled)
            let out = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
                .appendingPathComponent("bitmule")
            let outcome = try await recvFile(url: url.trimmingCharacters(in: .whitespaces), outDir: out.path, onProgress: box)
            result = URL(fileURLWithPath: outcome.path)
        } catch {
            self.error = "\(error)"
        }
        receiving = false
    }
}
