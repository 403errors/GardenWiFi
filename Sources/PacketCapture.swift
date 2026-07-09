import Foundation
import SwiftUI

// MARK: - Helpers
private extension String {
    /// Wraps the string in single-quotes and escapes any single-quotes inside.
    /// Safe for embedding arbitrary paths into shell commands.
    var shellEscaped: String {
        "'" + self.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

// MARK: - Capture State
enum CaptureState: Equatable {
    case idle
    case running(secondsLeft: Int)
    case done(pcapPath: String)
    case failed(reason: String)

    var isCapturing: Bool {
        if case .running = self { return true }
        return false
    }
}

// MARK: - Capture Session
@MainActor
class CaptureSession: ObservableObject {
    @Published var state: CaptureState = .idle
    @Published var livePacketCount: Int = 0
    
    @Published var capturedSSID: String = ""
    @Published var capturedBSSID: String = ""
    @Published var extractedHashPath: String? = nil
    @Published var extractionMessage: String? = nil

    private var process: Process?
    private var timer: Timer?

    // Duration in seconds
    static let captureDuration = 30

    func start(ssid: String, bssid: String, channel: Int) {
        guard !state.isCapturing else { return }

        livePacketCount = 0
        extractedHashPath = nil
        extractionMessage = nil
        self.capturedSSID = ssid
        self.capturedBSSID = bssid

        // Build output path: ~/Desktop/GardenWiFi-Captures/<SSID>-<timestamp>.pcap
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Desktop/GardenWiFi-Captures")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        let timestamp   = Int(Date().timeIntervalSince1970)
        let safeName    = ssid.components(separatedBy: .alphanumerics.inverted).joined(separator: "_")
        let finalURL    = dir.appendingPathComponent("\(safeName)-ch\(channel)-\(timestamp).pcap")
        let finalPath   = finalURL.path
        // Write to /tmp first — guaranteed writable by root regardless of Desktop perms.
        // We move the finished file to Desktop/GardenWiFi-Captures on success.
        let tmpPcapPath = "/tmp/gardenwifi_capture_\(timestamp).pcap"
        let pidFile     = "/tmp/gardenwifi_\(timestamp).pid"
        let logFile     = "/tmp/gardenwifi_\(timestamp).log"
        let launcherPath = "/tmp/gardenwifi_\(timestamp).sh"

        // The launcher script backgrounds tcpdump and writes its PID to a file,
        // then exits immediately so osascript returns (AppleScript blocks until
        // all foreground processes in the shell exit).
        let launcherLines = [
            "#!/bin/bash",
            "/usr/sbin/tcpdump -I -i en0 -U -w \(tmpPcapPath) ether host \(bssid) >\(logFile) 2>&1 &",
            "echo $! > \(pidFile)"
        ]
        let launcherScript = launcherLines.joined(separator: "\n")
        do {
            try launcherScript.write(toFile: launcherPath, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: launcherPath)
        } catch {
            state = .failed(reason: "Could not write launcher script: \(error.localizedDescription)")
            return
        }

        // Run the launcher via osascript (triggers macOS password prompt once)
        let appleScript = "do shell script \"\(launcherPath)\" with administrator privileges"
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", appleScript]
        proc.standardOutput = Pipe()   // discard stdout
        proc.standardError  = Pipe()   // discard stderr
        self.process = proc

        do { try proc.run() } catch {
            state = .failed(reason: "Could not launch osascript: \(error.localizedDescription)")
            return
        }

        state = .running(secondsLeft: Self.captureDuration)
        let duration = Self.captureDuration

        Task { @MainActor [weak self] in
            guard let self else { return }

            // ── Wait for launcher to write the PID file (poll up to 6 s) ──
            let tcpdumpPID: Int? = await withCheckedContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    // osascript returns after the launcher script exits (~instantly)
                    proc.waitUntilExit()

                    // Poll for PID file (the launcher writes it asynchronously)
                    var pid: Int? = nil
                    for _ in 0..<60 {
                        if let raw = try? String(contentsOfFile: pidFile, encoding: .utf8),
                           let p   = Int(raw.trimmingCharacters(in: .whitespacesAndNewlines)) {
                            pid = p
                            break
                        }
                        Thread.sleep(forTimeInterval: 0.1)
                    }
                    try? FileManager.default.removeItem(atPath: pidFile)
                    try? FileManager.default.removeItem(atPath: launcherPath)
                    continuation.resume(returning: pid)
                }
            }

            guard let pid = tcpdumpPID else {
                let log = (try? String(contentsOfFile: logFile, encoding: .utf8)) ?? ""
                try? FileManager.default.removeItem(atPath: logFile)
                let detail = log.isEmpty ? "" : "\n\nTcpdump error:\n\(log.prefix(300))"
                self.state = .failed(reason: "tcpdump failed to start. Check that Wi-Fi is on.\(detail)")
                return
            }

            // ── Early sanity check: tcpdump creates the pcap file immediately.
            //    If it doesn't appear within 3 s, it crashed at startup. ──
            let fileAppeared: Bool = await withCheckedContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    var found = false
                    for _ in 0..<30 {
                        if FileManager.default.fileExists(atPath: tmpPcapPath) { found = true; break }
                        Thread.sleep(forTimeInterval: 0.1)
                    }
                    continuation.resume(returning: found)
                }
            }
            guard fileAppeared else {
                let log = (try? String(contentsOfFile: logFile, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                try? FileManager.default.removeItem(atPath: logFile)
                let detail = log.isEmpty
                    ? "\n\nHint: tcpdump may have failed to open the interface. Try running:\n  sudo tcpdump -i en0 -c 1\nin Terminal to test basic capture permission."
                    : "\n\nTcpdump error:\n\(log.prefix(400))"
                self.state = .failed(reason: "tcpdump started (PID \(pid)) but didn't create the output file.\(detail)")
                return
            }

            // ── Countdown — cooperative sleeps keep UI responsive ──
            for remaining in stride(from: duration - 1, through: 0, by: -1) {
                guard case .running = self.state else { return }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                self.state = .running(secondsLeft: remaining)
            }
            guard case .running = self.state else { return }

            // ── Stop tcpdump gracefully by PID (SIGTERM flushes the pcap) ──
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                DispatchQueue.global(qos: .userInitiated).async {
                    // kill without admin — tcpdump was launched as root so we need sudo
                    let ks = "do shell script \"kill \(pid)\" with administrator privileges"
                    let kp = Process()
                    kp.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
                    kp.arguments = ["-e", ks]
                    kp.standardOutput = Pipe(); kp.standardError = Pipe()
                    try? kp.run(); kp.waitUntilExit()
                    c.resume()
                }
            }

            try? await Task.sleep(nanoseconds: 600_000_000)  // wait for pcap flush
            self.process = nil

            let log = (try? String(contentsOfFile: logFile, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            try? FileManager.default.removeItem(atPath: logFile)

            guard FileManager.default.fileExists(atPath: tmpPcapPath) else {
                let detail = log.isEmpty ? "" : "\n\nTcpdump output:\n\(log.prefix(500))"
                self.state = .failed(reason: "Capture produced no output file.\(detail)")
                return
            }

            let size = (try? FileManager.default.attributesOfItem(atPath: tmpPcapPath))?[.size] as? Int ?? 0
            guard size >= 24 else {
                try? FileManager.default.removeItem(atPath: tmpPcapPath)
                let detail = log.isEmpty ? "" : "\n\nTcpdump output:\n\(log.prefix(500))"
                self.state = .failed(reason: "tcpdump ran but captured 0 packets.\(detail)")
                return
            }

            // Move finished pcap from /tmp to Desktop/GardenWiFi-Captures/
            do {
                try FileManager.default.moveItem(atPath: tmpPcapPath, toPath: finalPath)
                self.state = .done(pcapPath: finalPath)
            } catch {
                // If move fails (e.g. Desktop folder issue), just keep it in /tmp
                self.state = .done(pcapPath: tmpPcapPath)
            }
            
            // Automatically extract handshake
            self.extractHandshake()
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        // Send SIGTERM to the tcpdump subprocess (it may already have ended)
        process?.terminate()
        process = nil
        if case .running = state {
            state = .idle
        }
    }

    func reset() {
        stop()
        livePacketCount = 0
        extractedHashPath = nil
        extractionMessage = nil
        state = .idle
    }

    func extractHandshake() {
        guard case .done(let pcapPath) = state else { return }
        
        let hashes = HandshakeExtractor.extract(pcapPath: pcapPath, ssid: capturedSSID, targetBssid: capturedBSSID)
        
        guard !hashes.isEmpty else {
            extractionMessage = "No PMKID or EAPOL handshakes found in this capture.\n\nHint: A handshake only occurs when a device connects to the network. Try capturing again, and while it is running, manually disconnect and reconnect your phone to the target WiFi to force a handshake over the air."
            return
        }
        
        // Write hashes to .hc22000 file
        let pcapURL = URL(fileURLWithPath: pcapPath)
        let hc22000URL = pcapURL.deletingPathExtension().appendingPathExtension("hc22000")
        
        let hashContent = hashes.map { $0.hashString }.joined(separator: "\n") + "\n"
        
        do {
            try hashContent.write(to: hc22000URL, atomically: true, encoding: .utf8)
            extractedHashPath = hc22000URL.path
            
            let pmkidCount = hashes.filter { $0.type == "01" }.count
            let eapolCount = hashes.filter { $0.type == "02" }.count
            
            var summary = "Successfully extracted: "
            if pmkidCount > 0 {
                summary += "\(pmkidCount) PMKID(s)"
            }
            if eapolCount > 0 {
                if pmkidCount > 0 { summary += ", " }
                summary += "\(eapolCount) EAPOL handshake(s)"
            }
            extractionMessage = "\(summary)\nSaved to: \(hc22000URL.lastPathComponent)"
        } catch {
            extractionMessage = "Failed to save .hc22000 file: \(error.localizedDescription)"
        }
    }
}

// MARK: - Capture Button + Sheet
struct CaptureButton: View {
    let network: WiFiNetwork
    @StateObject private var session = CaptureSession()
    @State private var showSheet = false

    var body: some View {
        Button {
            showSheet = true
        } label: {
            Image(systemName: "waveform.badge.magnifyingglass")
                .foregroundColor(.accentColor)
        }
        .buttonStyle(.plain)
        .help("Capture packets from this network")
        .sheet(isPresented: $showSheet) {
            CaptureSheet(network: network, session: session)
                .frame(width: 480, height: 400)
        }
    }
}

// MARK: - Capture Sheet
struct CaptureSheet: View {
    let network: WiFiNetwork
    @ObservedObject var session: CaptureSession
    @Environment(\.dismiss) private var dismiss
    
    @StateObject private var cracker = WPACracker()
    @State private var selectedWordlistURL: URL? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {

            // --- Header ---
            HStack(spacing: 12) {
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .font(.title2)
                    .foregroundColor(.accentColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Packet Capture")
                        .font(.headline)
                    Text(network.ssid)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.escape)
            }
            .padding()

            Divider()

            // --- Network Info ---
            VStack(alignment: .leading, spacing: 8) {
                infoRow("SSID", network.ssid)
                infoRow("BSSID (MAC)", network.bssid)
                infoRow("Channel", "\(network.channel)")
                infoRow("Band", network.band)
                infoRow("Security", network.security)
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)
            .padding(.horizontal)
            .padding(.top, 12)

            // --- Status Area ---
            Group {
                switch session.state {
                case .idle:
                    InfoBox(
                        icon: "info.circle",
                        color: .blue,
                        message: "Captures 802.11 frames from this access point for 30 seconds and saves them to ~/Desktop/GardenWiFi-Captures/. macOS will prompt for your admin password to enable monitor mode."
                    )

                case .running(let secondsLeft):
                    VStack(spacing: 8) {
                        ProgressView(value: Double(CaptureSession.captureDuration - secondsLeft),
                                     total: Double(CaptureSession.captureDuration))
                            .progressViewStyle(.linear)
                        HStack {
                            Image(systemName: "dot.radiowaves.left.and.right")
                                .foregroundColor(.green)
                            Text("Capturing… \(secondsLeft)s remaining")
                                .font(.callout)
                            Spacer()
                            Button("Stop") { session.stop() }
                                .buttonStyle(.bordered)
                        }
                    }

                case .done(let path):
                    VStack(alignment: .leading, spacing: 8) {
                        InfoBox(
                            icon: "checkmark.circle.fill",
                            color: .green,
                            message: "Capture complete! File saved to:\n\(URL(fileURLWithPath: path).lastPathComponent)"
                        )
                        
                        if let msg = session.extractionMessage {
                            VStack(alignment: .leading, spacing: 6) {
                                Text(msg)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                    .padding(.top, 4)
                                
                                CrackingStatusView(cracker: cracker)
                            }
                        }
                    }
                    .padding(.top, 4)

                case .failed(let reason):
                    InfoBox(icon: "xmark.circle.fill", color: .red, message: reason)
                }
            }
            .padding()

            Spacer()

            Divider()

            // --- Action ---
            HStack(spacing: 8) {
                if case .done(let path) = session.state {
                    if cracker.isCracking {
                        Button("Cancel Verification") {
                            cracker.cancel()
                        }
                        .buttonStyle(.bordered)
                        .tint(.red)
                        
                        Spacer()
                    } else {
                        Button("Capture Again") {
                            selectedWordlistURL = nil
                            cracker.state = .idle
                            session.reset()
                        }
                        .buttonStyle(.bordered)
                        
                        Spacer()
                        
                        Button("Reveal PCAP") {
                            NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
                        }
                        .buttonStyle(.bordered)
                        
                        if let hashPath = session.extractedHashPath {
                            Button("Reveal .hc22000") {
                                NSWorkspace.shared.selectFile(hashPath, inFileViewerRootedAtPath: "")
                            }
                            .buttonStyle(.bordered)
                            
                            switch cracker.state {
                            case .idle:
                                Button(action: selectWordlist) {
                                    HStack(spacing: 4) {
                                        Image(systemName: "folder")
                                        Text(selectedWordlistURL == nil ? "Select Wordlist..." : selectedWordlistURL!.lastPathComponent)
                                    }
                                }
                                .buttonStyle(.bordered)
                                
                                if selectedWordlistURL != nil {
                                    Button("Verify Hash") {
                                        startCracking(hashPath: hashPath)
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .tint(.green)
                                }
                                
                            case .success(let password, _):
                                Button("Copy Password") {
                                    let pasteboard = NSPasteboard.general
                                    pasteboard.clearContents()
                                    pasteboard.setString(password, forType: .string)
                                }
                                .buttonStyle(.borderedProminent)
                                .tint(.green)
                                
                                Button("Verify Again") {
                                    cracker.state = .idle
                                }
                                .buttonStyle(.bordered)
                                
                            case .notFound, .failed:
                                Button("Try Another Wordlist...") {
                                    selectWordlist()
                                    if selectedWordlistURL != nil {
                                        startCracking(hashPath: hashPath)
                                    }
                                }
                                .buttonStyle(.borderedProminent)
                                .tint(.blue)
                                
                            default:
                                EmptyView()
                            }
                        }
                    }
                } else if case .failed = session.state {
                    Button("Try Again") {
                        selectedWordlistURL = nil
                        cracker.state = .idle
                        session.reset()
                    }
                    .buttonStyle(.bordered)
                    
                    Spacer()
                } else {
                    Button("Close") { dismiss() }
                        .buttonStyle(.bordered)
                    
                    Spacer()
                    
                    if case .idle = session.state {
                        Button("Start Capture") {
                            session.start(ssid: network.ssid, bssid: network.bssid, channel: network.channel)
                        }
                        .buttonStyle(.borderedProminent)
                    } else if case .running = session.state {
                        Button("Stop Capture") { session.stop() }
                            .buttonStyle(.borderedProminent)
                            .tint(.red)
                    }
                }
            }
            .padding()
        }
    }

    private func selectWordlist() {
        let panel = NSOpenPanel()
        panel.title = "Select Wordlist File"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        
        if panel.runModal() == .OK {
            selectedWordlistURL = panel.url
        }
    }
    
    private func startCracking(hashPath: String) {
        guard let url = selectedWordlistURL else { return }
        guard let hashContent = try? String(contentsOfFile: hashPath, encoding: .utf8) else {
            cracker.state = .failed(reason: "Could not read hash file at: \(hashPath)")
            return
        }
        let lines = hashContent.components(separatedBy: .newlines).filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        guard let firstLine = lines.first else {
            cracker.state = .failed(reason: "Hash file is empty: \(hashPath)")
            return
        }
        
        cracker.crack(hashLine: firstLine, wordlistURL: url)
    }

    private func infoRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
                .frame(width: 90, alignment: .leading)
            Text(value)
                .font(.system(.caption, design: .monospaced))
        }
    }
}

// MARK: - Reusable Info Box
struct InfoBox: View {
    let icon: String
    let color: Color
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .foregroundColor(color)
                .font(.title3)
            Text(message)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .background(color.opacity(0.1))
        .cornerRadius(8)
    }
}

// MARK: - Cracking UI Status View
struct CrackingStatusView: View {
    @ObservedObject var cracker: WPACracker
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            switch cracker.state {
            case .idle:
                EmptyView()
                
            case .readingWordlist:
                HStack(spacing: 10) {
                    ProgressView()
                        .scaleEffect(0.6)
                        .frame(width: 16, height: 16)
                    Text("Preparing wordlist...")
                        .font(.callout)
                        .foregroundColor(.secondary)
                }
                .padding(.vertical, 8)
                
            case .cracking(let tested, let total, let speed, let currentWord, let elapsed):
                VStack(alignment: .leading, spacing: 8) {
                    ProgressView(value: Double(tested), total: Double(total))
                        .progressViewStyle(.linear)
                    
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text("Progress:")
                                .foregroundColor(.secondary)
                                .frame(width: 70, alignment: .leading)
                            Text("\(tested) / \(total) (\(Int(Double(tested)/Double(total)*100.0))%)")
                                .fontWeight(.medium)
                        }
                        HStack {
                            Text("Speed:")
                                .foregroundColor(.secondary)
                                .frame(width: 70, alignment: .leading)
                            Text("\(Int(speed)) keys/s")
                                .fontWeight(.medium)
                        }
                        HStack {
                            Text("Elapsed:")
                                .foregroundColor(.secondary)
                                .frame(width: 70, alignment: .leading)
                            Text(formatTime(elapsed))
                                .fontWeight(.medium)
                        }
                        HStack {
                            Text("Current:")
                                .foregroundColor(.secondary)
                                .frame(width: 70, alignment: .leading)
                            Text(currentWord)
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.accentColor)
                                .lineLimit(1)
                        }
                    }
                    .font(.caption)
                }
                
            case .success(let password, let elapsed):
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: "checkmark.seal.fill")
                            .foregroundColor(.green)
                            .font(.title2)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("PASSWORD FOUND!")
                                .font(.subheadline)
                                .fontWeight(.bold)
                                .foregroundColor(.green)
                            Text("Found in \(formatTime(elapsed))")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(8)
                    .background(Color.green.opacity(0.1))
                    .cornerRadius(8)
                    
                    HStack {
                        Text("Passphrase:")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                        Text(password)
                            .font(.system(.title3, design: .monospaced))
                            .fontWeight(.bold)
                            .foregroundColor(.primary)
                            .textSelection(.enabled)
                    }
                    .padding(.top, 4)
                }
                
            case .notFound(let elapsed):
                HStack {
                    Image(systemName: "exclamationmark.shield.fill")
                        .foregroundColor(.orange)
                        .font(.title2)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("PASSWORD NOT FOUND")
                            .font(.subheadline)
                            .fontWeight(.bold)
                            .foregroundColor(.orange)
                        Text("Checked wordlist in \(formatTime(elapsed))")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                .padding(8)
                .background(Color.orange.opacity(0.1))
                .cornerRadius(8)
                
            case .failed(let reason):
                HStack {
                    Image(systemName: "xmark.octagon.fill")
                        .foregroundColor(.red)
                        .font(.title2)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("ERROR OCCURRED")
                            .font(.subheadline)
                            .fontWeight(.bold)
                            .foregroundColor(.red)
                        Text(reason)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                .padding(8)
                .background(Color.red.opacity(0.1))
                .cornerRadius(8)
            }
        }
    }
    
    private func formatTime(_ interval: TimeInterval) -> String {
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.minute, .second]
        formatter.unitsStyle = .abbreviated
        return formatter.string(from: interval) ?? "\(Int(interval))s"
    }
}
