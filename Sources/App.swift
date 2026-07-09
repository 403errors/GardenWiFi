import SwiftUI
import CoreWLAN
import CoreLocation

// MARK: - App Entry Point
@main
struct GardenWiFiApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 700, minHeight: 450)
        }
        .windowStyle(HiddenTitleBarWindowStyle())
    }
}

// MARK: - Models
struct WiFiNetwork: Identifiable {
    let id = UUID()
    let ssid: String
    let bssid: String
    let rssi: Int
    let noise: Int
    let channel: Int
    let band: String
    let security: String
    let vendor: String
}

// MARK: - Location Manager
@MainActor
class LocationManager: NSObject, ObservableObject, CLLocationManagerDelegate {
    private var manager = CLLocationManager()
    @Published var isAuthorized = false
    
    override init() {
        super.init()
        manager.delegate = self
    }
    
    func requestPermission() {
        if manager.authorizationStatus == .notDetermined {
            manager.requestWhenInUseAuthorization()
        } else {
            // In macOS, authorizedAlways is the main authorized state (or just .authorized on older macOS)
            isAuthorized = (manager.authorizationStatus == .authorizedAlways || manager.authorizationStatus == .authorized)
        }
    }
    
    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let status = manager.authorizationStatus
        Task { @MainActor in
            self.isAuthorized = (status == .authorizedAlways || status == .authorized)
        }
    }
}

// MARK: - Scanner
@MainActor
class WiFiScanner: ObservableObject {
    @Published var networks: [WiFiNetwork] = []
    @Published var isScanning = false
    @Published var errorMessage: String? = nil
    
    func scan() {
        isScanning = true
        errorMessage = nil
        
        Task {
            do {
                // Run the blocking scan in a detached background task to prevent UI freezes
                let mappedNetworks = try await Task.detached {
                    let client = CWWiFiClient.shared()
                    guard let interface = client.interface() else {
                        throw NSError(domain: "WiFiError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Could not find a Wi-Fi interface. Ensure Wi-Fi is enabled."])
                    }
                    
                    let cwNetworks = try interface.scanForNetworks(withName: nil)
                    let sorted = cwNetworks.sorted { $0.rssiValue > $1.rssiValue }
                    
                    return sorted.map { net in
                        let ssid = net.ssid ?? "<Hidden>"
                        return WiFiNetwork(
                            ssid: ssid,
                            bssid: net.bssid ?? "Unknown",
                            rssi: net.rssiValue,
                            noise: net.noiseMeasurement,
                            channel: net.wlanChannel?.channelNumber ?? 0,
                            band: getBandString(for: net),
                            security: getSecurityString(for: net),
                            vendor: getVendor(for: net.bssid ?? "Unknown", ssid: ssid)
                        )
                    }
                }.value
                
                self.networks = mappedNetworks
                self.isScanning = false
                
            } catch {
                self.errorMessage = error.localizedDescription
                self.isScanning = false
            }
        }
    }
}

// MARK: - UI Components
struct ContentView: View {
    @StateObject private var locationManager = LocationManager()
    @StateObject private var scanner = WiFiScanner()
    
    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("GardenWiFi")
                        .font(.title)
                        .fontWeight(.bold)
                    Text("Nearby Network Scanner")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                if !locationManager.isAuthorized {
                    HStack {
                        Image(systemName: "location.slash.fill")
                        Text("Location access needed for SSIDs")
                    }
                    .foregroundColor(.orange)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color.orange.opacity(0.2))
                    .cornerRadius(8)
                }
                
                Button(action: {
                    scanner.scan()
                }) {
                    if scanner.isScanning {
                        ProgressView()
                            .scaleEffect(0.6)
                            .frame(width: 24, height: 24)
                    } else {
                        Image(systemName: "arrow.clockwise")
                            .font(.system(size: 14, weight: .bold))
                            .frame(width: 24, height: 24)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(scanner.isScanning)
                .keyboardShortcut("r", modifiers: .command)
                .help("Refresh (⌘R)")
            }
            .padding()
            .background(Color(NSColor.windowBackgroundColor))
            
            Divider()
            
            // Content
            if let error = scanner.errorMessage {
                VStack {
                    Spacer()
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.largeTitle)
                        .foregroundColor(.red)
                        .padding(.bottom, 8)
                    Text(error)
                        .foregroundColor(.secondary)
                    Spacer()
                }
            } else {
                Table(scanner.networks) {
                    TableColumn("SSID", value: \.ssid)
                        .width(min: 150, ideal: 180)
                    
                    TableColumn("Manufacturer", value: \.vendor)
                        .width(min: 130, ideal: 150)
                    
                    TableColumn("Security", value: \.security)
                        .width(min: 80, ideal: 90)
                    
                    TableColumn("RSSI") { network in
                        HStack(spacing: 8) {
                            SignalBars(rssi: network.rssi)
                            Text("\(network.rssi) dBm")
                                .font(.system(.body, design: .monospaced))
                        }
                    }
                    .width(min: 100, ideal: 120, max: 120)
                    
                    TableColumn("Channel") { network in
                        Text("\(network.channel)")
                    }
                    .width(min: 60, max: 80)
                    
                    TableColumn("Band", value: \.band)
                        .width(min: 60, max: 80)
                    
                    TableColumn("Noise") { network in
                        Text("\(network.noise) dBm")
                            .font(.system(.body, design: .monospaced))
                    }
                    .width(min: 80, max: 100)
                    
                    TableColumn("BSSID", value: \.bssid)
                        .width(min: 130, ideal: 150)
                    
                    TableColumn("Capture") { network in
                        CaptureButton(network: network)
                    }
                    .width(ideal: 60, max: 70)
                }
                .overlay(
                    Group {
                        if scanner.networks.isEmpty && !scanner.isScanning {
                            Text("No networks found")
                                .foregroundColor(.secondary)
                        }
                    }
                )
            }
        }
        .onAppear {
            locationManager.requestPermission()
            scanner.scan()
        }
        .onChange(of: locationManager.isAuthorized) { authorized in
            if authorized {
                scanner.scan()
            }
        }
    }
}

// MARK: - Signal Bars View
struct SignalBars: View {
    let rssi: Int
    
    var bars: Int {
        if rssi > -50 { return 4 }
        if rssi > -65 { return 3 }
        if rssi > -80 { return 2 }
        if rssi > -90 { return 1 }
        return 0
    }
    
    var color: Color {
        switch bars {
        case 4: return .green
        case 3: return .green
        case 2: return .yellow
        case 1: return .orange
        default: return .red
        }
    }
    
    var body: some View {
        HStack(alignment: .bottom, spacing: 2) {
            ForEach(0..<4) { index in
                RoundedRectangle(cornerRadius: 1)
                    .fill(index < bars ? color : Color.gray.opacity(0.3))
                    .frame(width: 4, height: CGFloat(6 + (index * 3)))
            }
        }
    }
}
