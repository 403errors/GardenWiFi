import Foundation
import CoreWLAN

class OUILookup: @unchecked Sendable {
    static let shared = OUILookup()
    
    private var ouiMap: [String: String] = [:]
    
    private init() {
        guard let url = Bundle.module.url(forResource: "manuf", withExtension: "txt") else {
            print("Failed to find manuf.txt in bundle")
            return
        }
        
        do {
            let content = try String(contentsOf: url, encoding: .utf8)
            let lines = content.components(separatedBy: .newlines)
            for line in lines {
                if line.hasPrefix("#") || line.isEmpty { continue }
                
                // The Wireshark manuf file separates columns by tabs/spaces.
                // Col 0: MAC Prefix, Col 1: Short Vendor, Col 2: Full Vendor
                let parts = line.components(separatedBy: .whitespaces).filter { !$0.isEmpty }
                
                if parts.count >= 2 {
                    let prefix = parts[0].uppercased()
                    // Only index the standard 24-bit OUI prefixes (XX:XX:XX) which are 8 chars
                    if prefix.count == 8 {
                        // The short vendor name is the second token
                        ouiMap[prefix] = parts[1]
                    }
                }
            }
            print("Successfully loaded \(ouiMap.count) OUI vendor prefixes.")
        } catch {
            print("Failed to load OUI map: \(error)")
        }
    }
    
    func vendor(for bssid: String, ssid: String) -> String {
        // Detect MAC randomization (locally administered)
        // Check the second character of the MAC address
        if bssid.count >= 2 {
            let secondChar = bssid[bssid.index(bssid.startIndex, offsetBy: 1)].uppercased()
            if ["2", "6", "A", "E"].contains(secondChar) {
                return "Randomized (Hotspot/Mesh)"
            }
        }
        
        let prefix = String(bssid.prefix(8)).uppercased()
        let vendorName = ouiMap[prefix] ?? "Unknown"
        
        // Clean up common OEM names for ISPs
        let lowerSSID = ssid.lowercased()
        if lowerSSID.contains("airtel") {
            if vendorName == "Unknown" { return "Airtel" }
            return "Airtel (\(vendorName))"
        }
        if lowerSSID.contains("jio") {
            if vendorName == "Unknown" { return "Jio" }
            return "Jio (\(vendorName))"
        }
        if lowerSSID.contains("act") {
            if vendorName == "Unknown" { return "ACT Fibernet" }
            return "ACT (\(vendorName))"
        }
        
        return vendorName
    }
}

func getVendor(for bssid: String, ssid: String) -> String {
    return OUILookup.shared.vendor(for: bssid, ssid: ssid)
}

func getBandString(for network: CWNetwork) -> String {
    guard let channel = network.wlanChannel else { return "Unknown" }
    switch channel.channelBand {
    case .bandUnknown: return "Unknown"
    case .band2GHz: return "2.4 GHz"
    case .band5GHz: return "5 GHz"
    case .band6GHz: return "6 GHz"
    @unknown default: return "Unknown"
    }
}

func getSecurityString(for network: CWNetwork) -> String {
    if network.supportsSecurity(.wpa3Personal) { return "WPA3" }
    if network.supportsSecurity(.wpa3Enterprise) { return "WPA3 Ent" }
    if network.supportsSecurity(.wpa2Personal) { return "WPA2" }
    if network.supportsSecurity(.wpa2Enterprise) { return "WPA2 Ent" }
    if network.supportsSecurity(.wpaPersonal) { return "WPA" }
    if network.supportsSecurity(.wpaEnterprise) { return "WPA Ent" }
    if network.supportsSecurity(.WEP) { return "WEP" }
    if network.supportsSecurity(.none) { return "Open" }
    return "Secure"
}
