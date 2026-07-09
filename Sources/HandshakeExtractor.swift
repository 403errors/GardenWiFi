import Foundation

struct HandshakeHash {
    let type: String // "01" (PMKID) or "02" (EAPOL)
    let hashString: String
}

class HandshakeExtractor {
    
    static func extract(pcapPath: String, ssid: String, targetBssid: String) -> [HandshakeHash] {
        guard let reader = PcapReader(filePath: pcapPath) else {
            print("Failed to open or parse PCAP file: \(pcapPath)")
            return []
        }
        
        let targetBssidClean = targetBssid.replacingOccurrences(of: ":", with: "").lowercased()
        let essidHex = ssid.data(using: .utf8)?.hexEncodedString ?? ""
        
        var m1Dict: [String: Data] = [:] // Keyed by: clientMAC_replayCounter -> AP Nonce (ANonce)
        var hashes: [HandshakeHash] = []
        var processedPmkids = Set<String>()
        var processedEapols = Set<String>()
        
        while let packet = reader.readNextPacket() {
            let data = packet.data
            var eapolData: Data? = nil
            var srcMAC = ""
            var dstMAC = ""
            
            if reader.getLinkType == 1 { // Ethernet
                guard data.count >= 14 else { continue }
                dstMAC = data.subdata(in: 0..<6).hexEncodedString
                srcMAC = data.subdata(in: 6..<12).hexEncodedString
                let etherType = (UInt16(data[12]) << 8) | UInt16(data[13])
                
                if etherType == 0x888E {
                    eapolData = data.subdata(in: 14..<data.count)
                }
            } else if reader.getLinkType == 127 || reader.getLinkType == 105 { // Radiotap or 802.11
                var offset = 0
                if reader.getLinkType == 127 { // Radiotap
                    guard data.count >= 4 else { continue }
                    let radiotapHeaderLen = Int(data[2]) | (Int(data[3]) << 8)
                    guard data.count >= radiotapHeaderLen + 24 else { continue }
                    offset = radiotapHeaderLen
                }
                
                guard data.count >= offset + 24 else { continue }
                let fc = UInt16(data[offset]) | (UInt16(data[offset+1]) << 8)
                let type = (fc & 0x000C) >> 2
                let subtype = (fc & 0x00F0) >> 4
                
                if type == 2 {
                    let addr1 = data.subdata(in: offset + 4 ..< offset + 10).hexEncodedString
                    let addr2 = data.subdata(in: offset + 10 ..< offset + 16).hexEncodedString
                    
                    dstMAC = addr1
                    srcMAC = addr2
                    
                    var payloadOffset = offset + 24
                    
                    let toDS = (fc & 0x0100) != 0
                    let fromDS = (fc & 0x0200) != 0
                    if toDS && fromDS {
                        payloadOffset += 6 // Addr4
                    }
                    
                    if (subtype & 0x08) != 0 { // QoS Data
                        payloadOffset += 2 // QoS Control
                        if (fc & 0x8000) != 0 { // Order bit -> HT Control
                            payloadOffset += 4
                        }
                    }
                    
                    // LLC / SNAP Header (8 bytes)
                    guard data.count >= payloadOffset + 8 else { continue }
                    let etherType = (UInt16(data[payloadOffset + 6]) << 8) | UInt16(data[payloadOffset + 7])
                    
                    if etherType == 0x888E {
                        eapolData = data.subdata(in: payloadOffset + 8 ..< data.count)
                    }
                }
            }
            
            guard let eapol = eapolData, eapol.count >= 99 else { continue }
            
            let eapolType = eapol[1]
            guard eapolType == 3 else { continue } // Key
            
            let eapolLength = (Int(eapol[2]) << 8) | Int(eapol[3])
            let totalEapolFrameSize = 4 + eapolLength
            guard eapol.count >= totalEapolFrameSize else { continue }
            
            let eapolFrame = eapol.subdata(in: 0..<totalEapolFrameSize)
            
            let keyDescType = eapol[4]
            guard keyDescType == 2 || keyDescType == 254 else { continue }
            
            let keyInfo = (UInt16(eapol[5]) << 8) | UInt16(eapol[6])
            
            // Check if it is a Pairwise key exchange
            let isPairwise = (keyInfo & 0x0008) != 0
            guard isPairwise else { continue }
            
            let keyAck = (keyInfo & 0x0080) != 0
            let keyMic = (keyInfo & 0x0100) != 0
            let secure = (keyInfo & 0x0200) != 0
            
            let replayCounterBytes = eapolFrame.subdata(in: 9..<17)
            let replayCounterStr = replayCounterBytes.hexEncodedString
            
            let keyNonce = eapolFrame.subdata(in: 17..<49)
            let keyMicBytes = eapolFrame.subdata(in: 81..<97)
            
            let keyDataLength = (Int(eapolFrame[97]) << 8) | Int(eapolFrame[98])
            let keyData = eapolFrame.subdata(in: 99..<min(eapolFrame.count, 99 + keyDataLength))
            
            // Determine AP and Client MACs
            let isFromAP: Bool
            let apMac: String
            let clientMac: String
            
            if srcMAC == targetBssidClean {
                isFromAP = true
                apMac = srcMAC
                clientMac = dstMAC
            } else if dstMAC == targetBssidClean {
                isFromAP = false
                apMac = dstMAC
                clientMac = srcMAC
            } else {
                // Not matching our target AP
                continue
            }
            
            // ── Extract PMKID (WPA*01) ──
            if isFromAP && !keyMic {
                if let pmkid = parsePMKID(from: keyData) {
                    let pmkidHex = pmkid.hexEncodedString
                    let hashLine = "WPA*01*\(pmkidHex)*\(apMac)*\(clientMac)*\(essidHex)***"
                    if !processedPmkids.contains(hashLine) {
                        processedPmkids.insert(hashLine)
                        hashes.append(HandshakeHash(type: "01", hashString: hashLine))
                    }
                }
            }
            
            // ── Extract EAPOL Handshake (WPA*02) ──
            if isFromAP && keyAck && !keyMic && !secure {
                // Message 1 (AP to Client)
                let dictKey = "\(clientMac)_\(replayCounterStr)"
                m1Dict[dictKey] = keyNonce
            } else if !isFromAP && !keyAck && keyMic && !secure {
                // Message 2 (Client to AP)
                let dictKey = "\(clientMac)_\(replayCounterStr)"
                if let anonce = m1Dict[dictKey] {
                    // We have M1 and M2! Build WPA*02 hash
                    let micHex = keyMicBytes.hexEncodedString
                    let anonceHex = anonce.hexEncodedString
                    
                    // Zero out the MIC field in the client EAPOL M2 frame
                    var zeroedEapolFrame = eapolFrame
                    for i in 81..<97 {
                        if i < zeroedEapolFrame.count {
                            zeroedEapolFrame[i] = 0
                        }
                    }
                    let eapolClientHex = zeroedEapolFrame.hexEncodedString
                    
                    let hashLine = "WPA*02*\(micHex)*\(apMac)*\(clientMac)*\(essidHex)*\(anonceHex)*\(eapolClientHex)*00"
                    if !processedEapols.contains(hashLine) {
                        processedEapols.insert(hashLine)
                        hashes.append(HandshakeHash(type: "02", hashString: hashLine))
                    }
                }
            }
        }
        
        return hashes
    }
    
    private static func parsePMKID(from keyData: Data) -> Data? {
        var offset = 0
        while offset + 2 <= keyData.count {
            let elementID = keyData[offset]
            let length = Int(keyData[offset + 1])
            if offset + 2 + length > keyData.count { break }
            
            if elementID == 48 { // RSN IE
                let rsnData = keyData.subdata(in: offset + 2 ..< offset + 2 + length)
                if let pmkid = extractPMKIDFromRSN(rsnData) {
                    return pmkid
                }
            }
            offset += 2 + length
        }
        return nil
    }
    
    private static func extractPMKIDFromRSN(_ rsnData: Data) -> Data? {
        var offset = 0
        guard rsnData.count >= 2 + 4 + 2 else { return nil }
        offset += 2 // Version
        offset += 4 // Group Cipher
        
        // Pairwise Cipher List
        let pairwiseCount = Int(rsnData[offset]) | (Int(rsnData[offset + 1]) << 8)
        offset += 2
        guard rsnData.count >= offset + 4 * pairwiseCount + 2 else { return nil }
        offset += 4 * pairwiseCount
        
        // AKM List
        let akmCount = Int(rsnData[offset]) | (Int(rsnData[offset + 1]) << 8)
        offset += 2
        guard rsnData.count >= offset + 4 * akmCount + 2 else { return nil }
        offset += 4 * akmCount
        
        // Capabilities
        guard rsnData.count >= offset + 2 + 2 else { return nil }
        offset += 2 // Capabilities
        
        // PMKID Count
        let pmkidCount = Int(rsnData[offset]) | (Int(rsnData[offset + 1]) << 8)
        offset += 2
        
        if pmkidCount > 0 && rsnData.count >= offset + 16 {
            return rsnData.subdata(in: offset ..< offset + 16)
        }
        return nil
    }
}

// Private helper structures for PcapReader inside HandshakeExtractor.swift
private struct PcapPacket {
    let timestampSec: UInt32
    let timestampUsec: UInt32
    let data: Data
}

private class PcapReader {
    private let data: Data
    private var offset: Int = 0
    private var isSwapped: Bool = false
    private var linkType: UInt32 = 1

    init?(filePath: String) {
        guard let fileData = try? Data(contentsOf: URL(fileURLWithPath: filePath)) else {
            return nil
        }
        self.data = fileData
        guard fileData.count >= 24 else { return nil }

        let magic = readUInt32(at: 0, swapped: false)
        if magic == 0xa1b2c3d4 || magic == 0xa1b23c4d {
            isSwapped = false
        } else if magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1 {
            isSwapped = true
        } else {
            return nil
        }

        linkType = readUInt32(at: 20, swapped: isSwapped)
        offset = 24
    }

    private func readUInt32(at index: Int, swapped: Bool) -> UInt32 {
        guard index + 4 <= data.count else { return 0 }
        let value = data.subdata(in: index..<index+4).withUnsafeBytes { $0.load(as: UInt32.self) }
        return swapped ? value.byteSwapped : value
    }

    func readNextPacket() -> PcapPacket? {
        guard offset + 16 <= data.count else { return nil }

        let tsSec = readUInt32(at: offset, swapped: isSwapped)
        let tsUsec = readUInt32(at: offset + 4, swapped: isSwapped)
        let inclLen = readUInt32(at: offset + 8, swapped: isSwapped)
        
        offset += 16
        guard offset + Int(inclLen) <= data.count else { return nil }

        let packetData = data.subdata(in: offset..<offset+Int(inclLen))
        offset += Int(inclLen)

        return PcapPacket(timestampSec: tsSec, timestampUsec: tsUsec, data: packetData)
    }

    var getLinkType: UInt32 {
        return linkType
    }
}

extension Data {
    var hexEncodedString: String {
        return map { String(format: "%02x", $0) }.joined()
    }
}
