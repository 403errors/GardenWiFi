import Foundation
import CommonCrypto

// MARK: - Local Data Lexicographical Comparison Helper
private extension Data {
    static func < (lhs: Data, rhs: Data) -> Bool {
        let count = Swift.min(lhs.count, rhs.count)
        for i in 0..<count {
            if lhs[i] < rhs[i] { return true }
            if lhs[i] > rhs[i] { return false }
        }
        return lhs.count < rhs.count
    }
}

// MARK: - Cracking State
enum CrackingState: Sendable, Equatable {
    case idle
    case readingWordlist
    case cracking(tested: Int, total: Int, speed: Double, currentWord: String, elapsed: TimeInterval)
    case success(password: String, elapsed: TimeInterval)
    case notFound(elapsed: TimeInterval)
    case failed(reason: String)
}

// MARK: - Target Hash Details
enum HashType: Sendable {
    case pmkid
    case eapol
}

struct TargetHash: Sendable {
    let type: HashType
    let ssid: String
    let ssidBytes: Data
    let apMac: Data
    let clientMac: Data
    let micOrPmkid: Data
    let anonce: Data?
    let eapolClient: Data?
    let keyDescriptorVersion: Int?
}

// MARK: - Internal Task Result
private enum CrackingTaskResult {
    case success(password: String, elapsed: TimeInterval)
    case notFound(elapsed: TimeInterval)
    case failed(reason: String)
    case cancelled
}

// MARK: - WPA Cracker Engine
@MainActor
class WPACracker: ObservableObject {
    @Published var state: CrackingState = .idle
    @Published var isCracking = false
    
    private var isCancelled = false
    
    func crack(hashLine: String, wordlistURL: URL) {
        isCancelled = false
        isCracking = true
        state = .readingWordlist
        
        Task {
            // Run the entire cracking flow in a detached task to keep the MainActor completely free
            let result = await Task.detached(priority: .userInitiated) { [weak self] () -> CrackingTaskResult in
                guard let self = self else { return .failed(reason: "WPACracker instance deallocated") }
                
                // 1. Parse hash line
                guard let target = await self.parseHashLine(hashLine) else {
                    return .failed(reason: "Invalid or unsupported WPA hash line format.")
                }
                
                // 2. Count lines (asynchronously, with security scope)
                let totalWords: Int
                do {
                    totalWords = try await self.countLines(at: wordlistURL)
                } catch {
                    return .failed(reason: "Could not read wordlist: \(error.localizedDescription)")
                }
                
                guard totalWords > 0 else {
                    return .failed(reason: "Wordlist is empty.")
                }
                
                // 3. Open file using LineReader (handles security scoped init)
                guard let fileReader = LineReader(url: wordlistURL) else {
                    return .failed(reason: "Could not open wordlist file (permission denied).")
                }
                
                let startTime = Date()
                var wordsTested = 0
                let batchSize = 10000 // Large batches for high multi-core throughput
                var batch: [String] = []
                
                while let word = fileReader.nextLine() {
                    // Check cancellation periodically
                    let cancelled = await self.checkCancelled()
                    if cancelled {
                        return .cancelled
                    }
                    
                    let cleanedWord = word.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !cleanedWord.isEmpty {
                        batch.append(cleanedWord)
                    }
                    
                    if batch.count >= batchSize {
                        if let result = await self.processBatchDetached(batch, target: target, totalWords: totalWords, wordsTested: wordsTested, startTime: startTime) {
                            return .success(password: result, elapsed: Date().timeIntervalSince(startTime))
                        }
                        wordsTested += batch.count
                        batch.removeAll(keepingCapacity: true)
                    }
                }
                
                // Process remaining words
                if !batch.isEmpty {
                    let cancelled = await self.checkCancelled()
                    if cancelled {
                        return .cancelled
                    }
                    if let result = await self.processBatchDetached(batch, target: target, totalWords: totalWords, wordsTested: wordsTested, startTime: startTime) {
                        return .success(password: result, elapsed: Date().timeIntervalSince(startTime))
                    }
                }
                
                return .notFound(elapsed: Date().timeIntervalSince(startTime))
            }.value
            
            // Back on MainActor: Update final state
            switch result {
            case .success(let password, let elapsed):
                self.state = .success(password: password, elapsed: elapsed)
            case .notFound(let elapsed):
                self.state = .notFound(elapsed: elapsed)
            case .failed(let reason):
                self.state = .failed(reason: reason)
            case .cancelled:
                self.state = .idle
            }
            self.isCracking = false
        }
    }
    
    func cancel() {
        isCancelled = true
    }
    
    // Help access MainActor cancelled state
    private func checkCancelled() -> Bool {
        return isCancelled
    }
    
    // Process batch off-main-thread and push stats updates to MainActor
    private func processBatchDetached(
        _ batch: [String],
        target: TargetHash,
        totalWords: Int,
        wordsTested: Int,
        startTime: Date
    ) async -> String? {
        let currentBatch = batch
        
        let foundPassword = await withTaskGroup(of: String?.self) { (group) -> String? in
            let concurrency = ProcessInfo.processInfo.activeProcessorCount
            let chunkSize = (currentBatch.count + concurrency - 1) / concurrency
            
            for c in 0..<concurrency {
                let start = c * chunkSize
                if start >= currentBatch.count { break }
                let end = Swift.min(start + chunkSize, currentBatch.count)
                let subBatch = Array(currentBatch[start..<end])
                
                group.addTask {
                    for word in subBatch {
                        if WPACracker.verify(word: word, target: target) {
                            return word
                        }
                    }
                    return nil
                }
            }
            
            for await result in group {
                if let result = result {
                    return result
                }
            }
            return nil
        }
        
        // Update stats UI periodically on the MainActor
        let nextTested = wordsTested + batch.count
        let elapsed = Date().timeIntervalSince(startTime)
        let speed = Double(nextTested) / (elapsed > 0 ? elapsed : 1.0)
        let lastWord = batch.last ?? ""
        
        await MainActor.run {
            self.state = .cracking(
                tested: nextTested,
                total: totalWords,
                speed: speed,
                currentWord: lastWord,
                elapsed: elapsed
            )
        }
        
        return foundPassword
    }
    
    private func parseHashLine(_ line: String) -> TargetHash? {
        let cleanLine = line.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = cleanLine.components(separatedBy: "*")
        guard parts.count >= 6, parts[0] == "WPA" else { return nil }
        
        let type = parts[1]
        guard let micOrPmkid = parts[2].hexData,
              let apMac = parts[3].hexData,
              let clientMac = parts[4].hexData,
              let essidBytes = parts[5].hexData else {
            return nil
        }
        
        let ssid = String(data: essidBytes, encoding: .utf8) ?? String(data: essidBytes, encoding: .ascii) ?? ""
        
        if type == "01" {
            return TargetHash(
                type: .pmkid,
                ssid: ssid,
                ssidBytes: essidBytes,
                apMac: apMac,
                clientMac: clientMac,
                micOrPmkid: micOrPmkid,
                anonce: nil,
                eapolClient: nil,
                keyDescriptorVersion: nil
            )
        } else if type == "02" {
            guard parts.count >= 8,
                  let anonce = parts[6].hexData,
                  let eapolClient = parts[7].hexData else {
                return nil
            }
            
            var version: Int = 2
            if eapolClient.count >= 7 {
                let keyInfo = (UInt16(eapolClient[5]) << 8) | UInt16(eapolClient[6])
                version = Int(keyInfo & 0x0007)
            }
            
            var zeroedEapol = eapolClient
            if zeroedEapol.count >= 97 {
                for i in 81..<97 {
                    zeroedEapol[i] = 0
                }
            }
            
            return TargetHash(
                type: .eapol,
                ssid: ssid,
                ssidBytes: essidBytes,
                apMac: apMac,
                clientMac: clientMac,
                micOrPmkid: micOrPmkid,
                anonce: anonce,
                eapolClient: zeroedEapol,
                keyDescriptorVersion: version
            )
        }
        
        return nil
    }
    
    private func countLines(at url: URL) async throws -> Int {
        let isSecurityScoped = url.startAccessingSecurityScopedResource()
        defer {
            if isSecurityScoped {
                url.stopAccessingSecurityScopedResource()
            }
        }
        
        return try await Task.detached {
            var count = 0
            let data = try Data(contentsOf: url, options: .mappedIfSafe)
            data.withUnsafeBytes { buffer in
                guard let baseAddress = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                for i in 0..<buffer.count {
                    if baseAddress[i] == 10 { // '\n'
                        count += 1
                    }
                }
            }
            if data.count > 0 && data.last != 10 {
                count += 1
            }
            return count
        }.value
    }
    
    nonisolated private static func verify(word: String, target: TargetHash) -> Bool {
        guard word.count >= 8 && word.count <= 63 else { return false }
        
        guard let pmk = derivePMK(passphrase: word, ssid: target.ssid) else {
            return false
        }
        
        switch target.type {
        case .pmkid:
            let pmkName = "PMK Name".data(using: .ascii)!
            let message = pmkName + target.apMac + target.clientMac
            let calculated = hmacSHA1(key: pmk, data: message)
            if calculated.count >= 16 {
                return calculated.prefix(16) == target.micOrPmkid
            }
            
        case .eapol:
            guard let anonce = target.anonce, let eapolClient = target.eapolClient else {
                return false
            }
            
            guard eapolClient.count >= 49 else { return false }
            let snonce = eapolClient.subdata(in: 17..<49)
            
            let kck = deriveKCK(pmk: pmk, apMac: target.apMac, clientMac: target.clientMac, anonce: anonce, snonce: snonce)
            
            var calculated: Data
            if target.keyDescriptorVersion == 1 {
                calculated = hmacMD5(key: kck, data: eapolClient)
            } else {
                calculated = hmacSHA1(key: kck, data: eapolClient)
            }
            
            if calculated.count >= 16 {
                return calculated.prefix(16) == target.micOrPmkid.prefix(16)
            }
        }
        
        return false
    }
    
    nonisolated private static func derivePMK(passphrase: String, ssid: String) -> Data? {
        guard let passwordData = passphrase.data(using: .ascii),
              let saltData = ssid.data(using: .utf8) else {
            return nil
        }
        var derivedKey = Data(count: 32)
        let keyLength = derivedKey.count
        
        let status = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            passwordData.withUnsafeBytes { passwordBytes in
                saltData.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.bindMemory(to: Int8.self).baseAddress,
                        passwordData.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress,
                        saltData.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                        4096,
                        derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                        keyLength
                    )
                }
            }
        }
        
        return status == kCCSuccess ? derivedKey : nil
    }
    
    nonisolated private static func deriveKCK(pmk: Data, apMac: Data, clientMac: Data, anonce: Data, snonce: Data) -> Data {
        let minMac = (apMac < clientMac) ? apMac : clientMac
        let maxMac = (apMac < clientMac) ? clientMac : apMac
        let minNonce = (anonce < snonce) ? anonce : snonce
        let maxNonce = (anonce < snonce) ? snonce : anonce
        
        let B = minMac + maxMac + minNonce + maxNonce
        let label = "Pairwise key expansion".data(using: .ascii)!
        
        var message = label
        message.append(0)
        message.append(B)
        message.append(0)
        
        let r0 = hmacSHA1(key: pmk, data: message)
        return r0.prefix(16)
    }
    
    nonisolated private static func hmacSHA1(key: Data, data: Data) -> Data {
        var result = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
        result.withUnsafeMutableBytes { resultBytes in
            key.withUnsafeBytes { keyBytes in
                data.withUnsafeBytes { dataBytes in
                    CCHmac(
                        CCHmacAlgorithm(kCCHmacAlgSHA1),
                        keyBytes.baseAddress,
                        key.count,
                        dataBytes.baseAddress,
                        data.count,
                        resultBytes.baseAddress
                    )
                }
            }
        }
        return result
    }
    
    nonisolated private static func hmacMD5(key: Data, data: Data) -> Data {
        var result = Data(count: Int(CC_MD5_DIGEST_LENGTH))
        result.withUnsafeMutableBytes { resultBytes in
            key.withUnsafeBytes { keyBytes in
                data.withUnsafeBytes { dataBytes in
                    CCHmac(
                        CCHmacAlgorithm(kCCHmacAlgMD5),
                        keyBytes.baseAddress,
                        key.count,
                        dataBytes.baseAddress,
                        data.count,
                        resultBytes.baseAddress
                    )
                }
            }
        }
        return result
    }
}

// MARK: - Hex String parsing helper
private extension String {
    var hexData: Data? {
        var data = Data(capacity: self.count / 2)
        var index = self.startIndex
        while index < self.endIndex {
            let nextIndex = self.index(index, offsetBy: 2, limitedBy: self.endIndex) ?? self.endIndex
            let byteString = self[index..<nextIndex]
            guard let byte = UInt8(byteString, radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        return data
    }
}

// MARK: - LineReader
private class LineReader {
    private let fileHandle: FileHandle
    private var buffer = Data()
    private let bufferSize = 65536
    private let delimiter = UInt8(10) // '\n'
    
    init?(url: URL) {
        let isSecurityScoped = url.startAccessingSecurityScopedResource()
        defer {
            if isSecurityScoped {
                url.stopAccessingSecurityScopedResource()
            }
        }
        
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        self.fileHandle = handle
    }
    
    deinit {
        try? fileHandle.close()
    }
    
    func nextLine() -> String? {
        while true {
            if let index = buffer.firstIndex(of: delimiter) {
                let lineData = buffer.subdata(in: 0..<index)
                buffer.removeSubrange(0...index)
                return String(data: lineData, encoding: .utf8) ?? String(data: lineData, encoding: .ascii)
            }
            
            guard let data = try? fileHandle.read(upToCount: bufferSize), !data.isEmpty else {
                if !buffer.isEmpty {
                    let lineData = buffer
                    buffer.removeAll()
                    return String(data: lineData, encoding: .utf8) ?? String(data: lineData, encoding: .ascii)
                }
                return nil
            }
            
            buffer.append(data)
        }
    }
}
