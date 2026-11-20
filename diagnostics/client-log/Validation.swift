import Foundation

// Look at the same first four tokens as the public formatter. A standalone
// level, or a token after an earlier recognized priority, is not a verbose record.
func originalAppend(_ incoming: [String], to log: inout [String], limit: Int = 5000) {
    precondition(limit > 0)
    log.append(contentsOf: incoming)
    guard log.count > limit else { return }
    var excess = log.count - limit
    log = log.filter { line in
        guard excess > 0 else { return true }
        let level = splitLogLine(line).level
        if level == "TRACE" || level == "DEBUG" {
            excess -= 1
            return false
        }
        return true
    }
    // Important records are bounded too; once no verbose lines can be removed,
    // retain the latest important records rather than grow without limit.
    if excess > 0 { log.removeFirst(excess) }
}

func splitLogLine(_ line: String) -> (level: String, message: String) {
    let fields = line.split(separator: " ", maxSplits: 5, omittingEmptySubsequences: true)
    let levels = ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"]
    guard let at = fields.prefix(4).firstIndex(where: { levels.contains(String($0)) }), at < fields.count - 1 else {
        return ("", line)
    }
    return (String(fields[at]), fields[(at + 1)...].joined(separator: " ").trimmingCharacters(in: .whitespaces))
}

@main struct Study {
    static func newLine(_ kind: String, _ i: Int) -> String {
        switch kind {
        case "important": return "2026-11-20T00:00:00Z INFO relay: completed flow id=\(i)"
        case "verbose": return "2026-11-20T00:00:00Z DEBUG relay: transport metadata id=\(i)"
        default:
            let lines=["body without level", "2026-11-20 UTC source TRACE sample   id=", " INFO  DEBUG message ",
                       "WARNING INFO plain", "DEBUG", "X Y Z TRACE ", "X Y Z TRACE record", "DEBUG\tvalue",
                       "text info DEBUG detail", "WARN relay:", " TRACE payload ", " leading WARN reason"]
            return lines[i % lines.count] + (i%4==0 ? "" : " \(i)")
        }
    }
    static func run(_ variant: String, _ batches: [[String]], _ limit: Int) -> (UInt64,UInt64) {
        var old:[String]=[]
        
        var checksum:UInt64=1469598103934665603
        let start=DispatchTime.now().uptimeNanoseconds
        for batch in batches {
            let result: [String]
            if variant == "original" {originalAppend(batch,to:&old,limit:limit)}
            else {appendClientLog(batch,to:&old,limit:limit)}
            result=old
            // Model the published array and observable ordering after every batch.
            for index in [0,result.count/2,max(0,result.count-1)] where index < result.count {
                for byte in result[index].utf8 {checksum = (checksum ^ UInt64(byte)) &* 1099511628211}
            }
            checksum ^= UInt64(result.count)
        }
        return (DispatchTime.now().uptimeNanoseconds-start,checksum)
    }
    static func main() {
        let kinds=["original","selected"]
        let tokens=["", " ", "  ", "X", " UTC ", " WARN", "INFO ", "DEBUG ", " TRACE ", "ERROR ",
                    "\t", "\u{a0}", "\u{301}", "\u{1f680}", " long-message-here "]
        var seed: UInt64 = 127
        func word() -> String {
            seed = seed &* 6364136223846793005 &+ 1442695040888963407
            return tokens[Int((seed >> 32) % UInt64(tokens.count))]
        }
        var all:[String] = []
        for i in 0..<9000 {
            let line=(0..<(1+i%18)).map{_ in word()}.joined()
            let expected=["ERROR","WARN","INFO","DEBUG","TRACE"].firstIndex(of:splitLogLine(line).level) ?? 0
            for setting in LogLevel.allCases {precondition(setting.shows(line) == (Int(setting.nativeValue) >= expected))}
            all.append(line)
        }
        for limit in [1,2,4,31,256,5000] {
            var ref:[String]=[]; var actual:[String]=[]
            for i in stride(from:0,to:all.count,by:51) {
                let batch=Array(all[i..<min(all.count,i+51)])
                originalAppend(batch,to:&ref,limit:limit); appendClientLog(batch,to:&actual,limit:limit)
                precondition(ref==actual)
            }
        }
        for shape in ["underfull","important","verbose","mixed"] {
            for batched in [1,16] {
                let backlog=(0..<(shape=="underfull" ? 40 : 5000)).map{newLine(shape,$0)}
                let updates=(0..<32).map{n in (0..<batched).map{newLine(shape,5000+n*batched+$0)}}
                let input=[backlog]+updates
                var expected: UInt64?
                for round in 0..<6 {
                    for i in 0..<2 {
                        let variant=kinds[(i+round)%2]
                        let (ns,check)=run(variant,input,5000)
                        if let expected {precondition(expected==check)} else {expected=check}
                        print("LOG \(shape) \(batched) \(round) \(variant) \(ns)")
                    }
                }
            }
        }
    }
}
