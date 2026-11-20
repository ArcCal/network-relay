import Foundation

// Look at the same first four tokens as the public formatter. A standalone
// level, or a token after an earlier recognized priority, is not a verbose record.
func levelOnly(_ line: String) -> Bool {
    var fields = line.split(separator: " ", maxSplits: 5, omittingEmptySubsequences: true).makeIterator()
    for _ in 0..<4 {
        guard let field = fields.next() else { break }
        switch field {
        case "ERROR", "WARN", "INFO": return false
        case "DEBUG", "TRACE": return fields.next() != nil
        default: continue
        }
    }
    return false
}

func levelFilter(_ input: [String], _ log: inout [String], _ limit: Int) {
    log.append(contentsOf: input)
    var excess = log.count-limit
    guard excess>0 else {return}
    log = log.filter { line in
        if excess>0 && levelOnly(line) {excess-=1; return false}
        return true
    }
    if excess>0 {log.removeFirst(excess)}
}

func inplace(_ input: [String], _ log: inout [String], _ limit: Int) {
    log.append(contentsOf: input)
    var excess=log.count-limit
    guard excess>0 else {return}
    log.removeAll { line in
        guard excess>0 else {return false}
        let level=splitLogLine(line).level
        if level=="DEBUG" || level=="TRACE" {excess-=1; return true}
        return false
    }
    if excess>0 {log.removeFirst(excess)}
}

struct OrderedPriorityLog {
    struct Entry {
        var text: String
        var next: Int?
        var previous: Int?
        var nextVerbose: Int?
    }
    let limit: Int
    private var entries: [Entry] = []
    private var first: Int?
    private var last: Int?
    private var firstVerbose: Int?
    private var lastVerbose: Int?

    init(limit: Int) {precondition(limit>0); self.limit=limit}
    mutating func append(_ lines: [String]) {
        for line in lines {
            let verbose=levelOnly(line)
            let slot: Int
            if entries.count == limit {
                if let oldest=firstVerbose {
                    slot=oldest; firstVerbose=entries[slot].nextVerbose
                    if firstVerbose == nil {lastVerbose=nil}
                } else {
                    if verbose {continue}
                    slot=first!
                }
                let before=entries[slot].previous; let after=entries[slot].next
                if let before {entries[before].next=after} else {first=after}
                if let after {entries[after].previous=before} else {last=before}
                entries[slot]=Entry(text:line,next:nil,previous:last,nextVerbose:nil)
            } else {
                slot=entries.count; entries.append(Entry(text:line,next:nil,previous:last,nextVerbose:nil))
            }
            if let tail=last {entries[tail].next=slot} else {first=slot}
            last=slot
            if verbose {
                if let tail=lastVerbose {entries[tail].nextVerbose=slot} else {firstVerbose=slot}
                lastVerbose=slot
            }
        }
    }
    func snapshot() -> [String] {
        var lines:[String]=[]; lines.reserveCapacity(entries.count)
        var cursor=first
        while let i=cursor {lines.append(entries[i].text); cursor=entries[i].next}
        return lines
    }
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
        var queue=OrderedPriorityLog(limit:limit)
        var checksum:UInt64=1469598103934665603
        let start=DispatchTime.now().uptimeNanoseconds
        for batch in batches {
            let result: [String]
            switch variant {
            case "original": appendClientLog(batch,to:&old,limit:limit); result=old
            case "level": levelFilter(batch,&old,limit); result=old
            case "inplace": inplace(batch,&old,limit); result=old
            case "indexed": queue.append(batch); result=queue.snapshot()
            default: preconditionFailure()
            }
            // Model the published array and observable ordering after every batch.
            for index in [0,result.count/2,max(0,result.count-1)] where index < result.count {
                for byte in result[index].utf8 {checksum = (checksum ^ UInt64(byte)) &* 1099511628211}
            }
            checksum ^= UInt64(result.count)
        }
        return (DispatchTime.now().uptimeNanoseconds-start,checksum)
    }
    static func main() {
        let kinds=["original","level","inplace","indexed"]
        for limit in [1,2,4,15,31] {
            var old:[String]=[]; var l:[String]=[]; var ip:[String]=[];var queue=OrderedPriorityLog(limit:limit)
            for i in 0..<240 {
                let batch=(0..<(i*7%37)).map {newLine("mixed",i*47+$0)}
                appendClientLog(batch,to:&old,limit:limit); levelFilter(batch,&l,limit)
                inplace(batch,&ip,limit);queue.append(batch)
                precondition(old==l && old==ip && old==queue.snapshot())
            }
        }
        for shape in ["important","verbose","mixed"] {
            for batched in [1,16] {
                let backlog=(0..<5000).map{newLine(shape,$0)}
                let updates=(0..<32).map{n in (0..<batched).map{newLine(shape,5000+n*batched+$0)}}
                let input=[backlog]+updates
                var expected: UInt64?
                for round in 0..<4 {
                    for i in 0..<4 {
                        let variant=kinds[((round%2==0 ? i : 3-i)+round/2)%4]
                        let (ns,check)=run(variant,input,5000)
                        if let expected {precondition(expected==check)} else {expected=check}
                        print("LOG \(shape) \(batched) \(round) \(variant) \(ns)")
                    }
                }
            }
        }
    }
}
