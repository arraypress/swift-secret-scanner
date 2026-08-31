//
//  Entropy.swift
//  SecretScanner
//
//  Created by David Sherlock on 2026.
//
//  Shannon entropy — the generic rules' test of whether a value
//  looks random enough to be a credential at all.
//

import Foundation

/// Shannon entropy — the generic rules' test of whether a value looks random.
public enum Entropy {
    /// Shannon entropy in bits per character. Random tokens run above 4;
    /// English words and repeated characters run below 3.
    public static func bits(_ text: String) -> Double {
        guard !text.isEmpty else { return 0 }
        var counts: [Character: Int] = [:]
        for c in text { counts[c, default: 0] += 1 }
        let n = Double(text.count)
        return counts.values.reduce(0.0) { acc, count in
            let p = Double(count) / n
            return acc - p * log2(p)
        }
    }
}
