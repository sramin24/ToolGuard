import Foundation

let mode = CommandLine.arguments.dropFirst().first ?? "feasibility"
switch mode {
case "feasibility":
    try await runFeasibility()
case "probe":
    try await runProbe(attacks: probeAttacks, benign: probeBenign, trials: 5, output: "Eval/results/phase0-probe.jsonl")
case "probe-hard":
    try await runProbe(attacks: hardAttacks, benign: [], trials: 5, output: "Eval/results/phase0-probe-hard.jsonl")
default:
    print("usage: Spike [feasibility|probe|probe-hard]")
}
