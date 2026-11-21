import csv

from analyzer import analyze

N_BENIGN = 300
THRESHOLDS = [1, 15, 20, 30, 40, 50]
REPORT_THRESHOLD = 30   # 用这个报警线来列出误报和漏报


def load_phishing(path):
    urls = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                urls.append(line)
    return urls


def load_benign(path, n):
    urls = []
    with open(path) as f:
        for rank, domain in csv.reader(f):
            urls.append("https://" + domain)
            if len(urls) == n:
                break
    return urls


def confusion(phishing_scores, benign_scores, threshold):
    tp = sum(1 for s in phishing_scores if s >= threshold)
    fn = len(phishing_scores) - tp
    fp = sum(1 for s in benign_scores if s >= threshold)
    tn = len(benign_scores) - fp
    return tp, fn, fp, tn


def main():
    phishing = load_phishing("data/openphish.txt")
    benign = load_benign("data/top-1m.csv", N_BENIGN) + load_phishing("data/benign_free_hosting.txt")

    phishing_scores = [analyze(u)["risk_score"] for u in phishing]
    benign_scores = [analyze(u)["risk_score"] for u in benign]

    print(f"Phishing: {len(phishing)}   Benign: {len(benign)}\n")
    print("Threshold    TP    FN    FP    TN   Precision   Recall")
    for t in THRESHOLDS:
        tp, fn, fp, tn = confusion(phishing_scores, benign_scores, t)
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        print(f"{t:>9} {tp:>5} {fn:>5} {fp:>5} {tn:>5} {precision:>11.1%} {recall:>8.1%}")

    missed = [u for u, s in zip(phishing, phishing_scores) if s < REPORT_THRESHOLD]
    false_alarms = [u for u, s in zip(benign, benign_scores) if s >= REPORT_THRESHOLD]

    print(f"\nAt threshold {REPORT_THRESHOLD}:")
    print("False alarms:")
    for url in false_alarms:
        print("  ", url)

    with open("data/missed.txt", "w") as f:
        for url in missed:
            f.write(url + "\n")
    print(f"{len(missed)} missed URLs written to data/missed.txt")


main()