import csv

from analyzer import analyze

THRESHOLD = 1   # 分数 >= 这个值就算"程序报警"
N_BENIGN = 300


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


def main():
    phishing = load_phishing("data/openphish.txt")
    benign = load_benign("data/top-1m.csv", N_BENIGN)

    tp = fn = fp = tn = 0
    missed = []
    false_alarms = []

    for url in phishing:
        flagged = analyze(url)["risk_score"] >= THRESHOLD
        if flagged:
            tp += 1
        else:
            fn += 1
            missed.append(url)

    for url in benign:
        flagged = analyze(url)["risk_score"] >= THRESHOLD
        if flagged:
            fp += 1
            false_alarms.append(url)
        else:
            tn += 1

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0

    print(f"Phishing: {len(phishing)}   Benign: {len(benign)}")
    print(f"TP={tp}  FN={fn}  FP={fp}  TN={tn}")
    print(f"Precision: {precision:.1%}")
    print(f"Recall:    {recall:.1%}")
    print("\nFalse alarms:")
    for url in false_alarms:
        print("  ", url)
    print("\nMissed (first 15):")
    for url in missed[:15]:
        print("  ", url)


main()