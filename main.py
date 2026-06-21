from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from random import Random
from statistics import mean

SIGNUP_BONUS = 25
NORMAL_ACCOUNT_COUNT = 50_000
FRAUD_RING_COUNT = 2
FRAUD_RING_SIZE = 5
HIGH_RISK_THRESHOLD = 70


@dataclass(frozen=True)
class Account:
    """
    Represents a user account in the referral bonus program.
    The attributes are relevant for fraud detection.
    """

    account_id: str
    created_at: datetime
    ip_address: str
    device_id: str
    payout_account: str
    email: str
    phone: str
    referred_by: str | None
    bonus_awarded: bool
    bonus_amount: int
    cashout_at: datetime | None
    cashout_amount: int
    label: str
    ring_id: str | None = None


@dataclass(frozen=True)
class ClusterSummary:
    """
    Represents a cluster of related accounts.
    """

    cluster_id: str
    members: list[str]
    score_mean: float
    fraud_labels: int
    suspicious_signals: list[str]
    payout_accounts: list[str]
    device_ids: list[str]


@dataclass(frozen=True)
class DemoResults:
    """
    Represents the results of the referral bonus abuse demo.
    """

    accounts: list[Account]
    scores: dict[str, int]
    reasons: dict[str, list[str]]
    clusters: list[ClusterSummary]


def build_synthetic_accounts(seed: int = 7) -> list[Account]:
    """
    Generates a synthetic dataset of accounts with a mix of legitimate and fraudulent behaviors.

    Returns a list of Account objects sorted by creation time.
    """
    rng = Random(seed)
    base_time = datetime(2026, 4, 1, 8, 0, 0)
    accounts: list[Account] = []

    for index in range(NORMAL_ACCOUNT_COUNT):
        created_at = base_time + timedelta(minutes=index * 3 + rng.randint(0, 8))
        account_id = f"acct_{index:05d}"
        ip_address = (
            f"10.{rng.randint(0, 15)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}"
        )
        device_id = f"device_{index:05d}"
        payout_account = f"bank_{index:05d}"
        email = f"customer{index}@example.com"
        phone = f"555-{20_000 + index:05d}-{rng.randint(10, 99):02d}"
        has_bonus = rng.random() < 0.42
        bonus_amount = SIGNUP_BONUS if has_bonus else 0
        referred_by = None
        if has_bonus and index > 50 and rng.random() < 0.3:
            referred_by = f"acct_{rng.randint(max(0, index - 500), index - 1):05d}"

        cashout_at = None
        cashout_amount = 0
        if has_bonus and rng.random() < 0.15:
            cashout_at = created_at + timedelta(
                days=rng.randint(3, 45), hours=rng.randint(0, 18)
            )
            cashout_amount = rng.randint(20, 110)

        accounts.append(
            Account(
                account_id=account_id,
                created_at=created_at,
                ip_address=ip_address,
                device_id=device_id,
                payout_account=payout_account,
                email=email,
                phone=phone,
                referred_by=referred_by,
                bonus_awarded=has_bonus,
                bonus_amount=bonus_amount,
                cashout_at=cashout_at,
                cashout_amount=cashout_amount,
                label="legit",
            )
        )

    for ring_index in range(FRAUD_RING_COUNT):
        ring_tag = f"ring_{ring_index + 1}"
        ring_start = base_time + timedelta(
            days=25 + ring_index, minutes=ring_index * 11
        )
        shared_subnet = f"172.16.{40 + ring_index}"
        shared_payout = f"mule_{ring_index + 1:02d}"
        primary_device = f"shared_device_{ring_index + 1:02d}"

        for member_index in range(FRAUD_RING_SIZE):
            created_at = ring_start + timedelta(minutes=member_index * 4)
            account_id = f"fraud_{ring_index + 1}_{member_index + 1}"
            ip_address = f"{shared_subnet}.{50 + member_index}"
            device_id = (
                primary_device if member_index < 4 else f"{primary_device}_backup"
            )
            payout_account = shared_payout
            email = f"promo.hunter.{ring_index + 1}.{member_index + 1}@maildrop.test"
            phone = f"555-99{ring_index + 1:02d}-{1100 + member_index}"
            referred_by = (
                None if member_index == 0 else f"fraud_{ring_index + 1}_{member_index}"
            )
            cashout_at = created_at + timedelta(hours=2 + member_index)

            accounts.append(
                Account(
                    account_id=account_id,
                    created_at=created_at,
                    ip_address=ip_address,
                    device_id=device_id,
                    payout_account=payout_account,
                    email=email,
                    phone=phone,
                    referred_by=referred_by,
                    bonus_awarded=True,
                    bonus_amount=SIGNUP_BONUS,
                    cashout_at=cashout_at,
                    cashout_amount=25 + rng.randint(0, 20),
                    label="fraud",
                    ring_id=ring_tag,
                )
            )

    return sorted(accounts, key=lambda account: account.created_at)


def subnet(ip_address: str) -> str:
    return ".".join(ip_address.split(".")[:3])


def phone_stem(phone: str) -> str:
    return phone.rsplit("-", maxsplit=1)[0]


def email_stem(email: str) -> str:
    local_part = email.split("@", maxsplit=1)[0]
    segments = local_part.split(".")
    return ".".join(segments[:-1]) if len(segments) > 1 else local_part


def count_recent_signups(accounts: list[Account]) -> dict[str, int]:
    recent_counts: dict[str, int] = {}
    grouped = defaultdict(list)
    for account in accounts:
        grouped[subnet(account.ip_address)].append(account)

    for subnet_key, members in grouped.items():
        window: deque[Account] = deque()
        for account in sorted(members, key=lambda item: item.created_at):
            while window and account.created_at - window[0].created_at > timedelta(
                minutes=30
            ):
                window.popleft()
            window.append(account)
            recent_counts[account.account_id] = len(window)

    return recent_counts


def build_risk_features(
    accounts: list[Account],
) -> tuple[dict[str, int], dict[str, list[str]]]:
    """
    Generates risk scores and reason codes for each account based on various signals.

    The scoring is based on the presence of shared attributes which all contribute to the overall risk score.

    Parameters:
    - accounts: List of Account objects to analyze

    Returns a tuple containing:
    - A dictionary mapping account_id to computed risk score (0-100)
    - A dictionary mapping account_id to a list of reason codes that contributed to the risk score
    """
    device_counts = Counter(account.device_id for account in accounts)
    payout_counts = Counter(account.payout_account for account in accounts)
    phone_counts = Counter(phone_stem(account.phone) for account in accounts)
    email_counts = Counter(email_stem(account.email) for account in accounts)
    referral_children = Counter(
        account.referred_by for account in accounts if account.referred_by
    )
    recent_signups = count_recent_signups(accounts)

    scores: dict[str, int] = {}
    reasons: dict[str, list[str]] = {}

    for account in accounts:
        score = 0
        reason_codes: list[str] = []

        if device_counts[account.device_id] >= 3:
            score += 30
            reason_codes.append(f"shared_device:{device_counts[account.device_id]}")

        if payout_counts[account.payout_account] >= 2:
            score += 35
            reason_codes.append(
                f"shared_payout:{payout_counts[account.payout_account]}"
            )

        if recent_signups[account.account_id] >= 4:
            score += 20
            reason_codes.append(
                f"burst_signups:{recent_signups[account.account_id]}_in_30m"
            )

        if account.referred_by and referral_children[account.referred_by] >= 2:
            score += 10
            reason_codes.append("referrer_fanout")

        if account.referred_by and account.referred_by.startswith("fraud_"):
            score += 10
            reason_codes.append("internal_referral_chain")

        if phone_counts[phone_stem(account.phone)] >= 3:
            score += 10
            reason_codes.append(
                f"phone_pattern:{phone_counts[phone_stem(account.phone)]}"
            )

        if email_counts[email_stem(account.email)] >= 3:
            score += 10
            reason_codes.append(
                f"email_pattern:{email_counts[email_stem(account.email)]}"
            )

        if account.cashout_at and account.bonus_awarded:
            hours_to_cashout = (
                account.cashout_at - account.created_at
            ).total_seconds() / 3600
            if hours_to_cashout <= 24:
                score += 25
                reason_codes.append(f"cashout_lt_24h:{hours_to_cashout:.1f}h")

        if account.bonus_awarded:
            score += 5
            reason_codes.append("bonus_collected")

        scores[account.account_id] = score
        reasons[account.account_id] = reason_codes

    return scores, reasons


def build_relationship_graph(accounts: list[Account]) -> dict[str, set[str]]:
    """
    Generates a graph where each account is a node and edges represent shared attributes that may indicate a relationship.

    Parameters:
    - accounts: List of Account objects to analyze

    Returns a dictionary mapping account_id to a set of related account_ids based on shared signals.
    """
    graph = {account.account_id: set() for account in accounts}
    by_device = defaultdict(list)
    by_payout = defaultdict(list)
    by_subnet = defaultdict(list)
    by_referrer = defaultdict(list)

    for account in accounts:
        by_device[account.device_id].append(account.account_id)
        by_payout[account.payout_account].append(account.account_id)
        by_subnet[subnet(account.ip_address)].append(account.account_id)
        if account.referred_by:
            by_referrer[account.referred_by].append(account.account_id)

    for group in (
        list(by_device.values())
        + list(by_payout.values())
        + list(by_subnet.values())
        + list(by_referrer.values())
    ):
        if len(group) < 2:
            continue
        for account_id in group:
            graph[account_id].update(other for other in group if other != account_id)

    return graph


def cluster_accounts(
    accounts: list[Account], scores: dict[str, int], reasons: dict[str, list[str]]
) -> list[ClusterSummary]:
    """
    Generates clusters of related accounts based on shared attributes and computes summary statistics for each cluster.

    The clustering is done using a breadth-first search (BFS) on the relationship graph.
    Each cluster is summarized with its mean risk score, number of known fraud labels, and common signals.

    Parameters:
    - accounts: List of Account objects to cluster
    - scores: Dictionary mapping account_id to risk score
    - reasons: Dictionary mapping account_id to list of reason codes for risk score

    Returns a list of ClusterSummary objects sorted by mean risk score and cluster size.
    """
    account_lookup = {account.account_id: account for account in accounts}
    graph = build_relationship_graph(accounts)
    visited: set[str] = set()
    clusters: list[ClusterSummary] = []

    for account_id in graph:
        if account_id in visited:
            continue

        queue = deque([account_id])
        members: list[str] = []
        visited.add(account_id)

        while queue:
            current = queue.popleft()
            members.append(current)
            for neighbor in graph[current]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

        if len(members) == 1:
            continue

        payouts = sorted({account_lookup[member].payout_account for member in members})
        devices = sorted({account_lookup[member].device_id for member in members})
        signals = sorted(
            {
                reason.split(":", maxsplit=1)[0]
                for member in members
                for reason in reasons[member]
            }
        )
        fraud_labels = sum(
            1 for member in members if account_lookup[member].label == "fraud"
        )

        clusters.append(
            ClusterSummary(
                cluster_id=f"cluster_{len(clusters) + 1:03d}",
                members=sorted(members),
                score_mean=mean(scores[member] for member in members),
                fraud_labels=fraud_labels,
                suspicious_signals=signals,
                payout_accounts=payouts,
                device_ids=devices,
            )
        )

    clusters.sort(
        key=lambda cluster: (cluster.score_mean, len(cluster.members)), reverse=True
    )
    return clusters


def detection_metrics(
    accounts: list[Account], scores: dict[str, int]
) -> dict[str, int]:
    """
    Computes detection metrics (TP, FP, TN, FN) based on the predicted scores and actual labels.

    TP: True Positives - accounts correctly identified as fraud
    FP: False Positives - accounts incorrectly identified as fraud
    TN: True Negatives - accounts correctly identified as legit
    FN: False Negatives - accounts incorrectly identified as legit

    Parameters:
    - accounts: List of Account objects with actual labels
    - scores: Dictionary mapping account_id to predicted risk score

    Returns a dictionary with the counts of each metric.
    """
    tp = fp = tn = fn = 0
    for account in accounts:
        predicted_fraud = scores[account.account_id] >= HIGH_RISK_THRESHOLD
        is_fraud = account.label == "fraud"
        if predicted_fraud and is_fraud:
            tp += 1
        elif predicted_fraud and not is_fraud:
            fp += 1
        elif not predicted_fraud and is_fraud:
            fn += 1
        else:
            tn += 1

    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def top_suspicious_accounts(
    accounts: list[Account], scores: dict[str, int], limit: int = 12
) -> list[Account]:
    return sorted(
        accounts, key=lambda account: scores[account.account_id], reverse=True
    )[:limit]


def flagged_clusters(
    clusters: list[ClusterSummary], threshold: int = HIGH_RISK_THRESHOLD, limit: int = 5
) -> list[ClusterSummary]:
    return [cluster for cluster in clusters if cluster.score_mean >= threshold][:limit]


def run_demo(seed: int = 7) -> DemoResults:
    accounts = build_synthetic_accounts(seed=seed)
    scores, reasons = build_risk_features(accounts)
    clusters = cluster_accounts(accounts, scores, reasons)
    return DemoResults(
        accounts=accounts, scores=scores, reasons=reasons, clusters=clusters
    )


def print_summary(
    accounts: list[Account],
    scores: dict[str, int],
    reasons: dict[str, list[str]],
    clusters: list[ClusterSummary],
) -> None:
    metrics = detection_metrics(accounts, scores)
    top_accounts = top_suspicious_accounts(accounts, scores)
    high_risk_clusters = flagged_clusters(clusters)

    print("Referral Bonus Abuse Demo")
    print("=" * 80)
    print(f"Accounts simulated: {len(accounts):,}")
    print(
        f"Known fraud accounts: {sum(account.label == 'fraud' for account in accounts)}"
    )
    print(f"High-risk threshold: {HIGH_RISK_THRESHOLD}")
    print()

    print("Detection snapshot")
    print("-" * 80)
    print(
        " ".join(
            [
                f"TP={metrics['tp']}",
                f"FP={metrics['fp']}",
                f"TN={metrics['tn']}",
                f"FN={metrics['fn']}",
            ]
        )
    )
    print()

    print("Top suspicious accounts")
    print("-" * 80)
    for account in top_accounts:
        risk_band = (
            "HIGH" if scores[account.account_id] >= HIGH_RISK_THRESHOLD else "REVIEW"
        )
        print(
            f"{account.account_id:12} score={scores[account.account_id]:3} label={account.label:5} "
            f"band={risk_band:6} payout={account.payout_account:10} device={account.device_id:20}"
        )
        print(f"  reasons: {', '.join(reasons[account.account_id])}")
    print()

    print("Suspicious clusters")
    print("-" * 80)
    if not high_risk_clusters:
        print("No clusters exceeded the high-risk threshold.")
    for cluster in high_risk_clusters:
        print(
            f"{cluster.cluster_id} members={len(cluster.members)} mean_score={cluster.score_mean:.1f} "
            f"known_fraud={cluster.fraud_labels}"
        )
        print(f"  signals: {', '.join(cluster.suspicious_signals)}")
        print(f"  payouts: {', '.join(cluster.payout_accounts[:3])}")
        print(f"  devices: {', '.join(cluster.device_ids[:3])}")
        print(f"  sample_members: {', '.join(cluster.members[:5])}")


def main() -> None:
    results = run_demo()
    print_summary(results.accounts, results.scores, results.reasons, results.clusters)


if __name__ == "__main__":
    main()
