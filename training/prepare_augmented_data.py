"""
Prepare augmented training data for AURA unified safety model v3.

Combines:
1. KoalaAI (1.46M) - base multilingual toxicity/safety dataset
2. Synthetic grooming examples from AURA kids lexicon (template-based)
3. Kids synthetic data (multi-turn grooming, bullying, manipulation, self-harm, negatives)
4. Suicide/self-harm data (vibhorag101 232K)
5. Mental health data (AIMH/SWMH 54K)
6. Multilingual toxicity (textdetox 71K, has UK+RU)
7. Cyberbullying (AnikaBasu 3K, Instagram/TikTok 538)
8. Offensive + grooming (Brandon-h 30K, has Spanish grooming labels)
9. Youth self-harm benchmark (apgard 90)

Outputs a single parquet file with unified schema:
  prompt, S, S3, SH, HR, H, V, V2, H2

Changes from v2:
  - Dropped sentiment labels (model is now pure 8-label safety)
  - Added kids-specific synthetic data with multi-stage grooming
  - Added cyberbullying datasets
  - Added negative controls (benign teen conversations)
  - Increased grooming oversample from 5x to 8x
"""

import json
import random
import os
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "raw" / "hf"
SYNTHETIC_DIR = PROJECT_ROOT / "training" / "synthetic"
OUTPUT_DIR = PROJECT_ROOT / "training" / "augmented"
LABELS = ["S", "S3", "SH", "HR", "H", "V", "V2", "H2"]

random.seed(42)


def load_koalai():
    """Load original KoalaAI dataset."""
    path = DATA_DIR / "KoalaAI_Text-Moderation-Multilingual" / "train.parquet"
    print(f"Loading KoalaAI from {path}...")
    table = pq.read_table(path)
    texts = table.column("prompt").to_pylist()
    labels = {}
    for col in LABELS:
        labels[col] = [int(v or 0) for v in table.column(col).to_pylist()]
    print(f"  {len(texts)} samples")
    return texts, labels


def generate_grooming_synthetic():
    """Generate synthetic grooming examples from AURA kids lexicon."""
    lexicon_path = PROJECT_ROOT / "crates" / "aura-kids" / "data" / "lexicon.json"
    print(f"Generating grooming synthetic from {lexicon_path}...")

    with open(lexicon_path, "r", encoding="utf-8") as f:
        lex = json.load(f)

    grooming_phrases = []
    for rule in lex.get("grooming", []):
        for phrase in rule.get("any_of", []):
            grooming_phrases.append(phrase)
        for group in rule.get("any_groups", []):
            for phrase in group:
                grooming_phrases.append(phrase)

    manipulation_phrases = []
    for rule in lex.get("manipulation", []):
        for phrase in rule.get("any_of", []):
            manipulation_phrases.append(phrase)
        for group in rule.get("any_groups", []):
            for phrase in group:
                manipulation_phrases.append(phrase)

    selfharm_phrases = []
    for rule in lex.get("selfharm", []):
        for phrase in rule.get("any_of", []):
            selfharm_phrases.append(phrase)
        for group in rule.get("any_groups", []):
            for phrase in group:
                selfharm_phrases.append(phrase)

    bullying_phrases = []
    for rule in lex.get("bullying", []):
        for phrase in rule.get("any_of", []):
            bullying_phrases.append(phrase)
        for group in rule.get("any_groups", []):
            for phrase in group:
                bullying_phrases.append(phrase)

    grooming_templates = [
        "{phrase}",
        "Hey, {phrase}",
        "Listen, {phrase}",
        "I need you to {phrase}",
        "Can you {phrase}",
        "Please {phrase}, ok?",
        "You trust me right? {phrase}",
        "It's just between us. {phrase}",
        "Nobody needs to know. {phrase}",
        "I really like you. {phrase}",
    ]

    texts = []
    labels = {col: [] for col in LABELS}

    # Grooming → S3
    for phrase in grooming_phrases:
        for template in random.sample(grooming_templates, min(4, len(grooming_templates))):
            text = template.format(phrase=phrase)
            texts.append(text)
            for col in LABELS:
                labels[col].append(1 if col == "S3" else 0)

    # Manipulation → HR
    manip_templates = ["{phrase}", "Listen, {phrase}", "If you don't, {phrase}"]
    for phrase in manipulation_phrases:
        for template in manip_templates:
            text = template.format(phrase=phrase)
            texts.append(text)
            for col in LABELS:
                labels[col].append(1 if col == "HR" else 0)

    # Selfharm → SH
    sh_templates = ["{phrase}", "I just feel like {phrase}", "I've decided, {phrase}"]
    for phrase in selfharm_phrases:
        for template in sh_templates:
            text = template.format(phrase=phrase)
            texts.append(text)
            for col in LABELS:
                labels[col].append(1 if col == "SH" else 0)

    # Bullying → HR
    bully_templates = ["{phrase}", "Hey loser, {phrase}", "Everyone knows {phrase}"]
    for phrase in bullying_phrases:
        for template in bully_templates:
            text = template.format(phrase=phrase)
            texts.append(text)
            for col in LABELS:
                labels[col].append(1 if col == "HR" else 0)

    print(f"  Generated {len(texts)} synthetic examples")
    return texts, labels


def load_kids_synthetic():
    """Load kids-specific synthetic data (multi-stage grooming, negatives)."""
    path = SYNTHETIC_DIR / "kids_synthetic.parquet"
    if not path.exists():
        print("  kids_synthetic.parquet not found, run generate_kids_synthetic.py first")
        return [], {col: [] for col in LABELS}

    print(f"Loading kids synthetic from {path}...")
    table = pq.read_table(path)
    texts = table.column("prompt").to_pylist()
    labels = {}
    for col in LABELS:
        labels[col] = [int(v or 0) for v in table.column(col).to_pylist()]
    print(f"  {len(texts)} samples")
    return texts, labels


def load_suicide_data():
    """Load vibhorag101 suicide prediction dataset."""
    path = DATA_DIR / "vibhorag101_suicide"
    if not path.exists():
        print("  vibhorag101 not found, skipping")
        return [], {col: [] for col in LABELS}

    from datasets import load_from_disk
    print(f"Loading vibhorag101 suicide data...")
    ds = load_from_disk(str(path))
    train = ds["train"]

    texts = []
    labels = {col: [] for col in LABELS}

    for row in train:
        text = row.get("text", "") or ""
        label = row.get("label", row.get("class", "")) or ""
        if not text or len(text) < 10:
            continue
        is_suicide = str(label).lower() in ("suicide", "1")
        texts.append(text[:512])
        for col in LABELS:
            labels[col].append(1 if (col == "SH" and is_suicide) else 0)

    # Subsample non-suicide to balance
    suicide_idx = [i for i, t in enumerate(texts) if labels["SH"][i] == 1]
    non_suicide_idx = [i for i, t in enumerate(texts) if labels["SH"][i] == 0]
    keep_non = random.sample(non_suicide_idx, min(len(non_suicide_idx), len(suicide_idx) * 2))
    keep = sorted(suicide_idx + keep_non)

    texts = [texts[i] for i in keep]
    for col in LABELS:
        labels[col] = [labels[col][i] for i in keep]

    print(f"  {len(texts)} samples ({sum(labels['SH'])} suicide, {len(texts) - sum(labels['SH'])} non-suicide)")
    return texts, labels


def load_swmh_data():
    """Load AIMH/SWMH mental health dataset."""
    path = DATA_DIR / "AIMH_SWMH"
    if not path.exists():
        print("  AIMH/SWMH not found, skipping")
        return [], {col: [] for col in LABELS}

    from datasets import load_from_disk
    print(f"Loading AIMH/SWMH...")
    ds = load_from_disk(str(path))
    train = ds["train"]

    texts = []
    labels = {col: [] for col in LABELS}

    for row in train:
        text = row.get("text", "") or ""
        label = row.get("label", 0)
        if not text or len(text) < 10:
            continue
        is_sh = label == 4  # suicidal ideation
        texts.append(text[:512])
        for col in LABELS:
            labels[col].append(1 if (col == "SH" and is_sh) else 0)

    print(f"  {len(texts)} samples ({sum(labels['SH'])} suicidal ideation)")
    return texts, labels


def load_textdetox():
    """Load multilingual toxicity dataset (has UK+RU+EN)."""
    path = DATA_DIR / "textdetox_multilingual"
    if not path.exists():
        print("  textdetox not found, skipping")
        return [], {col: [] for col in LABELS}

    from datasets import load_from_disk
    print(f"Loading textdetox multilingual...")
    ds = load_from_disk(str(path))

    texts = []
    labels = {col: [] for col in LABELS}

    for lang_key in ["en", "ru", "uk"]:
        if lang_key not in ds:
            continue
        split = ds[lang_key]
        for row in split:
            text = row.get("text", "") or ""
            is_toxic = row.get("toxic", 0) or 0
            if not text or len(text) < 5:
                continue
            texts.append(text[:512])
            for col in LABELS:
                labels[col].append(1 if (col == "HR" and is_toxic) else 0)

    print(f"  {len(texts)} UK/RU/EN samples ({sum(labels['HR'])} toxic)")
    return texts, labels


def load_cyberbullying():
    """Load AnikaBasu CyberbullyingDataset."""
    path = DATA_DIR / "AnikaBasu_CyberbullyingDataset"
    if not path.exists():
        print("  AnikaBasu cyberbullying not found, skipping")
        return [], {col: [] for col in LABELS}

    from datasets import load_from_disk
    print(f"Loading AnikaBasu cyberbullying...")
    ds = load_from_disk(str(path))
    train = ds["train"]

    texts = []
    labels = {col: [] for col in LABELS}

    # Columns: instruction (text), output (label like "not_cyberbullying", "gender", "religion", etc.)
    for row in train:
        text = row.get("instruction", "") or ""
        output = row.get("output", "") or ""
        if not text or len(text) < 5:
            continue
        is_bullying = output != "not_cyberbullying"
        texts.append(text[:512])
        for col in LABELS:
            labels[col].append(1 if (col == "HR" and is_bullying) else 0)

    print(f"  {len(texts)} samples ({sum(labels['HR'])} cyberbullying)")
    return texts, labels


def load_instagram_cyberbullying():
    """Load SSEF Instagram/TikTok cyberbullying."""
    path = DATA_DIR / "SSEF_cyberbullying_instagram_tiktok"
    if not path.exists():
        print("  SSEF Instagram cyberbullying not found, skipping")
        return [], {col: [] for col in LABELS}

    from datasets import load_from_disk
    print(f"Loading Instagram/TikTok cyberbullying...")
    ds = load_from_disk(str(path))
    train = ds["train"]

    texts = []
    labels = {col: [] for col in LABELS}

    for row in train:
        text = row.get("text", "") or ""
        label = row.get("label", 0)
        if not text or len(text) < 5:
            continue
        is_bullying = label == 1
        texts.append(text[:512])
        for col in LABELS:
            labels[col].append(1 if (col == "HR" and is_bullying) else 0)

    print(f"  {len(texts)} samples ({sum(labels['HR'])} cyberbullying)")
    return texts, labels


def load_offensive_grooming():
    """Load Brandon-h offensive and grooming dataset (Spanish)."""
    path = DATA_DIR / "Brandon-h_offensive_grooming"
    if not path.exists():
        print("  Brandon-h offensive+grooming not found, skipping")
        return [], {col: [] for col in LABELS}

    from datasets import load_from_disk
    print(f"Loading Brandon-h offensive+grooming...")
    ds = load_from_disk(str(path))

    texts = []
    labels = {col: [] for col in LABELS}

    # id2label = {0:"OFP", 1:"OFG", 2:"NO", 3:"NOE", 4:"GP"}
    # GP = Grooming Predator, OFP = Offensive to Person
    for split_name in ["train", "test"]:
        if split_name not in ds:
            continue
        for row in ds[split_name]:
            text = row.get("text", "") or ""
            label = row.get("label", 2)
            if not text or len(text) < 5:
                continue
            texts.append(text[:512])
            row_labels = {}
            if label == 4:  # GP (grooming predator)
                row_labels = {"S3": 1, "HR": 1}
            elif label == 0:  # OFP (offensive to person)
                row_labels = {"HR": 1}
            elif label == 1:  # OFG (offensive to group)
                row_labels = {"H": 1}
            # 2=NO, 3=NOE → all zeros (non-offensive)
            for col in LABELS:
                labels[col].append(1 if col in row_labels else 0)

    print(f"  {len(texts)} samples (S3: {sum(labels['S3'])}, HR: {sum(labels['HR'])}, H: {sum(labels['H'])})")
    return texts, labels


def load_youthsafebench():
    """Load apgard YouthSafeBench teen suicide/self-harm."""
    path = DATA_DIR / "apgard_youthsafebench"
    if not path.exists():
        print("  YouthSafeBench not found, skipping")
        return [], {col: [] for col in LABELS}

    from datasets import load_from_disk
    print(f"Loading YouthSafeBench...")
    ds = load_from_disk(str(path))
    train = ds["train"]

    texts = []
    labels = {col: [] for col in LABELS}

    # Label: 0=safe, 1=mild, 2=moderate, 3=severe
    for row in train:
        text = row.get("Message", "") or ""
        label = row.get("Label", 0)
        if not text or len(text) < 3:
            continue
        is_sh = label >= 2  # moderate or severe
        texts.append(text[:512])
        for col in LABELS:
            labels[col].append(1 if (col == "SH" and is_sh) else 0)

    print(f"  {len(texts)} samples ({sum(labels['SH'])} self-harm)")
    return texts, labels


def merge_datasets(*datasets):
    """Merge multiple (texts, labels) tuples."""
    all_texts = []
    all_labels = {col: [] for col in LABELS}
    for texts, labels in datasets:
        all_texts.extend(texts)
        for col in LABELS:
            all_labels[col].extend(labels[col])
    return all_texts, all_labels


def save_parquet(texts, labels, path):
    """Save as parquet file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.table({
        "prompt": texts,
        **{col: labels[col] for col in LABELS},
    })
    pq.write_table(table, path)
    print(f"\nSaved to {path}")
    print(f"  Total: {len(texts)} samples")
    for col in LABELS:
        pos = sum(labels[col])
        print(f"  {col}: {pos} positives ({pos * 100 / len(texts):.1f}%)")


def main():
    # Load all sources
    koalai = load_koalai()
    grooming_lexicon = generate_grooming_synthetic()
    kids_synthetic = load_kids_synthetic()
    suicide = load_suicide_data()
    swmh = load_swmh_data()
    textdetox = load_textdetox()
    cyberbullying = load_cyberbullying()
    instagram = load_instagram_cyberbullying()
    offensive_grooming = load_offensive_grooming()
    youthsafe = load_youthsafebench()

    # Oversample grooming data 8x (most critical category, hardest to detect)
    print("\nOversampling grooming data 8x...")
    grooming_8x_texts = grooming_lexicon[0] * 8
    grooming_8x_labels = {col: grooming_lexicon[1][col] * 8 for col in LABELS}

    # Oversample kids synthetic 10x (high-quality multi-stage data)
    print("Oversampling kids synthetic 10x...")
    kids_10x_texts = kids_synthetic[0] * 10
    kids_10x_labels = {col: kids_synthetic[1][col] * 10 for col in LABELS}

    # Merge everything
    print("\nMerging all datasets...")
    all_texts, all_labels = merge_datasets(
        koalai,
        (grooming_8x_texts, grooming_8x_labels),
        (kids_10x_texts, kids_10x_labels),
        suicide,
        swmh,
        textdetox,
        cyberbullying,
        instagram,
        offensive_grooming,
        youthsafe,
    )

    # Shuffle
    print(f"Shuffling {len(all_texts)} samples...")
    indices = list(range(len(all_texts)))
    random.shuffle(indices)
    all_texts = [all_texts[i] for i in indices]
    for col in LABELS:
        all_labels[col] = [all_labels[col][i] for i in indices]

    # Split: 95% train, 5% val
    split = int(len(all_texts) * 0.95)
    train_texts, val_texts = all_texts[:split], all_texts[split:]
    train_labels = {col: all_labels[col][:split] for col in LABELS}
    val_labels = {col: all_labels[col][split:] for col in LABELS}

    save_parquet(train_texts, train_labels, OUTPUT_DIR / "train.parquet")
    save_parquet(val_texts, val_labels, OUTPUT_DIR / "validation.parquet")


if __name__ == "__main__":
    main()
