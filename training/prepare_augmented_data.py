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

Outputs train and validation parquet files with the model-input schema:
  prompt, S, S3, SH, HR, H, V, V2, H2

and audit metadata:
  sample_id, source, provenance, source_record_id, source_group_id,
  source_record_kind, source_group_kind, split_group_id, content_sha256,
  augmentation, replica_index

Changes from v2:
  - Dropped sentiment labels (model is now pure 8-label safety)
  - Added kids-specific synthetic data with multi-stage grooming
  - Added cyberbullying datasets
  - Added negative controls (benign teen conversations)
  - Increased grooming oversample from 5x to 8x
  - Split source cases/templates before oversampling to prevent leakage
  - Retained source and grouping provenance in the parquet outputs
"""

from dataclasses import dataclass
import hashlib
import json
import random
from pathlib import Path
import unicodedata

import pyarrow as pa
import pyarrow.parquet as pq

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "raw" / "hf"
SYNTHETIC_DIR = PROJECT_ROOT / "training" / "synthetic"
OUTPUT_DIR = PROJECT_ROOT / "training" / "augmented"
LABELS = ["S", "S3", "SH", "HR", "H", "V", "V2", "H2"]
RANDOM_SEED = 42
VALIDATION_RATIO = 0.05

# Prefer identities that keep an entire conversation/case/template in one split.
# Generic row ids are intentionally not group ids: they would split messages from
# the same conversation when a source exposes both fields.
GROUP_ID_FIELDS = (
    "case_id",
    "conversation_id",
    "conversationId",
    "dialogue_id",
    "dialog_id",
    "thread_id",
    "session_id",
    "template_id",
    "scenario_id",
    "parent_id",
)
RECORD_ID_FIELDS = (
    "message_id",
    "record_id",
    "example_id",
    "uuid",
    "id",
)

RNG = random.Random(RANDOM_SEED)

KIDS_SYNTHETIC_PREFIXES = tuple(
    sorted(
        {
            "hey ", "listen ", "btw ", "ok so ", "yo ", "lol ",
            "seriously ", "honestly ", "look ", "bro ", "dude ",
            "слухай ", "ей ", "до речі ", "ну типу ", "серйозно ",
            "слушай ", "эй ", "кстати ", "ну типа ", "серьёзно ",
        },
        key=len,
        reverse=True,
    )
)


def _digest(namespace, value):
    """Return a stable, opaque identifier safe to retain for dataset audits."""
    payload = f"{namespace}\0{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalized_prompt(text):
    """Normalize representation without changing the prompt written to parquet."""
    return unicodedata.normalize("NFC", str(text or "")).strip()


def _kids_synthetic_template_identity(text):
    """Recover the source template shared by generated prefix variations."""
    normalized = _normalized_prompt(text)
    for prefix in KIDS_SYNTHETIC_PREFIXES:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
            break
    if not normalized:
        return normalized
    return normalized[0].lower() + normalized[1:]


def _identity_value(row, fields):
    for field in fields:
        value = row.get(field)
        if value is not None and str(value).strip():
            return field, str(value)
    return None, None


def _arrow_identity_values(table, fields):
    for field in fields:
        if field not in table.column_names:
            continue
        values = table.column(field).to_pylist()
        if any(value is not None and str(value).strip() for value in values):
            return field, values
    return None, None


@dataclass
class Samples:
    """Columnar samples plus identities required for leakage-safe splitting."""

    texts: list
    labels: dict
    sources: list
    provenances: list
    source_record_ids: list
    source_record_kinds: list
    source_group_ids: list
    source_group_kinds: list
    content_ids: list
    base_sample_ids: list
    split_group_ids: list
    augmentations: list
    replica_indices: list

    @classmethod
    def empty(cls):
        return cls(
            texts=[],
            labels={col: [] for col in LABELS},
            sources=[],
            provenances=[],
            source_record_ids=[],
            source_record_kinds=[],
            source_group_ids=[],
            source_group_kinds=[],
            content_ids=[],
            base_sample_ids=[],
            split_group_ids=[],
            augmentations=[],
            replica_indices=[],
        )

    def __len__(self):
        return len(self.texts)


def _samples_from_columns(
    source,
    provenance,
    texts,
    labels,
    *,
    group_values=None,
    group_kind="content",
    record_values=None,
    record_kind="row",
):
    """Attach stable provenance to a source's existing model columns."""
    sample_count = len(texts)
    if any(len(labels[col]) != sample_count for col in LABELS):
        raise ValueError(f"{source}: prompt and label column lengths differ")
    if group_values is not None and len(group_values) != sample_count:
        raise ValueError(f"{source}: group identity length differs from prompts")
    if record_values is not None and len(record_values) != sample_count:
        raise ValueError(f"{source}: record identity length differs from prompts")

    result = Samples.empty()
    for index, text in enumerate(texts):
        normalized = _normalized_prompt(text)
        content_id = _digest("prompt", normalized)

        raw_group = group_values[index] if group_values is not None else None
        if raw_group is None or not str(raw_group).strip():
            raw_group = content_id
            current_group_kind = "content"
        else:
            current_group_kind = group_kind
        source_group_id = _digest(
            "source-group",
            f"{source}\0{current_group_kind}\0{raw_group}",
        )

        raw_record = record_values[index] if record_values is not None else None
        if raw_record is None or not str(raw_record).strip():
            raw_record = f"{index}\0{content_id}"
            current_record_kind = "row"
        else:
            current_record_kind = record_kind
        source_record_id = _digest(
            "source-record",
            f"{source}\0{current_record_kind}\0{raw_record}",
        )
        base_sample_id = _digest(
            "base-sample",
            f"{source}\0{source_record_id}\0{content_id}\0{index}",
        )

        result.texts.append(text)
        for col in LABELS:
            result.labels[col].append(int(labels[col][index] or 0))
        result.sources.append(source)
        result.provenances.append(provenance)
        result.source_record_ids.append(source_record_id)
        result.source_record_kinds.append(current_record_kind)
        result.source_group_ids.append(source_group_id)
        result.source_group_kinds.append(current_group_kind)
        result.content_ids.append(content_id)
        result.base_sample_ids.append(base_sample_id)
        result.split_group_ids.append("")
        result.augmentations.append("original")
        result.replica_indices.append(0)

    return result


def _samples_from_arrow(source, provenance, table, texts, labels):
    group_kind, group_values = _arrow_identity_values(table, GROUP_ID_FIELDS)
    record_kind, record_values = _arrow_identity_values(table, RECORD_ID_FIELDS)
    return _samples_from_columns(
        source,
        provenance,
        texts,
        labels,
        group_values=group_values,
        group_kind=group_kind or "content",
        record_values=record_values,
        record_kind=record_kind or "row",
    )


def _append_row_identities(row, text, index, group_values, record_values, scope=None):
    group_kind, group_value = _identity_value(row, GROUP_ID_FIELDS)
    record_kind, record_value = _identity_value(row, RECORD_ID_FIELDS)
    if scope and group_kind:
        group_kind = f"{scope}:{group_kind}"
    if scope and record_kind:
        record_kind = f"{scope}:{record_kind}"
    group_values.append((group_kind, group_value))
    fallback_scope = scope or "rows"
    record_values.append(
        (
            record_kind,
            record_value or f"{fallback_scope}\0{index}\0{_digest('prompt', _normalized_prompt(text))}",
        )
    )


def _finish_row_dataset(source, provenance, texts, labels, group_identities, record_identities):
    group_kinds = {kind for kind, value in group_identities if value is not None}
    record_kinds = {kind for kind, value in record_identities if kind is not None and value is not None}

    # A source can expose more than one identity field across rows. Include the
    # field name in each raw value so those namespaces cannot collide.
    group_values = [f"{kind}:{value}" if value is not None else None for kind, value in group_identities]
    record_values = [f"{kind}:{value}" for kind, value in record_identities]
    return _samples_from_columns(
        source,
        provenance,
        texts,
        labels,
        group_values=group_values,
        group_kind="source-case" if group_kinds else "content",
        record_values=record_values,
        record_kind="source-record" if record_kinds else "row",
    )


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
    return _samples_from_arrow(
        "koalai_multilingual",
        "hf:KoalaAI/Text-Moderation-Multilingual",
        table,
        texts,
        labels,
    )


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
    group_values = []
    record_values = []

    # Grooming → S3
    for phrase in grooming_phrases:
        for template in RNG.sample(grooming_templates, min(4, len(grooming_templates))):
            text = template.format(phrase=phrase)
            texts.append(text)
            group_values.append(f"grooming:{phrase}")
            record_values.append(f"grooming:{phrase}:{template}")
            for col in LABELS:
                labels[col].append(1 if col == "S3" else 0)

    # Manipulation → HR
    manip_templates = ["{phrase}", "Listen, {phrase}", "If you don't, {phrase}"]
    for phrase in manipulation_phrases:
        for template in manip_templates:
            text = template.format(phrase=phrase)
            texts.append(text)
            group_values.append(f"manipulation:{phrase}")
            record_values.append(f"manipulation:{phrase}:{template}")
            for col in LABELS:
                labels[col].append(1 if col == "HR" else 0)

    # Selfharm → SH
    sh_templates = ["{phrase}", "I just feel like {phrase}", "I've decided, {phrase}"]
    for phrase in selfharm_phrases:
        for template in sh_templates:
            text = template.format(phrase=phrase)
            texts.append(text)
            group_values.append(f"selfharm:{phrase}")
            record_values.append(f"selfharm:{phrase}:{template}")
            for col in LABELS:
                labels[col].append(1 if col == "SH" else 0)

    # Bullying → HR
    bully_templates = ["{phrase}", "Hey loser, {phrase}", "Everyone knows {phrase}"]
    for phrase in bullying_phrases:
        for template in bully_templates:
            text = template.format(phrase=phrase)
            texts.append(text)
            group_values.append(f"bullying:{phrase}")
            record_values.append(f"bullying:{phrase}:{template}")
            for col in LABELS:
                labels[col].append(1 if col == "HR" else 0)

    print(f"  Generated {len(texts)} synthetic examples")
    return _samples_from_columns(
        "aura_kids_lexicon_synthetic",
        "generated:aura-kids/data/lexicon.json",
        texts,
        labels,
        group_values=group_values,
        group_kind="lexicon-phrase",
        record_values=record_values,
        record_kind="rendered-template",
    )


def load_kids_synthetic():
    """Load kids-specific synthetic data (multi-stage grooming, negatives)."""
    path = SYNTHETIC_DIR / "kids_synthetic.parquet"
    if not path.exists():
        print("  kids_synthetic.parquet not found, run generate_kids_synthetic.py first")
        return Samples.empty()

    print(f"Loading kids synthetic from {path}...")
    table = pq.read_table(path)
    texts = table.column("prompt").to_pylist()
    labels = {}
    for col in LABELS:
        labels[col] = [int(v or 0) for v in table.column(col).to_pylist()]
    print(f"  {len(texts)} samples")
    group_values = [_kids_synthetic_template_identity(text) for text in texts]
    return _samples_from_columns(
        "aura_kids_synthetic",
        "generated:training/generate_kids_synthetic.py",
        texts,
        labels,
        group_values=group_values,
        group_kind="synthetic-template",
    )


def load_suicide_data():
    """Load vibhorag101 suicide prediction dataset."""
    path = DATA_DIR / "vibhorag101_suicide"
    if not path.exists():
        print("  vibhorag101 not found, skipping")
        return Samples.empty()

    from datasets import load_from_disk
    print(f"Loading vibhorag101 suicide data...")
    ds = load_from_disk(str(path))
    train = ds["train"]

    texts = []
    labels = {col: [] for col in LABELS}
    group_identities = []
    record_identities = []

    for row_index, row in enumerate(train):
        text = row.get("text", "") or ""
        label = row.get("label", row.get("class", "")) or ""
        if not text or len(text) < 10:
            continue
        is_suicide = str(label).lower() in ("suicide", "1")
        texts.append(text[:512])
        _append_row_identities(
            row,
            text[:512],
            row_index,
            group_identities,
            record_identities,
        )
        for col in LABELS:
            labels[col].append(1 if (col == "SH" and is_suicide) else 0)

    # Subsample non-suicide to balance
    suicide_idx = [i for i, t in enumerate(texts) if labels["SH"][i] == 1]
    non_suicide_idx = [i for i, t in enumerate(texts) if labels["SH"][i] == 0]
    keep_non = RNG.sample(non_suicide_idx, min(len(non_suicide_idx), len(suicide_idx) * 2))
    keep = sorted(suicide_idx + keep_non)

    texts = [texts[i] for i in keep]
    for col in LABELS:
        labels[col] = [labels[col][i] for i in keep]
    group_identities = [group_identities[i] for i in keep]
    record_identities = [record_identities[i] for i in keep]

    print(f"  {len(texts)} samples ({sum(labels['SH'])} suicide, {len(texts) - sum(labels['SH'])} non-suicide)")
    return _finish_row_dataset(
        "vibhorag101_suicide",
        "hf:vibhorag101/suicide_prediction_dataset_phr",
        texts,
        labels,
        group_identities,
        record_identities,
    )


def load_swmh_data():
    """Load AIMH/SWMH mental health dataset."""
    path = DATA_DIR / "AIMH_SWMH"
    if not path.exists():
        print("  AIMH/SWMH not found, skipping")
        return Samples.empty()

    from datasets import load_from_disk
    print(f"Loading AIMH/SWMH...")
    ds = load_from_disk(str(path))
    train = ds["train"]

    texts = []
    labels = {col: [] for col in LABELS}
    group_identities = []
    record_identities = []

    for row_index, row in enumerate(train):
        text = row.get("text", "") or ""
        label = row.get("label", 0)
        if not text or len(text) < 10:
            continue
        is_sh = label == 4  # suicidal ideation
        texts.append(text[:512])
        _append_row_identities(
            row,
            text[:512],
            row_index,
            group_identities,
            record_identities,
        )
        for col in LABELS:
            labels[col].append(1 if (col == "SH" and is_sh) else 0)

    print(f"  {len(texts)} samples ({sum(labels['SH'])} suicidal ideation)")
    return _finish_row_dataset(
        "aimh_swmh",
        "hf:AIMH/SWMH",
        texts,
        labels,
        group_identities,
        record_identities,
    )


def load_textdetox():
    """Load multilingual toxicity dataset (has UK+RU+EN)."""
    path = DATA_DIR / "textdetox_multilingual"
    if not path.exists():
        print("  textdetox not found, skipping")
        return Samples.empty()

    from datasets import load_from_disk
    print(f"Loading textdetox multilingual...")
    ds = load_from_disk(str(path))

    texts = []
    labels = {col: [] for col in LABELS}
    group_identities = []
    record_identities = []

    for lang_key in ["en", "ru", "uk"]:
        if lang_key not in ds:
            continue
        split = ds[lang_key]
        for row_index, row in enumerate(split):
            text = row.get("text", "") or ""
            is_toxic = row.get("toxic", 0) or 0
            if not text or len(text) < 5:
                continue
            texts.append(text[:512])
            _append_row_identities(
                row,
                text[:512],
                row_index,
                group_identities,
                record_identities,
                scope=lang_key,
            )
            for col in LABELS:
                labels[col].append(1 if (col == "HR" and is_toxic) else 0)

    print(f"  {len(texts)} UK/RU/EN samples ({sum(labels['HR'])} toxic)")
    return _finish_row_dataset(
        "textdetox_multilingual",
        "hf:textdetox/multilingual_toxicity_dataset",
        texts,
        labels,
        group_identities,
        record_identities,
    )


def load_cyberbullying():
    """Load AnikaBasu CyberbullyingDataset."""
    path = DATA_DIR / "AnikaBasu_CyberbullyingDataset"
    if not path.exists():
        print("  AnikaBasu cyberbullying not found, skipping")
        return Samples.empty()

    from datasets import load_from_disk
    print(f"Loading AnikaBasu cyberbullying...")
    ds = load_from_disk(str(path))
    train = ds["train"]

    texts = []
    labels = {col: [] for col in LABELS}
    group_identities = []
    record_identities = []

    # Columns: instruction (text), output (label like "not_cyberbullying", "gender", "religion", etc.)
    for row_index, row in enumerate(train):
        text = row.get("instruction", "") or ""
        output = row.get("output", "") or ""
        if not text or len(text) < 5:
            continue
        is_bullying = output != "not_cyberbullying"
        texts.append(text[:512])
        _append_row_identities(
            row,
            text[:512],
            row_index,
            group_identities,
            record_identities,
        )
        for col in LABELS:
            labels[col].append(1 if (col == "HR" and is_bullying) else 0)

    print(f"  {len(texts)} samples ({sum(labels['HR'])} cyberbullying)")
    return _finish_row_dataset(
        "anikabasu_cyberbullying",
        "hf:AnikaBasu/CyberbullyingDataset",
        texts,
        labels,
        group_identities,
        record_identities,
    )


def load_instagram_cyberbullying():
    """Load SSEF Instagram/TikTok cyberbullying."""
    path = DATA_DIR / "SSEF_cyberbullying_instagram_tiktok"
    if not path.exists():
        print("  SSEF Instagram cyberbullying not found, skipping")
        return Samples.empty()

    from datasets import load_from_disk
    print(f"Loading Instagram/TikTok cyberbullying...")
    ds = load_from_disk(str(path))
    train = ds["train"]

    texts = []
    labels = {col: [] for col in LABELS}
    group_identities = []
    record_identities = []

    for row_index, row in enumerate(train):
        text = row.get("text", "") or ""
        label = row.get("label", 0)
        if not text or len(text) < 5:
            continue
        is_bullying = label == 1
        texts.append(text[:512])
        _append_row_identities(
            row,
            text[:512],
            row_index,
            group_identities,
            record_identities,
        )
        for col in LABELS:
            labels[col].append(1 if (col == "HR" and is_bullying) else 0)

    print(f"  {len(texts)} samples ({sum(labels['HR'])} cyberbullying)")
    return _finish_row_dataset(
        "ssef_instagram_tiktok_cyberbullying",
        "hf:SSEF/cyberbullying-instagram-tiktok",
        texts,
        labels,
        group_identities,
        record_identities,
    )


def load_offensive_grooming():
    """Load Brandon-h offensive and grooming dataset (Spanish)."""
    path = DATA_DIR / "Brandon-h_offensive_grooming"
    if not path.exists():
        print("  Brandon-h offensive+grooming not found, skipping")
        return Samples.empty()

    from datasets import load_from_disk
    print(f"Loading Brandon-h offensive+grooming...")
    ds = load_from_disk(str(path))

    texts = []
    labels = {col: [] for col in LABELS}
    group_identities = []
    record_identities = []

    # id2label = {0:"OFP", 1:"OFG", 2:"NO", 3:"NOE", 4:"GP"}
    # GP = Grooming Predator, OFP = Offensive to Person
    for split_name in ["train", "test"]:
        if split_name not in ds:
            continue
        for row_index, row in enumerate(ds[split_name]):
            text = row.get("text", "") or ""
            label = row.get("label", 2)
            if not text or len(text) < 5:
                continue
            texts.append(text[:512])
            _append_row_identities(
                row,
                text[:512],
                row_index,
                group_identities,
                record_identities,
                scope=split_name,
            )
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
    return _finish_row_dataset(
        "brandon_h_offensive_grooming",
        "hf:Brandon-h/offensive-grooming",
        texts,
        labels,
        group_identities,
        record_identities,
    )


def load_youthsafebench():
    """Load apgard YouthSafeBench teen suicide/self-harm."""
    path = DATA_DIR / "apgard_youthsafebench"
    if not path.exists():
        print("  YouthSafeBench not found, skipping")
        return Samples.empty()

    from datasets import load_from_disk
    print(f"Loading YouthSafeBench...")
    ds = load_from_disk(str(path))
    train = ds["train"]

    texts = []
    labels = {col: [] for col in LABELS}
    group_identities = []
    record_identities = []

    # Label: 0=safe, 1=mild, 2=moderate, 3=severe
    for row_index, row in enumerate(train):
        text = row.get("Message", "") or ""
        label = row.get("Label", 0)
        if not text or len(text) < 3:
            continue
        is_sh = label >= 2  # moderate or severe
        texts.append(text[:512])
        _append_row_identities(
            row,
            text[:512],
            row_index,
            group_identities,
            record_identities,
        )
        for col in LABELS:
            labels[col].append(1 if (col == "SH" and is_sh) else 0)

    print(f"  {len(texts)} samples ({sum(labels['SH'])} self-harm)")
    return _finish_row_dataset(
        "apgard_youthsafebench",
        "hf:apgard/YouthSafeBench",
        texts,
        labels,
        group_identities,
        record_identities,
    )


def merge_datasets(*datasets):
    """Merge source batches without discarding audit metadata."""
    result = Samples.empty()
    for dataset in datasets:
        _validate_samples(dataset, f"source:{dataset.sources[0]}" if dataset.sources else "empty-source")
        result.texts.extend(dataset.texts)
        for col in LABELS:
            result.labels[col].extend(dataset.labels[col])
        result.sources.extend(dataset.sources)
        result.provenances.extend(dataset.provenances)
        result.source_record_ids.extend(dataset.source_record_ids)
        result.source_record_kinds.extend(dataset.source_record_kinds)
        result.source_group_ids.extend(dataset.source_group_ids)
        result.source_group_kinds.extend(dataset.source_group_kinds)
        result.content_ids.extend(dataset.content_ids)
        result.base_sample_ids.extend(dataset.base_sample_ids)
        result.split_group_ids.extend(dataset.split_group_ids)
        result.augmentations.extend(dataset.augmentations)
        result.replica_indices.extend(dataset.replica_indices)
    _validate_samples(result, "merged")
    return result


def _validate_samples(samples, name):
    """Pure structural checks; safe to call before any output is written."""
    expected = len(samples)
    columns = {
        **{f"label:{col}": samples.labels[col] for col in LABELS},
        "source": samples.sources,
        "provenance": samples.provenances,
        "source_record_id": samples.source_record_ids,
        "source_record_kind": samples.source_record_kinds,
        "source_group_id": samples.source_group_ids,
        "source_group_kind": samples.source_group_kinds,
        "content_id": samples.content_ids,
        "base_sample_id": samples.base_sample_ids,
        "split_group_id": samples.split_group_ids,
        "augmentation": samples.augmentations,
        "replica_index": samples.replica_indices,
    }
    mismatched = {column: len(values) for column, values in columns.items() if len(values) != expected}
    if mismatched:
        raise ValueError(f"{name}: column lengths differ from prompts: {mismatched}")

    invalid_labels = [
        col
        for col in LABELS
        if any(value not in (0, 1) for value in samples.labels[col])
    ]
    if invalid_labels:
        raise ValueError(f"{name}: non-binary values in labels {invalid_labels}")

    if any(not value for value in samples.sources):
        raise ValueError(f"{name}: source must be present for every sample")
    if any(not value for value in samples.provenances):
        raise ValueError(f"{name}: provenance must be present for every sample")
    if any(not value for value in samples.source_record_ids):
        raise ValueError(f"{name}: source_record_id must be present for every sample")
    if any(not value for value in samples.source_record_kinds):
        raise ValueError(f"{name}: source_record_kind must be present for every sample")
    if any(not value for value in samples.source_group_ids):
        raise ValueError(f"{name}: source_group_id must be present for every sample")
    if any(not value for value in samples.source_group_kinds):
        raise ValueError(f"{name}: source_group_kind must be present for every sample")
    if any(not value for value in samples.content_ids):
        raise ValueError(f"{name}: content_id must be present for every sample")
    if any(index < 0 for index in samples.replica_indices):
        raise ValueError(f"{name}: replica_index cannot be negative")


class _UnionFind:
    def __init__(self, size):
        self.parent = list(range(size))
        self.rank = bytearray(size)

    def find(self, value):
        root = value
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[value] != value:
            parent = self.parent[value]
            self.parent[value] = root
            value = parent
        return root

    def union(self, left, right):
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if self.rank[left_root] < self.rank[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1


def _split_components(samples):
    """Connect rows sharing either a source case/template or exact content."""
    union_find = _UnionFind(len(samples))
    first_by_source_group = {}
    first_by_content = {}

    for index, (source_group_id, content_id) in enumerate(
        zip(samples.source_group_ids, samples.content_ids)
    ):
        source_owner = first_by_source_group.setdefault(source_group_id, index)
        union_find.union(index, source_owner)

        # content_id is global rather than source-namespaced. Exact duplicates
        # across different datasets therefore cannot land in opposing splits.
        content_owner = first_by_content.setdefault(content_id, index)
        union_find.union(index, content_owner)

    canonical_by_root = {}
    for index, (source_group_id, content_id) in enumerate(
        zip(samples.source_group_ids, samples.content_ids)
    ):
        root = union_find.find(index)
        row_identity = min(f"group:{source_group_id}", f"content:{content_id}")
        current = canonical_by_root.get(root)
        if current is None or row_identity < current:
            canonical_by_root[root] = row_identity

    split_group_by_root = {
        root: _digest("split-component", canonical)
        for root, canonical in canonical_by_root.items()
    }
    return [split_group_by_root[union_find.find(index)] for index in range(len(samples))]


def _take(samples, indices, split_group_ids):
    result = Samples.empty()
    result.texts = [samples.texts[index] for index in indices]
    for col in LABELS:
        result.labels[col] = [samples.labels[col][index] for index in indices]
    result.sources = [samples.sources[index] for index in indices]
    result.provenances = [samples.provenances[index] for index in indices]
    result.source_record_ids = [samples.source_record_ids[index] for index in indices]
    result.source_record_kinds = [samples.source_record_kinds[index] for index in indices]
    result.source_group_ids = [samples.source_group_ids[index] for index in indices]
    result.source_group_kinds = [samples.source_group_kinds[index] for index in indices]
    result.content_ids = [samples.content_ids[index] for index in indices]
    result.base_sample_ids = [samples.base_sample_ids[index] for index in indices]
    result.split_group_ids = [split_group_ids[index] for index in indices]
    result.augmentations = [samples.augmentations[index] for index in indices]
    result.replica_indices = [samples.replica_indices[index] for index in indices]
    return result


def deterministic_group_split(samples, validation_ratio=VALIDATION_RATIO):
    """Split connected source/content groups deterministically."""
    if not 0.0 < validation_ratio < 1.0:
        raise ValueError("validation_ratio must be between zero and one")
    if len(samples) < 2:
        raise ValueError("at least two samples are required for train/validation split")

    split_group_ids = _split_components(samples)
    unique_groups = sorted(set(split_group_ids))
    if len(unique_groups) < 2:
        raise ValueError("at least two independent groups are required for leakage-safe splitting")

    cutoff = int(validation_ratio * (1 << 64))
    group_score = {
        group_id: int(_digest(f"split:{RANDOM_SEED}", group_id)[:16], 16)
        for group_id in unique_groups
    }
    validation_groups = {
        group_id for group_id, score in group_score.items() if score < cutoff
    }

    # Tiny inputs can hash entirely to one side. Preserve determinism while
    # guaranteeing that both output files remain usable.
    if not validation_groups:
        validation_groups.add(min(unique_groups, key=lambda group_id: group_score[group_id]))
    if len(validation_groups) == len(unique_groups):
        validation_groups.remove(max(unique_groups, key=lambda group_id: group_score[group_id]))

    train_indices = []
    validation_indices = []
    for index, group_id in enumerate(split_group_ids):
        destination = validation_indices if group_id in validation_groups else train_indices
        destination.append(index)

    train = _take(samples, train_indices, split_group_ids)
    validation = _take(samples, validation_indices, split_group_ids)
    _validate_split_integrity(train, validation, expect_validation_originals=True)
    return train, validation


def oversample_training(samples, source_factors):
    """Replicate only training rows, retaining their original split group."""
    result = Samples.empty()
    for index in range(len(samples)):
        factor = source_factors.get(samples.sources[index], 1)
        if not isinstance(factor, int) or factor < 1:
            raise ValueError(f"invalid oversampling factor for {samples.sources[index]}: {factor}")
        for replica_index in range(factor):
            result.texts.append(samples.texts[index])
            for col in LABELS:
                result.labels[col].append(samples.labels[col][index])
            result.sources.append(samples.sources[index])
            result.provenances.append(samples.provenances[index])
            result.source_record_ids.append(samples.source_record_ids[index])
            result.source_record_kinds.append(samples.source_record_kinds[index])
            result.source_group_ids.append(samples.source_group_ids[index])
            result.source_group_kinds.append(samples.source_group_kinds[index])
            result.content_ids.append(samples.content_ids[index])
            result.base_sample_ids.append(samples.base_sample_ids[index])
            result.split_group_ids.append(samples.split_group_ids[index])
            result.augmentations.append("original" if replica_index == 0 else "oversampled")
            result.replica_indices.append(replica_index)
    _validate_samples(result, "oversampled-train")
    _validate_oversampling(result, source_factors)
    return result


def _validate_oversampling(samples, source_factors):
    replicas_by_base = {}
    for source, base_sample_id, augmentation, replica_index in zip(
        samples.sources,
        samples.base_sample_ids,
        samples.augmentations,
        samples.replica_indices,
    ):
        factor = source_factors.get(source, 1)
        expected_augmentation = "original" if replica_index == 0 else "oversampled"
        if augmentation != expected_augmentation:
            raise ValueError(
                f"{base_sample_id}: augmentation does not match replica_index"
            )
        if factor == 1:
            if replica_index != 0:
                raise ValueError(f"{base_sample_id}: unexpected oversampled replica")
            continue
        state = replicas_by_base.setdefault(
            base_sample_id,
            {"factor": factor, "indices": set()},
        )
        if state["factor"] != factor:
            raise ValueError(f"{base_sample_id}: inconsistent oversampling factor")
        state["indices"].add(replica_index)

    for base_sample_id, state in replicas_by_base.items():
        factor = state["factor"]
        replica_indices = state["indices"]
        if replica_indices != set(range(factor)):
            raise ValueError(
                f"{base_sample_id}: expected replicas 0..{factor - 1}, "
                f"found {sorted(replica_indices)}"
            )


def _stable_shuffle(samples, namespace):
    indices = list(range(len(samples)))
    indices.sort(
        key=lambda index: _digest(
            f"shuffle:{RANDOM_SEED}:{namespace}",
            f"{samples.base_sample_ids[index]}\0{samples.replica_indices[index]}",
        )
    )
    return _take(samples, indices, samples.split_group_ids)


def _sample_ids(samples):
    return [
        _digest("sample", f"{base_sample_id}\0{replica_index}")
        for base_sample_id, replica_index in zip(
            samples.base_sample_ids,
            samples.replica_indices,
        )
    ]


def _validate_split_integrity(train, validation, expect_validation_originals):
    """Fail closed if any split or replica invariant is violated."""
    _validate_samples(train, "train")
    _validate_samples(validation, "validation")
    if len(train) == 0 or len(validation) == 0:
        raise ValueError("train and validation must both contain samples")
    if any(not group_id for group_id in train.split_group_ids):
        raise ValueError("train contains an unassigned split_group_id")
    if any(not group_id for group_id in validation.split_group_ids):
        raise ValueError("validation contains an unassigned split_group_id")

    checks = {
        "split groups": set(train.split_group_ids) & set(validation.split_group_ids),
        "source groups": set(train.source_group_ids) & set(validation.source_group_ids),
        "exact content": set(train.content_ids) & set(validation.content_ids),
        "base samples": set(train.base_sample_ids) & set(validation.base_sample_ids),
    }
    leaking = {name: values for name, values in checks.items() if values}
    if leaking:
        counts = {name: len(values) for name, values in leaking.items()}
        raise ValueError(f"train/validation leakage detected: {counts}")

    if expect_validation_originals and any(
        augmentation != "original" or replica_index != 0
        for augmentation, replica_index in zip(
            validation.augmentations,
            validation.replica_indices,
        )
    ):
        raise ValueError("validation must not contain oversampled replicas")

    train_ids = _sample_ids(train)
    validation_ids = _sample_ids(validation)
    if len(train_ids) != len(set(train_ids)):
        raise ValueError("train sample_id values are not unique")
    if len(validation_ids) != len(set(validation_ids)):
        raise ValueError("validation sample_id values are not unique")
    if set(train_ids) & set(validation_ids):
        raise ValueError("sample_id appears in both train and validation")


def save_parquet(samples, path):
    """Save model columns plus provenance required for later audit."""
    _validate_samples(samples, f"output:{path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.table({
        "prompt": samples.texts,
        **{col: samples.labels[col] for col in LABELS},
        "sample_id": _sample_ids(samples),
        "source": samples.sources,
        "provenance": samples.provenances,
        "source_record_id": samples.source_record_ids,
        "source_record_kind": samples.source_record_kinds,
        "source_group_id": samples.source_group_ids,
        "source_group_kind": samples.source_group_kinds,
        "split_group_id": samples.split_group_ids,
        "content_sha256": samples.content_ids,
        "augmentation": samples.augmentations,
        "replica_index": samples.replica_indices,
    })
    pq.write_table(table, path)
    print(f"\nSaved to {path}")
    print(f"  Total: {len(samples)} samples")
    for col in LABELS:
        pos = sum(samples.labels[col])
        print(f"  {col}: {pos} positives ({pos * 100 / len(samples):.1f}%)")


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

    # Merge unique source rows before assigning any replicas.
    print("\nMerging all datasets...")
    base_samples = merge_datasets(
        koalai,
        grooming_lexicon,
        kids_synthetic,
        suicide,
        swmh,
        textdetox,
        cyberbullying,
        instagram,
        offensive_grooming,
        youthsafe,
    )

    print(f"Splitting {len(base_samples)} base samples by source/content groups...")
    train, validation = deterministic_group_split(base_samples)

    # Oversampling is train-only. Validation retains one original row per base
    # sample and therefore cannot share an oversampled copy with training.
    print("Oversampling train-only sources (grooming 8x, kids synthetic 10x)...")
    oversampling_factors = {
        "aura_kids_lexicon_synthetic": 8,
        "aura_kids_synthetic": 10,
    }
    train = oversample_training(train, oversampling_factors)
    train = _stable_shuffle(train, "train")
    validation = _stable_shuffle(validation, "validation")
    _validate_oversampling(train, oversampling_factors)
    _validate_split_integrity(train, validation, expect_validation_originals=True)

    save_parquet(train, OUTPUT_DIR / "train.parquet")
    save_parquet(validation, OUTPUT_DIR / "validation.parquet")


if __name__ == "__main__":
    main()
