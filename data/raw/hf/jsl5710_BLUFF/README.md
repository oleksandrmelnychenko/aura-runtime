---
license: cc-by-nc-sa-4.0
task_categories:
  - text-classification
language:
  - af
  - ar
  - az
  - bn
  - bs
  - bg
  - ca
  - cs
  - da
  - de
  - el
  - en
  - et
  - fa
  - fi
  - fr
  - gu
  - ha
  - he
  - hi
  - hr
  - hu
  - id
  - it
  - ja
  - ka
  - ko
  - ku
  - lv
  - lt
  - ml
  - mr
  - mk
  - ms
  - my
  - ne
  - nl
  - "no"
  - pa
  - pl
  - pt
  - ro
  - ru
  - si
  - sk
  - so
  - es
  - sq
  - sr
  - sw
  - sv
  - ta
  - te
  - tl
  - th
  - tr
  - uk
  - ur
  - vi
  - zh
pretty_name: "BLUFF: Benchmark for Linguistic Understanding of Fake-news Forensics"
size_categories:
  - 100K<n<1M
tags:
  - fake-news-detection
  - multilingual
  - misinformation
  - authorship-attribution
  - cross-lingual
  - low-resource-languages
  - benchmark
---

# BLUFF: Benchmark for Linguistic Understanding of Fake-news Forensics

**BLUFF** is a comprehensive multilingual benchmark for fake news detection spanning **78 languages** with over **201K samples**. It uniquely covers both high-resource "big-head" (20) and low-resource "long-tail" (58) languages, addressing critical gaps in multilingual disinformation research.

> **Paper:** *BLUFF: A Benchmark for Linguistic Understanding of Fake-news Forensics*
> **Authors:** Jason Lucas, Dongwon Lee
> **Affiliation:** PIKE Research Lab, Penn State University

| Resource | Link |
|----------|------|
| GitHub | [github.com/jsl5710/BLUFF](https://github.com/jsl5710/BLUFF) |
| Paper | Under review |

---

## Key Features

- **78 Languages** across 12 language families, 10 script types, and 4 syntactic orders
- **201K+ Samples** combining human-written (122K) and LLM-generated (78K) content
- **4 Content Types:** Human-Written (HWT), Machine-Generated (MGT), Machine-Translated (MTT), and Human-AI Hybrid (HAT)
- **39 Textual Modification Techniques:** 36 manipulation tactics for fake news + 3 AI-editing strategies for real news
- **19 Diverse mLLMs** used for content generation
- **4 Benchmark Tasks** with standardized train/val/test splits
- **6 Training Settings:** Multilingual, 4 cross-lingual variants, and external evaluation

---

## Dataset Structure

This repository is organized into four main directories:

```
data/
├── meta_data/                          # Metadata for all samples
│   ├── metadata_human_written.csv    #   Human-written sample metadata (122K rows)
│   └── metadata_ai_generated.csv     #   AI-generated sample metadata (78K rows)
│
├── processed/                          # Cleaned, extracted text data (ready to use)
│   └── generated_data/
│       ├── ai_generated/             #   Per-model, per-language CSV files
│       │   ├── gpt-4.1/{lang}/data.csv
│       │   ├── gemini-2.0-flash/{lang}/data.csv
│       │   ├── CohereForAI_aya-expanse-32b/{lang}/data.csv
│       │   └── ...  (19 models total)
│       └── human_written/            #   Per-organization, per-language CSV files
│           ├── {Organization}/{lang}/data.csv
│           └── ...
│
├── raw/                                # Original source data before processing
│   └── source_data/
│       ├── human/                    #   Raw human-written fact-check articles
│       ├── sd_eng_x_f/               #   Source data: English→X, fake news
│       ├── sd_eng_x_r/               #   Source data: English→X, real news
│       ├── sd_x_eng_f/               #   Source data: X→English, fake news
│       └── sd_x_eng_r/               #   Source data: X→English, real news
│
└── splits/                             # Evaluation split definitions (train + val only)
    └── evaluation/
        ├── multilingual/             #   Train on all languages
        ├── cross_lingual_bighead_longtail/  #  Train big-head, eval long-tail
        ├── cross_lingual_family/     #   Per language family (14 families)
        │   ├── Indo_European/
        │   ├── Afro_Asiatic/
        │   └── ...
        ├── cross_lingual_script/     #   Per script type (11 scripts)
        │   ├── Latin/
        │   ├── Cyrillic/
        │   └── ...
        ├── cross_lingual_syntax/     #   Per syntactic word order (4 types)
        │   ├── SVO/
        │   ├── SOV/
        │   ├── VSO/
        │   └── Free/
        ├── external_evaluation/      #   Held-out external dataset evaluation
        └── small_test_50/            #   Smaller balanced subsets (50 per class per lang)
```

> **Note:** Test splits are held out and not publicly released to preserve benchmark integrity. Only `train.json`, `val.json`, and `stats.json` are provided in each split directory. To evaluate on the test set, please contact the authors.

---

## Benchmark Tasks

| Task | Description | Classes | Metric |
|------|-------------|---------|--------|
| **Task 1** | Binary Veracity Classification | Real / Fake | F1 (macro) |
| **Task 2** | Multi-class Veracity Classification | Real / Fake × Source Type | F1 (macro) |
| **Task 3** | Binary Authorship Detection | Human / Machine | F1 (macro) |
| **Task 4** | Multi-class Authorship Attribution | HWT / MGT / MTT / HAT | F1 (macro) |

---

## Data Fields

### Processed Data (CSV files in `data/processed/`)

The processed CSV files contain the extracted, cleaned text data ready for model training:

| Column | Description |
|--------|-------------|
| `uuid` | Unique sample identifier |
| `article_content` | Full article text in the original language |
| `translated_content` | English translation of the article |
| `post_content` | Social media post version in the original language |
| `translated_post` | English translation of the post |
| `language` | ISO 639-3 language code |
| `translation_directionality` | Generation direction (`eng_x` or `x_eng`) |
| `model` | Generating model name |
| `veracity` | Veracity label (`fake_news` or `real_news`) |
| `technique_keys` | Manipulation technique IDs applied |
| `degree` | Edit intensity (`minor`, `moderate`, `critical`) |
| `source_dataset` | Original source dataset |
| `HAT` | Whether sample is Human-AI Hybrid (`y`/`n`) |
| `MGT` | Whether sample is Machine-Generated (`y`/`n`) |
| `MTT` | Whether sample is Machine-Translated (`y`/`n`) |
| `HWT` | Whether sample is Human-Written (`y`/`n`) |

### Metadata (CSV files in `data/meta_data/`)

Rich metadata for each sample including quality filtering results:

**Human-written metadata** (`metadata_human_written.csv`): 33 columns including `uuid`, `language`, `veracity`, `organization`, `country`, `category`, `topic`, `source_content_type`, etc.

**AI-generated metadata** (`metadata_ai_generated.csv`): 29 columns including `uuid`, `language`, `language_category` (head/tail), `transform_technique`, `technique_keys`, `degree`, `veracity`, `mLLM`, `mPURIFY` status, etc.

### Split Files (JSON files in `data/splits/`)

Each split directory contains:
- **`train.json`** — List of UUIDs for training samples
- **`val.json`** — List of UUIDs for validation samples
- **`stats.json`** — Sample counts per split

The UUIDs in the split files correspond to the `uuid` column in the metadata and processed CSV files. To build a dataset for a specific task and setting, join the split UUIDs with the metadata and processed data.

---

## Quick Start

### Option 1: Download Specific Files

```python
from huggingface_hub import hf_hub_download

# Download metadata
meta_path = hf_hub_download(
    repo_id="jsl5710/BLUFF",
    repo_type="dataset",
    filename="data/meta_data/metadata_ai_generated.csv"
)

# Download processed data for a specific model and language
data_path = hf_hub_download(
    repo_id="jsl5710/BLUFF",
    repo_type="dataset",
    filename="data/processed/generated_data/ai_generated/gpt-4.1/eng/data.csv"
)

# Download a split definition
split_path = hf_hub_download(
    repo_id="jsl5710/BLUFF",
    repo_type="dataset",
    filename="data/splits/evaluation/multilingual/train.json"
)
```

### Option 2: Download Entire Dataset

```python
from huggingface_hub import snapshot_download

# Download everything (~3.9 GB)
snapshot_download(
    repo_id="jsl5710/BLUFF",
    repo_type="dataset",
    local_dir="./BLUFF_data"
)
```

### Option 3: Download Specific Subdirectories

```python
from huggingface_hub import snapshot_download

# Download only processed data
snapshot_download(
    repo_id="jsl5710/BLUFF",
    repo_type="dataset",
    local_dir="./BLUFF_data",
    allow_patterns="data/processed/**"
)

# Download only metadata and splits
snapshot_download(
    repo_id="jsl5710/BLUFF",
    repo_type="dataset",
    local_dir="./BLUFF_data",
    allow_patterns=["data/meta_data/**", "data/splits/**"]
)
```

### Building a Training Dataset

```python
import json
import pandas as pd
from huggingface_hub import hf_hub_download

# 1. Load split definition (e.g., multilingual training)
split_path = hf_hub_download("jsl5710/BLUFF", "data/splits/evaluation/multilingual/train.json", repo_type="dataset")
with open(split_path) as f:
    train_uuids = set(json.load(f))

# 2. Load metadata
meta_path = hf_hub_download("jsl5710/BLUFF", "data/meta_data/metadata_ai_generated.csv", repo_type="dataset")
meta_ai = pd.read_csv(meta_path)

meta_path = hf_hub_download("jsl5710/BLUFF", "data/meta_data/metadata_human_written.csv", repo_type="dataset")
meta_hw = pd.read_csv(meta_path)

# 3. Filter to training split
train_ai = meta_ai[meta_ai["uuid"].isin(train_uuids)]
train_hw = meta_hw[meta_hw["uuid"].isin(train_uuids)]

print(f"Training samples - AI generated: {len(train_ai)}, Human written: {len(train_hw)}")
```

---

## Language Coverage

BLUFF covers **78 languages** organized into big-head (high-resource) and long-tail (low-resource) categories:

| Category | Count | Examples |
|----------|-------|---------|
| **Big-Head** | 20 | English, Spanish, French, Chinese, Arabic, Hindi, Portuguese, Russian, German, Japanese, Korean, Turkish, Vietnamese, Thai, Indonesian, Polish, Dutch, Italian, Swedish, Czech |
| **Long-Tail** | 58 | Yoruba, Amharic, Khmer, Lao, Quechua, Malagasy, Haitian Creole, Jamaican Patois, Guarani, Kurdish, Somali, Oromo, Nepali, Sinhala, ... |

**Language Families (12):** Indo-European, Sino-Tibetan, Afro-Asiatic, Niger-Congo, Austronesian, Dravidian, Turkic, Uralic, Koreanic, Japonic, Tai-Kadai, Austroasiatic

**Scripts (10):** Latin, Cyrillic, Arabic, Devanagari, CJK, Thai, Ethiopic, Khmer, Bengali, Georgian

---

## Generation Models (19)

The AI-generated content in BLUFF was produced using 19 diverse multilingual LLMs:

| Provider | Models |
|----------|--------|
| OpenAI | GPT-4.1, o1 |
| Google | Gemini 1.5 Flash, Gemini 1.5 Pro, Gemini 2.0 Flash, Gemini 2.0 Flash Thinking |
| Meta | Llama 3.3 70B, Llama 4 Maverick 17B, Llama 4 Scout 17B |
| DeepSeek | DeepSeek-R1, DeepSeek-R1 Turbo, DeepSeek-R1-Distill-Llama-70B |
| Cohere | Aya Expanse 32B |
| Alibaba | Qwen3-Next 80B, QwQ-32B |
| Mistral | Mistral Large |
| Microsoft | Phi-4 Multimodal |

---

## Training Settings

BLUFF provides pre-defined splits for 6 experimental settings:

| Setting | Directory | Description |
|---------|-----------|-------------|
| **Multilingual** | `multilingual/` | Train on all 78 languages, evaluate overall and per big-head/long-tail |
| **Cross-lingual (Head→Tail)** | `cross_lingual_bighead_longtail/` | Train on big-head languages, evaluate transfer to long-tail |
| **Cross-lingual (Family)** | `cross_lingual_family/{Family}/` | Leave-one-family-out: train on one family, evaluate on others |
| **Cross-lingual (Script)** | `cross_lingual_script/{Script}/` | Leave-one-script-out: train on one script, evaluate on others |
| **Cross-lingual (Syntax)** | `cross_lingual_syntax/{Order}/` | Leave-one-syntax-out: train on one word order, evaluate on others |
| **External Evaluation** | `external_evaluation/` | Evaluate on held-out external datasets |

---

## Dataset Statistics

| Subset | Samples |
|--------|---------|
| Human-Written (HWT) | ~122,000 |
| AI-Generated (MGT + MTT + HAT) | ~78,000 |
| **Total** | **~201,000** |
| Multilingual train split | 51,376 |
| Multilingual val split | 6,422 |

---

## Ethical Considerations

BLUFF contains realistic synthetic disinformation created solely for research purposes. By accessing this dataset, you agree to:

1. Use the data solely for research aimed at improving disinformation detection
2. Not redistribute generated fake news content outside research contexts
3. Cite the dataset in any publications using BLUFF
4. Report any misuse discovered to the authors

All generated content includes metadata identifying it as synthetic research material.

---

## Citation

Paper currently under review. Citation will be provided upon acceptance.

---

## License

- **Code:** [MIT License](https://github.com/jsl5710/BLUFF/blob/main/LICENSE)
- **Dataset:** [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)

---

## Contact

- **Jason Lucas** — [jsl5710@psu.edu](mailto:jsl5710@psu.edu)
- **Dongwon Lee** — [dongwon@psu.edu](mailto:dongwon@psu.edu)
- **PIKE Research Lab** — Penn State University, College of IST
