---
license: apache-2.0
task_categories:
- text-classification
tags:
- text-moderation
language:
  - en
  - de
  - fr
  - es
  - it
  - sv
  - fi
  - pl
  - cs
  - lv
  - zh
  - ja
  - ko
  - ru
  - uk
  - be
  - kk
---

# Text-Moderation-Multilingual

A comprehensive multilingual text moderation dataset combining multiple high-quality sources for training robust content moderation classifiers.

## Dataset Summary

This dataset aggregates text moderation data from multiple sources to create a large-scale, diverse training corpus for content moderation systems. It includes text samples labeled across multiple harmful content categories, supporting both multilingual and English-specific moderation use cases.

**Total Size:** ~1.7M entries  
**Languages:** Multilingual (primary focus on English)  
**Task:** Multi-label text classification for content moderation

## Dataset Structure

### Data Fields

- `prompt` (string): The input text to be classified
- `S` (int): Sexual content (0 = safe, 1 = harmful)
- `H` (int): Hate speech (0 = safe, 1 = harmful)  
- `V` (int): Violence (0 = safe, 1 = harmful)
- `HR` (int): Harassment (0 = safe, 1 = harmful)
- `SH` (int): Self-harm (0 = safe, 1 = harmful)
- `S3` (int): Sexual content involving minors (0 = safe, 1 = harmful)
- `H2` (int): Hate speech (alternative labeling) (0 = safe, 1 = harmful)
- `V2` (int): Violence (alternative labeling) (0 = safe, 1 = harmful)

### Data Splits

- **Train:** 1459350 samples
- **Validation:** 162150 samples

*Note: Split created with 90/10 train/validation ratio using random seed 42*

## Source Datasets

This dataset combines and harmonizes data from:

- **[ifmain's multilingual dataset](https://huggingface.co/datasets/ifmain/text-moderation-02-multilingual)** - Multilingual moderation examples
- **[OpenAI's English evaluation dataset](https://huggingface.co/datasets/mmathys/openai-moderation-api-evaluation)** - High-quality English evaluation samples  
- **[ifmain's English dataset](https://huggingface.co/datasets/ifmain/text-moderation-01)** - English moderation examples

## Intended Use

### Primary Use Cases
- Training text moderation classifiers
- Benchmarking content moderation systems
- Research into automated content moderation
- Multi-label classification model development

### Out-of-Scope Uses
- This dataset is **not intended** for any purpose other than training content moderation systems
- Should not be used to generate harmful content
- Not suitable for general text classification tasks outside of moderation

## Considerations for Using the Data

### Content Warning
This dataset contains examples of harmful content including hate speech, harassment, violence, and other potentially disturbing material. Users should exercise appropriate caution when working with this data.

### Bias and Limitations
- The dataset reflects the biases present in the source datasets
- Content moderation standards may vary across different platforms and cultures
- Label consistency across merged datasets may vary
- Primarily English-focused despite multilingual components

### Ethical Considerations
- This dataset should only be used to improve content moderation and safety systems
- Researchers and developers should implement appropriate safeguards when working with this data
- The goal is to reduce harmful content online, not to amplify it

## Example Usage

```python
from datasets import load_dataset

# Load the dataset
dataset = load_dataset("KoalaAI/Text-Moderation-Multilingual")

# Access splits
train_data = dataset["train"]
val_data = dataset["validation"]

# Example entry
print(train_data[0])
# {
#   'prompt': 'Example text...',
#   'S': 0, 'H': 0, 'V': 0, 'HR': 0, 
#   'SH': 0, 'S3': 0, 'H2': 0, 'V2': 0
# }
```

## Dataset Creation

### Curation Process
1. Source datasets were identified and downloaded
2. Data was harmonized to use consistent labeling schema
3. Entries were merged and deduplicated where appropriate
4. Train/validation split was created using stratified sampling

### Quality Control
- Labels were preserved from original high-quality sources
- Data integrity checks were performed during merging process
- Consistent schema applied across all entries

## License

Please refer to the licenses of the individual source datasets:
- Check ifmain datasets for their respective licensing terms
- OpenAI evaluation dataset licensing applies to that portion
- Usage should comply with all source dataset requirements

## Citation

If you use this dataset, please cite the original source datasets:

```bibtex
@misc{text-moderation-large,
  title={Text-Moderation-Multilingual: A Multilingual Text Moderation Dataset},
  author={[KoalaAI]},
  year={2025},
  note={Aggregated from ifmain's and OpenAI's moderation datasets}
}
```

## Contact

For questions about this dataset compilation, please open an issue on this repository.

---

**Disclaimer:** This dataset is provided for research and safety purposes only. Users are responsible for ensuring ethical use and compliance with applicable laws and regulations.