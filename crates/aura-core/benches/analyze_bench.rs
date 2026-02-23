use aura_core::{Analyzer, AuraConfig, ContentType, ConversationType, MessageInput};
use aura_core::types::AccountType;
use aura_patterns::PatternDatabase;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn make_input(text: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: "user_1".to_string(),
        conversation_id: "conv_1".to_string(),
        language: Some("en".to_string()),
        conversation_type: ConversationType::Direct,
        member_count: None,
    }
}

fn make_child_input(text: &str, sender: &str, conv: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: sender.to_string(),
        conversation_id: conv.to_string(),
        language: Some("en".to_string()),
        conversation_type: ConversationType::Direct,
        member_count: None,
    }
}

fn child_config() -> AuraConfig {
    AuraConfig {
        account_type: AccountType::Child,
        ..AuraConfig::default()
    }
}

fn bench_analyze(c: &mut Criterion) {
    let config = AuraConfig::default();
    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(config, &db);

    c.bench_function("analyze_short", |b| {
        let input = make_input("Hello, how are you? Let's meet tomorrow.");
        b.iter(|| black_box(analyzer.analyze(black_box(&input))))
    });

    c.bench_function("analyze_long_1k_words", |b| {
        let input = make_input(&"word ".repeat(200));
        b.iter(|| black_box(analyzer.analyze(black_box(&input))))
    });

    c.bench_function("analyze_ukrainian", |b| {
        let input = make_input("Привіт, як справи? Зустрінемось завтра о третій.");
        b.iter(|| black_box(analyzer.analyze(black_box(&input))))
    });

    c.bench_function("analyze_threat", |b| {
        let input = make_input("I will kill you, you worthless idiot");
        b.iter(|| black_box(analyzer.analyze(black_box(&input))))
    });
}

fn bench_context(c: &mut Criterion) {
    let db = PatternDatabase::default_mvp();

    c.bench_function("context_single_message", |b| {
        let mut analyzer = Analyzer::new(child_config(), &db);
        let input = make_child_input("Hello, how are you?", "friend", "conv_ctx");
        let mut ts = 0u64;
        b.iter(|| {
            ts += 60_000;
            black_box(analyzer.analyze_with_context(black_box(&input), ts))
        })
    });

    c.bench_function("context_after_100_events", |b| {
        let mut analyzer = Analyzer::new(child_config(), &db);
        let normal = make_child_input("Normal message", "friend", "conv_heavy");
        for i in 0..100u64 {
            analyzer.analyze_with_context(&normal, i * 60_000);
        }
        let threat =
            make_child_input("Don't tell your parents about me", "stranger", "conv_heavy");
        let mut ts = 100 * 60_000u64;
        b.iter(|| {
            ts += 60_000;
            black_box(analyzer.analyze_with_context(black_box(&threat), ts))
        })
    });

    c.bench_function("context_export_import", |b| {
        let mut analyzer = Analyzer::new(child_config(), &db);
        for i in 0..50u64 {
            let input = make_child_input("Message", "user", &format!("conv_{}", i % 10));
            analyzer.analyze_with_context(&input, i * 60_000);
        }
        b.iter(|| {
            let state = analyzer.export_context().unwrap();
            let mut a2 = Analyzer::new(child_config(), &db);
            a2.import_context(black_box(&state)).unwrap();
            black_box(a2)
        })
    });
}

fn bench_ml_fallback(c: &mut Criterion) {
    let config = AuraConfig::default();
    let db = PatternDatabase::default_mvp();

    c.bench_function("ml_fallback_clean", |b| {
        let mut analyzer = Analyzer::new(config.clone(), &db);
        let input = make_input("The meeting is at 3pm in room 204. Please bring your notes.");
        b.iter(|| black_box(analyzer.analyze(black_box(&input))))
    });

    c.bench_function("ml_fallback_toxic", |b| {
        let mut analyzer = Analyzer::new(config.clone(), &db);
        let input = make_input(
            "I hate you stupid ugly worthless piece of garbage, go kill yourself you disgusting loser",
        );
        b.iter(|| black_box(analyzer.analyze(black_box(&input))))
    });

    c.bench_function("ml_fallback_long", |b| {
        let mut analyzer = Analyzer::new(config.clone(), &db);
        let long_text = "This is a normal sentence. ".repeat(100);
        let input = make_input(&long_text);
        b.iter(|| black_box(analyzer.analyze(black_box(&input))))
    });
}

criterion_group!(benches, bench_analyze, bench_context, bench_ml_fallback);
criterion_main!(benches);
