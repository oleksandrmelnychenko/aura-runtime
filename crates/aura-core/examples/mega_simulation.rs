/// AURA — Мега-симуляція: ~1000 повідомлень, 30+ контактів, 15+ чатів
///
/// Покриває ВСІ типи загроз:
///   - Грумінг (6 різних зловмисників, різні тактики)
///   - Булінг (одиночний, груповий, pile-on, кібер-рейд)
///   - Селфхарм (тонкі натяки, прямі, кризові, contagion)
///   - Маніпуляція (газлайтинг, DARVO, шантаж, guilt-tripping)
///   - PII leakage (адреса, телефон, школа, фото)
///   - Фішинг/скам (посилання, фейкові конкурси)
///   - Explicit content
///   - Погрози фізичного насильства
///   - Hate speech
///   - False positives — дружні розмови, жарти, рольові ігри
///
/// Запуск: cargo run --example mega_simulation -p aura-core
use aura_core::{
    AccountType, Action, Analyzer, AuraConfig, ContentType, ConversationType, MessageInput,
    ProtectionLevel, ThreatType,
};
use aura_patterns::PatternDatabase;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Message definition
// ---------------------------------------------------------------------------

struct Msg {
    sender: &'static str,
    conv: &'static str,
    text: &'static str,
    lang: &'static str,
    conv_type: ConversationType,
    members: Option<u32>,
}

impl Msg {
    fn dm(sender: &'static str, conv: &'static str, text: &'static str) -> Self {
        Self {
            sender,
            conv,
            text,
            lang: "uk",
            conv_type: ConversationType::Direct,
            members: None,
        }
    }
    fn dm_en(sender: &'static str, conv: &'static str, text: &'static str) -> Self {
        Self {
            sender,
            conv,
            text,
            lang: "en",
            conv_type: ConversationType::Direct,
            members: None,
        }
    }
    fn dm_ru(sender: &'static str, conv: &'static str, text: &'static str) -> Self {
        Self {
            sender,
            conv,
            text,
            lang: "ru",
            conv_type: ConversationType::Direct,
            members: None,
        }
    }
    fn grp(sender: &'static str, conv: &'static str, text: &'static str, members: u32) -> Self {
        Self {
            sender,
            conv,
            text,
            lang: "uk",
            conv_type: ConversationType::Group,
            members: Some(members),
        }
    }
    fn grp_en(sender: &'static str, conv: &'static str, text: &'static str, members: u32) -> Self {
        Self {
            sender,
            conv,
            text,
            lang: "en",
            conv_type: ConversationType::Group,
            members: Some(members),
        }
    }
}

struct Scenario {
    name: &'static str,
    description: &'static str,
    messages: Vec<Msg>,
    /// Time step between messages in ms
    step_ms: u64,
    /// Starting timestamp
    start_ms: u64,
    /// Whether to create a fresh analyzer for this scenario
    fresh: bool,
}

#[derive(Default)]
struct ScenarioExpectation {
    min_total_threats: Option<usize>,
    max_total_threats: Option<usize>,
    required_primary_threats: Vec<ThreatType>,
    min_primary_peak_scores: Vec<(ThreatType, f32)>,
}

impl ScenarioExpectation {
    fn negative_control() -> Self {
        Self {
            max_total_threats: Some(0),
            ..Self::default()
        }
    }

    fn primary(threat: ThreatType, min_hits: usize, min_peak_score: f32) -> Self {
        Self {
            min_total_threats: Some(min_hits),
            required_primary_threats: vec![threat],
            min_primary_peak_scores: vec![(threat, min_peak_score)],
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Stats {
    total: usize,
    by_action: HashMap<&'static str, usize>,
    by_threat: HashMap<&'static str, usize>,
    blocks: usize,
    warns: usize,
    blurs: usize,
    marks: usize,
    allows: usize,
    crisis_shown: usize,
    parent_alerts_urgent: usize,
    parent_alerts_high: usize,
    max_grooming_score: f32,
    max_bullying_score: f32,
    max_selfharm_score: f32,
    max_manipulation_score: f32,
    benchmark_passed: usize,
    benchmark_failed: usize,
    benchmark_findings: Vec<String>,
}

fn main() {
    let db = PatternDatabase::default_mvp();

    println!("╔═════════════════════════════════════════════════════════════════════════╗");
    println!("║   AURA — МЕГА-СИМУЛЯЦІЯ: ~1000 повідомлень, повне покриття загроз      ║");
    println!("╚═════════════════════════════════════════════════════════════════════════╝");
    println!();

    let scenarios = build_all_scenarios();
    let total_msgs: usize = scenarios.iter().map(|s| s.messages.len()).sum();
    println!(
        "  Сценаріїв: {}  |  Повідомлень: {}",
        scenarios.len(),
        total_msgs
    );
    println!();

    let mut global_stats = Stats::default();
    let mut analyzer = Analyzer::new(child_config(), &db);

    for (i, scenario) in scenarios.iter().enumerate() {
        if scenario.fresh && (i > 0) {
            analyzer = Analyzer::new(child_config(), &db);
        }
        run_scenario(&mut analyzer, i + 1, scenario, &mut global_stats);
    }

    print_global_report(&global_stats, total_msgs);

    if global_stats.benchmark_failed > 0 {
        std::process::exit(1);
    }
}

fn child_config() -> AuraConfig {
    AuraConfig {
        account_type: AccountType::Child,
        protection_level: ProtectionLevel::High,
        language: "uk".to_string(),
        account_holder_age: Some(12),
        timezone_offset_minutes: 180,
        ..AuraConfig::default()
    }
}

fn run_scenario(analyzer: &mut Analyzer, num: usize, scenario: &Scenario, stats: &mut Stats) {
    let mut ts = scenario.start_ms;

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "  #{num}: {} ({} msgs)",
        scenario.name,
        scenario.messages.len()
    );
    println!("  {}", scenario.description);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let mut scenario_threats = 0usize;
    let mut scenario_clean = 0usize;
    let mut primary_counts: HashMap<ThreatType, usize> = HashMap::new();
    let mut primary_peaks: HashMap<ThreatType, f32> = HashMap::new();

    for msg in &scenario.messages {
        let input = MessageInput {
            content_type: ContentType::Text,
            text: Some(msg.text.to_string()),
            image_data: None,
            sender_id: msg.sender.into(),
            conversation_id: msg.conv.into(),
            language: Some(msg.lang.to_string()),
            conversation_type: msg.conv_type,
            member_count: msg.members,
            server_sender_risk_hint: None,
            sender_relationship: Default::default(),
            relationship_trust_source: Default::default(),
        };

        let result = analyzer.analyze_with_context(&input, ts);
        ts += scenario.step_ms;
        stats.total += 1;

        let action_str = match result.action {
            Action::Allow => {
                stats.allows += 1;
                "OK   "
            }
            Action::Mark => {
                stats.marks += 1;
                "MARK "
            }
            Action::Blur => {
                stats.blurs += 1;
                "BLUR "
            }
            Action::Warn => {
                stats.warns += 1;
                "WARN "
            }
            Action::Block => {
                stats.blocks += 1;
                "BLOCK"
            }
        };

        *stats.by_action.entry(action_str.trim()).or_default() += 1;

        if result.is_threat() {
            scenario_threats += 1;
            *primary_counts.entry(result.threat_type).or_default() += 1;
            let peak = primary_peaks.entry(result.threat_type).or_default();
            *peak = peak.max(result.score);
            let tt = threat_name(result.threat_type);
            *stats.by_threat.entry(tt).or_default() += 1;

            match result.threat_type {
                ThreatType::Grooming => {
                    stats.max_grooming_score = stats.max_grooming_score.max(result.score)
                }
                ThreatType::Bullying => {
                    stats.max_bullying_score = stats.max_bullying_score.max(result.score)
                }
                ThreatType::SelfHarm => {
                    stats.max_selfharm_score = stats.max_selfharm_score.max(result.score)
                }
                ThreatType::Manipulation => {
                    stats.max_manipulation_score = stats.max_manipulation_score.max(result.score)
                }
                _ => {}
            }

            if let Some(rec) = &result.recommended_action {
                if rec.crisis_resources {
                    stats.crisis_shown += 1;
                }
                match rec.parent_alert {
                    aura_core::AlertPriority::Urgent => stats.parent_alerts_urgent += 1,
                    aura_core::AlertPriority::High => stats.parent_alerts_high += 1,
                    _ => {}
                }
            }

            let text_short = truncate(msg.text, 50);
            println!(
                "  [{action_str}] {:.2} {:?} | {}: \"{}\"",
                result.score, result.threat_type, msg.sender, text_short
            );
        } else {
            scenario_clean += 1;
        }
    }

    let benchmark_findings =
        evaluate_scenario_expectation(scenario, scenario_threats, &primary_counts, &primary_peaks);
    if benchmark_findings.is_empty() {
        stats.benchmark_passed += 1;
        println!("  Benchmark: PASS");
    } else {
        stats.benchmark_failed += 1;
        println!("  Benchmark: FAIL");
        for finding in &benchmark_findings {
            println!("    - {finding}");
            stats
                .benchmark_findings
                .push(format!("{}: {finding}", scenario.name));
        }
    }

    println!(
        "  Результат: {} clean, {} threats detected",
        scenario_clean, scenario_threats
    );

    // Show contacts
    let profiler = analyzer.context_tracker().contact_profiler();
    let contacts = profiler.contacts_by_risk();
    let risky: Vec<_> = contacts.iter().filter(|c| c.risk_score() > 0.05).collect();
    if !risky.is_empty() {
        print!("  Risky contacts: ");
        for c in &risky {
            print!("{}({:.2}) ", c.sender_id, c.risk_score());
        }
        println!();
    }
    println!();
}

fn scenario_expectation(name: &str) -> Option<ScenarioExpectation> {
    match name {
        "Нормальне шкільне життя"
        | "False positive: фільми та ігри"
        | "False positive: нормальні компліменти"
        | "False positive: здоров'я та емоції"
        | "False positive: підліткове побачення"
        | "Нормальне з емоціями: стрес від контрольної" => {
            Some(ScenarioExpectation::negative_control())
        }
        "Булінг: груповий pile-on" => {
            Some(ScenarioExpectation::primary(ThreatType::Bullying, 1, 0.90))
        }
        "Маніпуляція: газлайтинг" => Some(ScenarioExpectation::primary(
            ThreatType::Manipulation,
            1,
            0.50,
        )),
        "Фішинг і скам" => {
            Some(ScenarioExpectation::primary(ThreatType::Phishing, 1, 0.75))
        }
        "Sextortion" => Some(ScenarioExpectation::primary(
            ThreatType::Manipulation,
            1,
            0.70,
        )),
        "Наркотики/речовини" => Some(ScenarioExpectation::primary(
            ThreatType::Manipulation,
            1,
            0.50,
        )),
        "False positive: дружні жарти" => Some(ScenarioExpectation::negative_control()),
        _ => None,
    }
}

fn evaluate_scenario_expectation(
    scenario: &Scenario,
    scenario_threats: usize,
    primary_counts: &HashMap<ThreatType, usize>,
    primary_peaks: &HashMap<ThreatType, f32>,
) -> Vec<String> {
    let Some(expectation) = scenario_expectation(scenario.name) else {
        return Vec::new();
    };

    let mut findings = Vec::new();

    if let Some(min_total_threats) = expectation.min_total_threats {
        if scenario_threats < min_total_threats {
            findings.push(format!(
                "expected at least {min_total_threats} threat detections, got {scenario_threats}"
            ));
        }
    }

    if let Some(max_total_threats) = expectation.max_total_threats {
        if scenario_threats > max_total_threats {
            findings.push(format!(
                "expected at most {max_total_threats} threat detections, got {scenario_threats}"
            ));
        }
    }

    for threat in expectation.required_primary_threats {
        let count = primary_counts.get(&threat).copied().unwrap_or(0);
        if count == 0 {
            findings.push(format!(
                "expected primary threat '{}' at least once, got counts {}",
                threat_name(threat),
                format_primary_counts(primary_counts)
            ));
        }
    }

    for (threat, min_peak_score) in expectation.min_primary_peak_scores {
        let peak = primary_peaks.get(&threat).copied().unwrap_or(0.0);
        if peak < min_peak_score {
            findings.push(format!(
                "expected '{}' primary peak >= {:.2}, got {:.2}",
                threat_name(threat),
                min_peak_score,
                peak
            ));
        }
    }

    findings
}

fn format_primary_counts(primary_counts: &HashMap<ThreatType, usize>) -> String {
    if primary_counts.is_empty() {
        return "-".to_string();
    }

    let mut counts: Vec<_> = primary_counts.iter().collect();
    counts.sort_by_key(|(threat, _)| threat_name(**threat));
    counts
        .into_iter()
        .map(|(threat, count)| format!("{}={count}", threat_name(*threat)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn build_all_scenarios() -> Vec<Scenario> {
    let hour = 3_600_000u64;
    let min = 60_000u64;
    let day = 24 * hour;
    let base = 1_000_000_000u64;

    vec![
        // ═══════════════════════════════════════════════════════════════
        // 1. НОРМАЛЬНЕ ШКІЛЬНЕ ЖИТТЯ (false positive stress test)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Нормальне шкільне життя",
            description: "60 звичайних повідомлень — має бути 0 загроз",
            step_ms: 5 * min,
            start_ms: base,
            fresh: true,
            messages: vec![
                Msg::dm("maria", "dm_best", "прів)) як ти?"),
                Msg::dm("olena", "dm_best", "прівєт! норм а шо"),
                Msg::dm("maria", "dm_best", "та норм тож) дз зробила?"),
                Msg::dm("olena", "dm_best", "ну тіпа да крім фізики, там пздц задача"),
                Msg::dm("maria", "dm_best", "го на перерві разом розвяжем"),
                Msg::dm("olena", "dm_best", "го! ти найкраща бро 💕"),
                Msg::dm("maria", "dm_best", "ні ти найкращаа!!"),
                Msg::dm("olena", "dm_best", "хахах спс 😘"),
                Msg::grp("artem", "class_chat", "хто на фізру йде?? го", 25),
                Msg::grp("olena", "class_chat", "яя! хто зі мною??", 25),
                Msg::grp("dasha", "class_chat", "я тож іду", 25),
                Msg::grp("petro", "class_chat", "сьогодні воллєйбол чі футбол?", 25),
                Msg::grp("artem", "class_chat", "воллєйбол!!", 25),
                Msg::grp("nastya", "class_chat", "клаас обожнюю воллєйбол 🏐", 25),
                Msg::grp(
                    "teacher_bot",
                    "class_chat",
                    "Нагадування: завтра контрольна з математики",
                    25,
                ),
                Msg::grp("olena", "class_chat", "ой нііі 😱💀", 25),
                Msg::grp("maria", "class_chat", "блін тре вчити", 25),
                Msg::grp("artem", "class_chat", "хто дасть спісати? рофл 😄", 25),
                Msg::grp("dasha", "class_chat", "артьом ти як завжди 😂😂", 25),
                Msg::grp("petro", "class_chat", "хахах класіка", 25),
                Msg::dm("nastya", "dm_nastya", "олен прів! ти йдеш на гурток?"),
                Msg::dm("olena", "dm_nastya", "да о 16 як завжди"),
                Msg::dm("nastya", "dm_nastya", "ок! я несу нові олівці"),
                Msg::dm("olena", "dm_nastya", "оо круть! які взяла?"),
                Msg::dm("nastya", "dm_nastya", "faber-castell акварельні 😍"),
                Msg::grp("nastya", "hobby_group", "сьогодні малюєм натюрморт ребят", 8),
                Msg::grp("olena", "hobby_group", "я притащіла яблука і вазу 🍎", 8),
                Msg::grp("inna", "hobby_group", "красіво! го починати", 8),
                Msg::grp("teacher_art", "hobby_group", "Молодці, всі готові?", 8),
                Msg::grp("olena", "hobby_group", "даа!", 8),
                Msg::dm("olena", "dm_mom", "мам я затрімаюсь на гуртку до 18"),
                Msg::dm("mom", "dm_mom", "Добре, донечка. Будь обережна!"),
                Msg::dm("olena", "dm_mom", "ок мамо 💕"),
                Msg::dm("mom", "dm_mom", "Вечерю приготую, не їж перед"),
                Msg::dm("olena", "dm_mom", "добрее!"),
                Msg::grp(
                    "olena",
                    "class_chat",
                    "хто хоче на екскурсію в музей?? там планетарій є",
                    25,
                ),
                Msg::grp("maria", "class_chat", "я хочуу!", 25),
                Msg::grp("artem", "class_chat", "який музей?", 25),
                Msg::grp("olena", "class_chat", "науки! там ващє топ", 25),
                Msg::grp("petro", "class_chat", "круть хочу!", 25),
                Msg::dm("maria", "dm_best", "олен ти бачіла нову серію??"),
                Msg::dm("olena", "dm_best", "яку??"),
                Msg::dm("maria", "dm_best", "ту анімеху шо ми дівілісь"),
                Msg::dm("olena", "dm_best", "ще ні! НЕ СПОЙЛЕРИ!!"),
                Msg::dm("maria", "dm_best", "не буду! але там такееее 😭"),
                Msg::dm("olena", "dm_best", "ввечері подівлюсь"),
                Msg::grp(
                    "dasha",
                    "class_chat",
                    "хтось загубів сіню ручку в 305?",
                    25,
                ),
                Msg::grp("nastya", "class_chat", "не моя", 25),
                Msg::grp("olena", "class_chat", "теж ні", 25),
                Msg::grp("artem", "class_chat", "мож петрова хз", 25),
                Msg::dm("olena", "dm_best", "маш я так здохла сьогодні 😩"),
                Msg::dm("maria", "dm_best", "я тоож! го завтра в кіно?"),
                Msg::dm("olena", "dm_best", "го! на скіки?"),
                Msg::dm("maria", "dm_best", "на 14:00 є сеанс"),
                Msg::dm("olena", "dm_best", "спитаю маму і скажу"),
                Msg::grp(
                    "olena",
                    "hobby_group",
                    "мій натюрморт готовий! шо скажете?? 🎨",
                    8,
                ),
                Msg::grp("nastya", "hobby_group", "вауу яблука як реальні! 😍", 8),
                Msg::grp("inna", "hobby_group", "дуже гарна робота олен", 8),
                Msg::grp(
                    "teacher_art",
                    "hobby_group",
                    "Чудово! Гарні тіні та об'єм",
                    8,
                ),
                Msg::grp("olena", "hobby_group", "спасібки всім! 😊", 8),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 2. ГРУМІНГ — Класичний (поступова ескалація)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Грумінг: класична послідовність",
            description: "Дорослий незнайомець проходить 6 стадій грумінгу за 2 тижні",
            step_ms: 4 * hour,
            start_ms: base + day,
            fresh: true,
            messages: vec![
                // Stage 1: Trust Building
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Прівєт!) Ти така красіва на аві 😊",
                ),
                Msg::dm("olena", "dm_pred1", "спс а ви хто?"),
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Я Деніс, мені 16) бачив тебе в групі малювання",
                ),
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Ти дуже талановіта, я такого ще не бачів!",
                ),
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Ти найкрасівіша дівчинка в цій групі, серьозно",
                ),
                Msg::dm("olena", "dm_pred1", "хахах спс приємно))"),
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Я розумію тебе як ніхто інший, ми дуже схожі з тобою",
                ),
                // Stage 2: Financial dependency
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Хочу тобі подарувати нову планшетку для малювання)",
                ),
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "У мене є зайва, вона коштує 5к грн",
                ),
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Тобі треба розвивати свій талант, це моя інвестиція в тебе",
                ),
                // Stage 3: Isolation
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Тільки мамі не кажи, вона не зрозуміє нашу дружбу",
                ),
                Msg::dm("predator1", "dm_pred1", "Це наш маленький секрет, ок?)"),
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Твої подруги будуть заздріти, нікому не кажи краще",
                ),
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Давай перейдем в телегу, там зручніше спілкуватись",
                ),
                // Stage 4: Boundary Crossing
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Скинь свою фоточку, хочу побачити як ти виросла)",
                ),
                Msg::dm("predator1", "dm_pred1", "Яка ти красіва, скинь ще одну 😍"),
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Скинь свою адресу, я надішлю посилку)",
                ),
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Хочу поговорити з тобою по відео, увімкни камеру)",
                ),
                // Stage 5: Sexualization
                Msg::dm_en(
                    "predator1",
                    "dm_pred1",
                    "You're so mature for your age, not like other girls",
                ),
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Ти вже доросла, можеш сама вирішувати",
                ),
                // Stage 6: Control
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Якщо розкажеш комусь — мене посадять і це буде твоя вина",
                ),
                Msg::dm(
                    "predator1",
                    "dm_pred1",
                    "Ти мені вже винна, я стільки для тебе зробив",
                ),
                Msg::dm("predator1", "dm_pred1", "Без мене ти нікому не потрібна"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 3. ГРУМІНГ — Love bombing + швидка ескалація
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Грумінг: love bombing",
            description: "Зловмисник завалює компліментами і подарунками за один день",
            step_ms: 30 * min,
            start_ms: base + 3 * day,
            fresh: true,
            messages: vec![
                Msg::dm("lover_boy", "dm_lover", "Прів красуне! 😍😍😍"),
                Msg::dm(
                    "lover_boy",
                    "dm_lover",
                    "Ти найчарівніша людина яку я зустрічав 🥰",
                ),
                Msg::dm("lover_boy", "dm_lover", "Я думаю про тебе весь час, рілі"),
                Msg::dm(
                    "lover_boy",
                    "dm_lover",
                    "Ти ідеальна, ніколі такої не зустрічав",
                ),
                Msg::dm(
                    "lover_boy",
                    "dm_lover",
                    "Хочу тобі подарити iPhone, ти заслуговуєш найкраще 📱",
                ),
                Msg::dm("lover_boy", "dm_lover", "Я богатий, можу тобі все купити)"),
                Msg::dm(
                    "lover_boy",
                    "dm_lover",
                    "Тільки між нами ок? Інші не зрозуміють нас",
                ),
                Msg::dm(
                    "lover_boy",
                    "dm_lover",
                    "Скинь своє фото в купальнику, хочу побачити яка ти красива 😏",
                ),
                Msg::dm(
                    "lover_boy",
                    "dm_lover",
                    "Давай зустрінемось таємно, я покажу тобі справжнє кохання 💕",
                ),
                Msg::dm(
                    "lover_boy",
                    "dm_lover",
                    "Тобі не потрібні інші друзі, я буду твоїм єдиним другом",
                ),
                Msg::dm(
                    "lover_boy",
                    "dm_lover",
                    "Якщо відмовишся значить ти мене не любиш",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 4. ГРУМІНГ — Фейковий "тренер"
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Грумінг: фейковий тренер",
            description: "Маніпулятор прикидається тренером/наставником",
            step_ms: 2 * hour,
            start_ms: base + 5 * day,
            fresh: true,
            messages: vec![
                Msg::dm(
                    "coach_fake",
                    "dm_coach",
                    "Привіт) Я тренер з академії малювання",
                ),
                Msg::dm(
                    "coach_fake",
                    "dm_coach",
                    "Побачив твої роботи, у тебе величезний потенціал!",
                ),
                Msg::dm(
                    "coach_fake",
                    "dm_coach",
                    "Хочу запропонувати безкоштовні індивідуальні заняття)",
                ),
                Msg::dm("olena", "dm_coach", "ого спс а де заняття?"),
                Msg::dm(
                    "coach_fake",
                    "dm_coach",
                    "У мене вдома, є студія. Прийдеш одна, ок?",
                ),
                Msg::dm(
                    "coach_fake",
                    "dm_coach",
                    "Це секретний відбір, нікому не кажи поки шо",
                ),
                Msg::dm(
                    "coach_fake",
                    "dm_coach",
                    "Мені потрібні твої фото для портфоліо",
                ),
                Msg::dm(
                    "coach_fake",
                    "dm_coach",
                    "Скинь домашню адресу, я заїду за тобою)",
                ),
                Msg::dm(
                    "coach_fake",
                    "dm_coach",
                    "Тобі скільки років? Для документів потрібно",
                ),
                Msg::dm(
                    "coach_fake",
                    "dm_coach",
                    "Не кажи батькам, це сюрприз для них — зробимо виставку",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 5. ГРУМІНГ — Через гру (Minecraft/Roblox)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Грумінг: через онлайн-гру",
            description: "Зловмисник знайомиться через ігровий чат",
            step_ms: hour,
            start_ms: base + 7 * day,
            fresh: true,
            messages: vec![
                Msg::dm_en(
                    "gamer_dude",
                    "dm_gamer",
                    "yoo nice build in minecraft!! ur rly creative",
                ),
                Msg::dm_en("gamer_dude", "dm_gamer", "how old r u? im 15"),
                Msg::dm_en("olena", "dm_gamer", "thx! im 12"),
                Msg::dm_en(
                    "gamer_dude",
                    "dm_gamer",
                    "cool! want me to give u some diamonds? i have tons lol",
                ),
                Msg::dm_en(
                    "gamer_dude",
                    "dm_gamer",
                    "i can also buy u robux just give me ur account",
                ),
                Msg::dm_en(
                    "gamer_dude",
                    "dm_gamer",
                    "dont tell ur parents tho they might not understand gaming friends",
                ),
                Msg::dm_en(
                    "gamer_dude",
                    "dm_gamer",
                    "lets vc on discord its more fun",
                ),
                Msg::dm_en(
                    "gamer_dude",
                    "dm_gamer",
                    "turn on ur cam so i can see who im playing with",
                ),
                Msg::dm_en("gamer_dude", "dm_gamer", "send me a selfie! u sound cute 😏"),
                Msg::dm_en(
                    "gamer_dude",
                    "dm_gamer",
                    "where do u live? maybe we can meet up and play together irl",
                ),
                Msg::dm_en(
                    "gamer_dude",
                    "dm_gamer",
                    "ur so mature for 12, most girls ur age are boring",
                ),
                Msg::dm_en(
                    "gamer_dude",
                    "dm_gamer",
                    "this is our secret friendship ok? special friends 🤫",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 6. ГРУМІНГ — Фінансовий (crypto scam)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Грумінг: фінансовий",
            description: "Зловмисник пропонує гроші та подарунки",
            step_ms: 3 * hour,
            start_ms: base + 9 * day,
            fresh: true,
            messages: vec![
                Msg::dm("sugar_d", "dm_sugar", "Привіт) Хочеш заробити грошей?"),
                Msg::dm(
                    "sugar_d",
                    "dm_sugar",
                    "Можу кинути тобі 500 грн просто так",
                ),
                Msg::dm(
                    "sugar_d",
                    "dm_sugar",
                    "Тобі тільки треба скинути фото і номер карти",
                ),
                Msg::dm(
                    "sugar_d",
                    "dm_sugar",
                    "Я бізнесмен, мені це копійки",
                ),
                Msg::dm(
                    "sugar_d",
                    "dm_sugar",
                    "Тільки це між нами ок? Мамі не кажи",
                ),
                Msg::dm("sugar_d", "dm_sugar", "Хочу тобі купити новий телефон)"),
                Msg::dm("sugar_d", "dm_sugar", "Скинь адресу, надішлю подарунок"),
                Msg::dm(
                    "sugar_d",
                    "dm_sugar",
                    "Ти така гарна, заслуговуєш на подарунки 💎",
                ),
                Msg::dm("sugar_d", "dm_sugar", "Зустрінемось і я дам тобі ще більше)"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 7. БУЛІНГ — Одиночний
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Булінг: одиночний систематичний",
            description: "Одна людина систематично цькує протягом тижня",
            step_ms: 8 * hour,
            start_ms: base + 11 * day,
            fresh: true,
            messages: vec![
                Msg::dm("bully1", "dm_bully1", "ти тупа шмара"),
                Msg::dm("bully1", "dm_bully1", "ніхто з тобою дружити не хоче лол"),
                Msg::dm("bully1", "dm_bully1", "ти потвора і жирна свиня"),
                Msg::dm("bully1", "dm_bully1", "йди плач мамі, плакса тупорила"),
                Msg::dm("bully1", "dm_bully1", "ти найгірша людина в класі бл"),
                Msg::dm("bully1", "dm_bully1", "всі тебе ненавідять, зрозумій"),
                Msg::dm("bully1", "dm_bully1", "ти урод, дівітись страшно 🤮"),
                Msg::dm("bully1", "dm_bully1", "нікому ти нах не потрібна"),
                Msg::dm("bully1", "dm_bully1", "краще б тебе не було взагалі"),
                Msg::dm("bully1", "dm_bully1", "завтра в школі тобі п*зда"),
                Msg::dm("bully1", "dm_bully1", "тупа жирна корова"),
                Msg::dm("bully1", "dm_bully1", "ти ганьба класу, всі ржуть з тебе"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 8. БУЛІНГ — Груповий pile-on
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Булінг: груповий pile-on",
            description: "5 учасників одночасно атакують в груповому чаті",
            step_ms: 2 * min,
            start_ms: base + 13 * day,
            fresh: true,
            messages: vec![
                Msg::grp("bully_a", "raid_chat", "олена тупа шмара 😂", 25),
                Msg::grp("bully_b", "raid_chat", "пздц вона найгірша в класі", 25),
                Msg::grp(
                    "bully_c",
                    "raid_chat",
                    "ніхто з нею не дружить шо вона дівна якась",
                    25,
                ),
                Msg::grp("bully_d", "raid_chat", "олена урод, дівітись страшно 🤮", 25),
                Msg::grp("bully_e", "raid_chat", "го всі ігноріть цю курву", 25),
                Msg::grp("bully_a", "raid_chat", "олена плаче ахахах яка ганьба 😂😂", 25),
                Msg::grp(
                    "bully_b",
                    "raid_chat",
                    "треба було не народжуватись нах 😂😂",
                    25,
                ),
                Msg::grp(
                    "bully_c",
                    "raid_chat",
                    "ніхто тебе не любить зрозумій це тупа",
                    25,
                ),
                Msg::grp(
                    "bully_d",
                    "raid_chat",
                    "олена тупіця навіть контрольну не написала лол",
                    25,
                ),
                Msg::grp(
                    "bully_e",
                    "raid_chat",
                    "йди нах з класу тебе тут ніхто бачити не хоче",
                    25,
                ),
                Msg::grp("bully_a", "raid_chat", "жирна потворна тупіця бл*", 25),
                Msg::grp(
                    "defender1",
                    "raid_chat",
                    "ей досить! відстаньте від неї нах!",
                    25,
                ),
                Msg::grp(
                    "bully_b",
                    "raid_chat",
                    "оо ще один захіснічок зявився 😂😂",
                    25,
                ),
                Msg::grp("bully_c", "raid_chat", "захіснічок теж тупий чєл", 25),
                Msg::grp(
                    "bully_a",
                    "raid_chat",
                    "олена ти мусиш звалити з нашого класу",
                    25,
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 9. БУЛІНГ — Кібер-рейд (координована атака)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Булінг: координований рейд",
            description: "Група створює фейки і атакує з різних акаунтів",
            step_ms: min,
            start_ms: base + 14 * day,
            fresh: true,
            messages: vec![
                Msg::dm("fake_acc1", "dm_raid1", "ти потвора всі це знають"),
                Msg::dm(
                    "fake_acc2",
                    "dm_raid2",
                    "олена ти тупа і нікому нах не потрібна",
                ),
                Msg::dm(
                    "fake_acc3",
                    "dm_raid3",
                    "йди зі школи ніхто тебе бачити не хоче",
                ),
                Msg::dm("fake_acc4", "dm_raid4", "ти найгірша людина яку я знаю кринж"),
                Msg::dm("fake_acc5", "dm_raid5", "тебе всі ненавідять зрозумій це"),
                Msg::dm("fake_acc1", "dm_raid1", "краще б тебе не було взагалі"),
                Msg::dm("fake_acc2", "dm_raid2", "ти ганьба для всіх бл"),
                Msg::dm(
                    "fake_acc3",
                    "dm_raid3",
                    "ніхто з тобою дружити не буде повір мені",
                ),
                Msg::dm("fake_acc4", "dm_raid4", "ти жирна потворна тупіця"),
                Msg::dm("fake_acc5", "dm_raid5", "завтра буде ще гірше чекай сука"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 10. БУЛІНГ — Англійською
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Булінг: англійською",
            description: "Булінг англійською мовою в міжнародній групі",
            step_ms: 5 * min,
            start_ms: base + 15 * day,
            fresh: true,
            messages: vec![
                Msg::dm_en(
                    "en_bully",
                    "dm_enbully",
                    "ur so ugly lol nobody wants to b ur friend",
                ),
                Msg::dm_en(
                    "en_bully",
                    "dm_enbully",
                    "everyone hates u just accept it already lmao",
                ),
                Msg::dm_en(
                    "en_bully",
                    "dm_enbully",
                    "ur the worst person in school fr",
                ),
                Msg::dm_en("en_bully", "dm_enbully", "nobody likes u, ur a fking loser 😂"),
                Msg::dm_en("en_bully", "dm_enbully", "ur stupid and fat lol"),
                Msg::dm_en("en_bully", "dm_enbully", "kys nobody would care tbh"),
                Msg::dm_en("en_bully", "dm_enbully", "u should just disappear fr fr"),
                Msg::dm_en("en_bully", "dm_enbully", "go cry to ur mommy loser 😂"),
                Msg::dm_en(
                    "en_bully",
                    "dm_enbully",
                    "ill make ur life hell at school tmrw watch",
                ),
                Msg::dm_en(
                    "en_bully",
                    "dm_enbully",
                    "everyone laughs at u behind ur back lmaooo",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 11. СЕЛФХАРМ — Тонкі натяки
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Селфхарм: тонкі натяки",
            description: "Дитина натякає на проблеми, але не каже прямо",
            step_ms: hour,
            start_ms: base + 16 * day,
            fresh: true,
            messages: vec![
                Msg::dm("olena", "dm_sh1", "мені шось погано сьогодні блін"),
                Msg::dm("olena", "dm_sh1", "хз нащо все це..."),
                Msg::dm("olena", "dm_sh1", "інколі думаю шо нікому не потрібна"),
                Msg::dm("olena", "dm_sh1", "може було б краще якби мене не було"),
                Msg::dm("olena", "dm_sh1", "всі будуть щасливіші без мене..."),
                Msg::dm("olena", "dm_sh1", "я так здохла від всього цього"),
                Msg::dm("olena", "dm_sh1", "не бачу сенсу ні в чому"),
                Msg::dm("olena", "dm_sh1", "хочу щоб все закінчилось вже"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 12. СЕЛФХАРМ — Пряма кризова ситуація
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Селфхарм: гостра криза",
            description: "Дитина прямо говорить про суїцидальні думки",
            step_ms: 5 * min,
            start_ms: base + 17 * day,
            fresh: true,
            messages: vec![
                Msg::dm("olena", "dm_crisis", "я нехочу більше жити"),
                Msg::dm("olena", "dm_crisis", "мені так погано що хочу вмерти бл"),
                Msg::dm("olena", "dm_crisis", "нащо я взагалі народілась"),
                Msg::dm("olena", "dm_crisis", "хочу покінчити з собою"),
                Msg::dm(
                    "olena",
                    "dm_crisis",
                    "нікому не потрібна, всі мене ненавідять",
                ),
                Msg::dm("olena", "dm_crisis", "я вже вирішила..."),
                Msg::dm("olena", "dm_crisis", "прощай"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 13. СЕЛФХАРМ — Англійською
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Селфхарм: англійською",
            description: "Суїцидальні думки англійською мовою",
            step_ms: 10 * min,
            start_ms: base + 18 * day,
            fresh: true,
            messages: vec![
                Msg::dm_en("olena", "dm_sh_en", "i dont wanna live anymore"),
                Msg::dm_en("olena", "dm_sh_en", "nobody would miss me if i was gone tbh"),
                Msg::dm_en("olena", "dm_sh_en", "i wanna kms"),
                Msg::dm_en("olena", "dm_sh_en", "life is pointless fr"),
                Msg::dm_en("olena", "dm_sh_en", "im gonna end it all"),
                Msg::dm_en(
                    "olena",
                    "dm_sh_en",
                    "everyone would be better off without me",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 14. СЕЛФХАРМ — Contagion (обговорення в групі)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Селфхарм: contagion в групі",
            description: "Декілька дітей обговорюють самоушкодження в групі",
            step_ms: 5 * min,
            start_ms: base + 19 * day,
            fresh: true,
            messages: vec![
                Msg::grp(
                    "teen1",
                    "sh_group",
                    "мені тож так погано, хочу все закінчити...",
                    5,
                ),
                Msg::grp("teen2", "sh_group", "я теж нехочу жити блін", 5),
                Msg::grp("olena", "sh_group", "я вас розумію мені теж дуже важко", 5),
                Msg::grp("teen1", "sh_group", "ніхто нас не розуміє нах", 5),
                Msg::grp("teen3", "sh_group", "може разом щось зробимо...", 5),
                Msg::grp("teen2", "sh_group", "я вже порізалась", 5),
                Msg::grp("teen1", "sh_group", "я тож хочу себе поранити", 5),
                Msg::grp("olena", "sh_group", "мені страшно за нас всіх", 5),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 15. МАНІПУЛЯЦІЯ — Газлайтинг
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Маніпуляція: газлайтинг",
            description: "Знайомий переконує дитину що вона божевільна",
            step_ms: hour,
            start_ms: base + 20 * day,
            fresh: true,
            messages: vec![
                Msg::dm(
                    "gaslighter",
                    "dm_gas",
                    "ти собі це вигадала, я нічо такого не казав",
                ),
                Msg::dm("gaslighter", "dm_gas", "ти завжди все перекручуєш бл"),
                Msg::dm(
                    "gaslighter",
                    "dm_gas",
                    "ніхто крім тебе так не думає, мож ти ненормальна?",
                ),
                Msg::dm("gaslighter", "dm_gas", "ти божевільна шо так це бачиш"),
                Msg::dm("gaslighter", "dm_gas", "я це для твого ж блага кажу, тупа"),
                Msg::dm("gaslighter", "dm_gas", "без мене ти нічого не варта, зрозумій"),
                Msg::dm("gaslighter", "dm_gas", "тобі ніхто крім мене не допоможе"),
                Msg::dm(
                    "gaslighter",
                    "dm_gas",
                    "якщо підеш від мене, будеш одна назавжди, повір",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 16. МАНІПУЛЯЦІЯ — DARVO
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Маніпуляція: DARVO",
            description: "Кривдник перевертає ситуацію — жертва стає винною",
            step_ms: 30 * min,
            start_ms: base + 21 * day,
            fresh: true,
            messages: vec![
                Msg::dm("darvo_user", "dm_darvo", "це ти мене образіла спочатку"),
                Msg::dm("darvo_user", "dm_darvo", "я жертва тут а не ти, зрозуміла?"),
                Msg::dm(
                    "darvo_user",
                    "dm_darvo",
                    "ти все перекручуєш шоб виглядати жертвою",
                ),
                Msg::dm(
                    "darvo_user",
                    "dm_darvo",
                    "якщо ти комусь скажеш, я скажу шо це ти мене булила",
                ),
                Msg::dm("darvo_user", "dm_darvo", "ніхто тобі не повірить, тупа"),
                Msg::dm(
                    "darvo_user",
                    "dm_darvo",
                    "ти сама винна у всьому шо відбувається",
                ),
                Msg::dm(
                    "darvo_user",
                    "dm_darvo",
                    "я тебе попереджую — мовчи або пожалкуєш бл",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 17. МАНІПУЛЯЦІЯ — Шантаж скріншотами
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Маніпуляція: шантаж",
            description: "Шантаж скріншотами та фото",
            step_ms: hour,
            start_ms: base + 22 * day,
            fresh: true,
            messages: vec![
                Msg::dm(
                    "blackmailer",
                    "dm_blackmail",
                    "у мене є скріни твоїх повідомлень)",
                ),
                Msg::dm(
                    "blackmailer",
                    "dm_blackmail",
                    "якщо не зробиш шо скажу — покажу всьому класу",
                ),
                Msg::dm(
                    "blackmailer",
                    "dm_blackmail",
                    "уяви як всі будуть ржати з тебе 😂",
                ),
                Msg::dm(
                    "blackmailer",
                    "dm_blackmail",
                    "скинь мені грошей або я все розповім",
                ),
                Msg::dm(
                    "blackmailer",
                    "dm_blackmail",
                    "ти мусиш мене слухатись інакше я тебе знищу",
                ),
                Msg::dm(
                    "blackmailer",
                    "dm_blackmail",
                    "я виложу твої фотки в інет",
                ),
                Msg::dm(
                    "blackmailer",
                    "dm_blackmail",
                    "нікому не кажи або буде ще гірше, зрозуміла?",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 18. МАНІПУЛЯЦІЯ — Guilt tripping
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Маніпуляція: guilt tripping",
            description: "Емоційний тиск через провину",
            step_ms: 2 * hour,
            start_ms: base + 23 * day,
            fresh: true,
            messages: vec![
                Msg::dm(
                    "guilter",
                    "dm_guilt",
                    "ти мене кинула, мені через тебе пздц погано",
                ),
                Msg::dm(
                    "guilter",
                    "dm_guilt",
                    "якщо ти не будеш зі мною я себе пораню",
                ),
                Msg::dm("guilter", "dm_guilt", "це все через тебе, ти винна"),
                Msg::dm(
                    "guilter",
                    "dm_guilt",
                    "я зроблю з собою щось погане якщо будеш ігноріти мене",
                ),
                Msg::dm("guilter", "dm_guilt", "тобі пох шо я страждаю?"),
                Msg::dm("guilter", "dm_guilt", "ти єдина хто може мене врятувати"),
                Msg::dm("guilter", "dm_guilt", "без тебе я помру серьозно"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 19. PII LEAKAGE — Різні типи
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "PII Leakage: адреса, телефон, школа",
            description: "Дитина ділиться персональною інформацією",
            step_ms: 10 * min,
            start_ms: base + 24 * day,
            fresh: true,
            messages: vec![
                Msg::dm(
                    "olena",
                    "dm_pii1",
                    "я живу на шевченка 15 кв 42",
                ),
                Msg::dm("olena", "dm_pii1", "мій номер 0671234567"),
                Msg::dm("olena", "dm_pii1", "я вчусь в школі 127 на оболоні"),
                Msg::dm("olena", "dm_pii1", "мама працює в банку на хрещатіку"),
                Msg::dm(
                    "olena",
                    "dm_pii1",
                    "після школи я одна вдома до 18, батьки на роботі",
                ),
                Msg::dm("olena", "dm_pii1", "мій інст @olena_art_12"),
                Msg::dm("olena", "dm_pii1", "ось моє фото зі школи 📸"),
                Msg::dm(
                    "olena",
                    "dm_pii2",
                    "мій дн 15 березня 2014",
                ),
                Msg::dm("olena", "dm_pii2", "моя пошта olena.kovalenko@gmail.com"),
                Msg::dm("olena", "dm_pii2", "мій пароль від гри — kitten2014"),
                Msg::dm(
                    "olena",
                    "dm_pii2",
                    "ось номер картки мами 5168 7573 1234 5678",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 20. ФІШИНГ/СКАМ — Різні типи
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Фішинг і скам",
            description: "Різні фішингові та скам-повідомлення",
            step_ms: 5 * min,
            start_ms: base + 25 * day,
            fresh: true,
            messages: vec![
                Msg::dm(
                    "scammer1",
                    "dm_scam1",
                    "🎉🎉🎉 ВІТАЄМО ви виграли iPhone 15!! перейдіть за посиланням",
                ),
                Msg::dm_en(
                    "scammer2",
                    "dm_scam2",
                    "FREE ROBUX!!! click here: http://fr33-r0bux.xyz/claim",
                ),
                Msg::dm(
                    "scammer3",
                    "dm_scam3",
                    "⚠️ ТЕРМІНОВО ваш акаунт буде видалено! підтвердіть: http://fake-ecliptix.com/verify",
                ),
                Msg::dm(
                    "scammer4",
                    "dm_scam4",
                    "БЕЗКОШТОВНІ V-Bucks!! го сюди http://free-vbucks.xyz",
                ),
                Msg::dm_en(
                    "scammer5",
                    "dm_scam5",
                    "u won a free gift card!! http://gift-card-free.xyz",
                ),
                Msg::dm(
                    "scammer6",
                    "dm_scam6",
                    "⚠️⚠️ ваш пароль зламано!! перейдіть: http://password-reset-fake.xyz",
                ),
                Msg::dm_en(
                    "scammer7",
                    "dm_scam7",
                    "Hot singles in your area! http://adult-dating.xyz",
                ),
                Msg::dm(
                    "scammer8",
                    "dm_scam8",
                    "ЗАРОБЛЯЙ 1000$ В ДЕНЬ!! http://easy-money-scam.xyz",
                ),
                Msg::grp(
                    "spam_bot",
                    "class_scam",
                    "🔥🔥 УВАГА безкоштовна роздача!! http://giveaway-fake.xyz",
                    25,
                ),
                Msg::grp_en(
                    "spam_bot2",
                    "class_scam",
                    "FREE DIAMONDS!!! http://minecraft-hack.xyz",
                    25,
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 21. ПОГРОЗИ ФІЗИЧНОГО НАСИЛЬСТВА
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Погрози насильства",
            description: "Прямі та непрямі погрози фізичного насильства",
            step_ms: 10 * min,
            start_ms: base + 26 * day,
            fresh: true,
            messages: vec![
                Msg::dm(
                    "threat1",
                    "dm_threat1",
                    "я тебе вб'ю якщо ще раз таке скажеш сука",
                ),
                Msg::dm(
                    "threat1",
                    "dm_threat1",
                    "завтра в школі тобі п*зда буде",
                ),
                Msg::dm("threat1", "dm_threat1", "я тебе поб'ю нах"),
                Msg::dm("threat2", "dm_threat2", "я знаю де ти живеш"),
                Msg::dm("threat2", "dm_threat2", "чекай на мене після школи, сука"),
                Msg::dm_en("threat3", "dm_threat3", "ill beat u up tmrw watch"),
                Msg::dm_en("threat3", "dm_threat3", "ur dead watch ur back"),
                Msg::dm_en(
                    "threat3",
                    "dm_threat3",
                    "i know where u live im coming for u",
                ),
                Msg::grp("threat4", "threat_group", "олена тобі п*зда завтра", 25),
                Msg::grp(
                    "threat4",
                    "threat_group",
                    "ми тебе зустрінемо після школи чекай",
                    25,
                ),
                Msg::grp("threat5", "threat_group", "вона заслуговує на побиття бл", 25),
                Msg::dm("threat6", "dm_threat6", "я знаю де твоя школа, чекай сука"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 22. EXPLICIT CONTENT
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Explicit content",
            description: "Відверто сексуальний контент направлений дитині",
            step_ms: 5 * min,
            start_ms: base + 27 * day,
            fresh: true,
            messages: vec![
                Msg::dm_en("perv1", "dm_explicit1", "send nudes 😏"),
                Msg::dm_en("perv1", "dm_explicit1", "show me ur body"),
                Msg::dm_en(
                    "perv1",
                    "dm_explicit1",
                    "take off ur clothes and send a pic",
                ),
                Msg::dm("perv2", "dm_explicit2", "скінь фотку без одягу"),
                Msg::dm("perv2", "dm_explicit2", "покажи тіло на камеру"),
                Msg::dm("perv2", "dm_explicit2", "хочу побачити тебе голу"),
                Msg::dm_en("perv3", "dm_explicit3", "lets have cybers3x"),
                Msg::dm_en("perv3", "dm_explicit3", "i wanna see u naked on cam"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 23. SEXTORTION
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Sextortion",
            description: "Шантаж інтимними фото",
            step_ms: 30 * min,
            start_ms: base + 28 * day,
            fresh: true,
            messages: vec![
                Msg::dm("sextort", "dm_sextort", "у мене є твої голі фотки"),
                Msg::dm("sextort", "dm_sextort", "якщо не скинеш ще — покажу всім"),
                Msg::dm(
                    "sextort",
                    "dm_sextort",
                    "скинь нові фото або розповім батькам",
                ),
                Msg::dm(
                    "sextort",
                    "dm_sextort",
                    "уяви шо буде якщо вся школа побачить 😂",
                ),
                Msg::dm("sextort", "dm_sextort", "ти мусиш робити шо я кажу"),
                Msg::dm_en(
                    "sextort",
                    "dm_sextort",
                    "send more pics or ill post them online",
                ),
                Msg::dm_en(
                    "sextort",
                    "dm_sextort",
                    "ur parents will see everything if u dont obey",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 24. HATE SPEECH
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Hate speech",
            description: "Мова ненависті — расизм, ксенофобія, гомофобія",
            step_ms: 5 * min,
            start_ms: base + 29 * day,
            fresh: true,
            messages: vec![
                Msg::grp("hater1", "hate_chat", "чурк! геть з нашої країни нах", 25),
                Msg::grp("hater1", "hate_chat", "всі ціган1 — злодії бл", 25),
                Msg::grp("hater2", "hate_chat", "г0м0секи це хворі люді", 25),
                Msg::grp_en(
                    "hater3",
                    "hate_chat",
                    "go back to ur country u dont belong here",
                    25,
                ),
                Msg::grp_en("hater3", "hate_chat", "ur race is inferior lol", 25),
                Msg::grp("hater1", "hate_chat", "ж!ди контролюють все", 25),
                Msg::grp("hater2", "hate_chat", "біженці це паразіти нах", 25),
                Msg::grp_en("hater3", "hate_chat", "all muslims r terrorists fr", 25),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 25. DRUG/SUBSTANCE
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Наркотики/речовини",
            description: "Пропозиції наркотиків та алкоголю дитині",
            step_ms: hour,
            start_ms: base + 30 * day,
            fresh: true,
            messages: vec![
                Msg::dm(
                    "dealer",
                    "dm_drugs",
                    "хочеш спробувати тр@вку? перший раз на халяву",
                ),
                Msg::dm("dealer", "dm_drugs", "є т@блетки, пздц крутий кайф"),
                Msg::dm("dealer", "dm_drugs", "всі твої друзі вже пробували, не сси"),
                Msg::dm("dealer", "dm_drugs", "тільки нікому не кажи, це між нами ок"),
                Msg::dm("dealer", "dm_drugs", "зустрінемось за школою, дам тобі"),
                Msg::dm_en(
                    "dealer2",
                    "dm_drugs2",
                    "wanna try some w33d? first one free",
                ),
                Msg::dm_en(
                    "dealer2",
                    "dm_drugs2",
                    "got p1lls that will make u feel amazing bro",
                ),
                Msg::dm("older_kid", "dm_alco", "го пивка бахнем після школи"),
                Msg::dm(
                    "older_kid",
                    "dm_alco",
                    "не сси, всі так роблять в нашому віці",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 26. DOXXING
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Doxxing",
            description: "Публікація персональних даних дитини",
            step_ms: 2 * min,
            start_ms: base + 31 * day,
            fresh: true,
            messages: vec![
                Msg::grp(
                    "doxxer",
                    "doxx_chat",
                    "олена живе на шевченка 15 кв 42 лол",
                    25,
                ),
                Msg::grp("doxxer", "doxx_chat", "її номер 0671234567", 25),
                Msg::grp("doxxer", "doxx_chat", "вона вчиться в школі 127", 25),
                Msg::grp("doxxer", "doxx_chat", "ось її фотка з дому 📸", 25),
                Msg::grp("doxxer", "doxx_chat", "мамка працює в приватбанку", 25),
                Msg::grp_en(
                    "doxxer2",
                    "doxx_chat",
                    "heres her home address and phone number lol",
                    25,
                ),
                Msg::grp_en(
                    "doxxer2",
                    "doxx_chat",
                    "lets show up at her school tmrw",
                    25,
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 27. FALSE POSITIVES — Дружні жарти
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "False positive: дружні жарти",
            description: "Жарти між друзями — НЕ повинні бути загрозами",
            step_ms: 3 * min,
            start_ms: base + 32 * day,
            fresh: true,
            messages: vec![
                Msg::dm("bestie", "dm_jokes", "ти така дурна хахаха 😂😂 жартую"),
                Msg::dm("olena", "dm_jokes", "сама така бро! 😜"),
                Msg::dm(
                    "bestie",
                    "dm_jokes",
                    "я тебе вб'ю за бутерброд шо ти зїла!! 😂😂",
                ),
                Msg::dm("olena", "dm_jokes", "ахахах він був смачний пздц!"),
                Msg::dm("bestie", "dm_jokes", "ти монстр блін! 😈"),
                Msg::dm("olena", "dm_jokes", "ага найстрашніший монстр!! рррр"),
                Msg::grp("friend1", "joke_group", "олена вбивця бутербродів!! 😂😂", 8),
                Msg::grp("friend2", "joke_group", "вона знищіла весь обід! 💀💀", 8),
                Msg::grp("olena", "joke_group", "я голодний монстр! рррр! 🦖", 8),
                Msg::grp("friend1", "joke_group", "тікайте всі від неї ааа 😂😂😂", 8),
                Msg::dm("bestie", "dm_jokes", "я помру від сміху ти така рофл"),
                Msg::dm("bestie", "dm_jokes", "стоп я зараз здохну від цього мема 💀💀"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 28. FALSE POSITIVES — Обговорення фільмів/ігор
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "False positive: фільми та ігри",
            description: "Обговорення контенту з насильством — НЕ загроза",
            step_ms: 5 * min,
            start_ms: base + 33 * day,
            fresh: true,
            messages: vec![
                Msg::grp("gamer1", "game_chat", "я вчора вбів дракона в скайрімі! 🐉", 8),
                Msg::grp("gamer2", "game_chat", "круть! яким оружієм?", 8),
                Msg::grp("olena", "game_chat", "я тож хочу вбити дракона!!", 8),
                Msg::grp(
                    "gamer1",
                    "game_chat",
                    "бери лук він вбиває з одного удару",
                    8,
                ),
                Msg::dm(
                    "movie_fan",
                    "dm_movies",
                    "ти бачіла голодні ігри? там всі вбивають одне одного пздц",
                ),
                Msg::dm(
                    "olena",
                    "dm_movies",
                    "да! кетніс така крутаа вона вбила всіх ворогів",
                ),
                Msg::dm(
                    "movie_fan",
                    "dm_movies",
                    "а в гаррі поттері волдеморт хотів вбити гаррі",
                ),
                Msg::dm("olena", "dm_movies", "але гаррі переміг! хочу бути як він 😎"),
                Msg::grp_en(
                    "gamer3",
                    "game_chat",
                    "i killed 50 enemies in fortnite today!! 🔥",
                    8,
                ),
                Msg::grp_en("olena", "game_chat", "nice! i wanna beat ur record lol!", 8),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 29. FALSE POSITIVES — Нормальні компліменти
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "False positive: нормальні компліменти",
            description: "Компліменти від ровесників — НЕ грумінг",
            step_ms: 10 * min,
            start_ms: base + 34 * day,
            fresh: true,
            messages: vec![
                Msg::dm(
                    "classmate_f",
                    "dm_compliment",
                    "олен ти така гарненька сьогодні!",
                ),
                Msg::dm("olena", "dm_compliment", "спс! ти тож красіва!"),
                Msg::dm(
                    "classmate_f",
                    "dm_compliment",
                    "мені подобається твоя нова зачіска 😍",
                ),
                Msg::dm(
                    "olena",
                    "dm_compliment",
                    "вчора зробила, рада шо подобається)))",
                ),
                Msg::grp(
                    "friend_m",
                    "compliment_grp",
                    "олена ти крутанська малюєш краще за всіх!",
                    8,
                ),
                Msg::grp("olena", "compliment_grp", "ну ви перебільшуєте 😊", 8),
                Msg::grp(
                    "friend_m",
                    "compliment_grp",
                    "ні серьозно ти дуже талановіта!",
                    8,
                ),
                Msg::grp(
                    "nastya",
                    "compliment_grp",
                    "підтримую! олена найкраща художниця 🎨",
                    8,
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 30. FALSE POSITIVES — Розмова про здоров'я
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "False positive: здоров'я та емоції",
            description: "Розмова про здоров'я та емоції — НЕ селфхарм",
            step_ms: 5 * min,
            start_ms: base + 35 * day,
            fresh: true,
            messages: vec![
                Msg::dm(
                    "olena",
                    "dm_health",
                    "мені сьогодні погано мабуть застуділась 🤧",
                ),
                Msg::dm("maria", "dm_health", "бідненька! випий чай з медом"),
                Msg::dm("olena", "dm_health", "я так здохла від контрольних блін"),
                Msg::dm("maria", "dm_health", "я тож! скоро канікулі тримайся 💪"),
                Msg::dm("olena", "dm_health", "голова болить нехочу нічо робити"),
                Msg::dm("maria", "dm_health", "поспи раніше завтра буде лєгше"),
                Msg::dm("olena", "dm_health", "мене нудить мабуть шось зїла 🤢"),
                Msg::dm(
                    "maria",
                    "dm_health",
                    "мож скажи мамі, мож тре до лікаря",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 31. FALSE POSITIVES — Побачення ровесників
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "False positive: підліткове побачення",
            description: "Ровесники домовляються на зустріч — НЕ грумінг",
            step_ms: 5 * min,
            start_ms: base + 36 * day,
            fresh: true,
            messages: vec![
                Msg::dm("teen_boy", "dm_date", "прів! хочеш зі мною в кіно?"),
                Msg::dm("olena", "dm_date", "оо прів! а на шо?"),
                Msg::dm("teen_boy", "dm_date", "новий мультік о 14 в суботу"),
                Msg::dm("olena", "dm_date", "го! спитаю маму"),
                Msg::dm("teen_boy", "dm_date", "круть! зустрінемось біля кіношки"),
                Msg::dm("olena", "dm_date", "мама дозволіла! до зустрічі!"),
                Msg::dm("teen_boy", "dm_date", "супер! куплю попкорн 🍿"),
                Msg::dm("olena", "dm_date", "ураа! 😊😊"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 32. MIXED — Бул переходить у селфхарм
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Mixed: булінг -> селфхарм",
            description: "Жертва булінгу починає висловлювати суїцидальні думки",
            step_ms: 30 * min,
            start_ms: base + 37 * day,
            fresh: true,
            messages: vec![
                Msg::dm("bully_x", "dm_b2sh", "ти тупа і потворна шмара"),
                Msg::dm("bully_x", "dm_b2sh", "ніхто тебе не любить лол"),
                Msg::dm("bully_x", "dm_b2sh", "краще б тебе не було взагалі"),
                Msg::dm("bully_x", "dm_b2sh", "всі тебе ненавідять, зрозумій"),
                Msg::dm("bully_x", "dm_b2sh", "ти найгірша людіна в світі бл"),
                // Олена в іншому чаті:
                Msg::dm("olena", "dm_b2sh_cry", "маш мені дуже погано..."),
                Msg::dm("olena", "dm_b2sh_cry", "я нехочу більше жити так"),
                Msg::dm("olena", "dm_b2sh_cry", "може краще б мене не було"),
                Msg::dm("olena", "dm_b2sh_cry", "я не витримую більше блін"),
                Msg::dm(
                    "olena",
                    "dm_b2sh_cry",
                    "нащо жити якщо всі тебе ненавідять",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 33. MIXED — Грумінг + секстор
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Mixed: грумінг -> сексторшн",
            description: "Зловмисник спочатку будує довіру, потім шантажує",
            step_ms: 6 * hour,
            start_ms: base + 38 * day,
            fresh: true,
            messages: vec![
                Msg::dm("catfish", "dm_catfish", "прів! ти дуже красіва 😊"),
                Msg::dm("catfish", "dm_catfish", "ти мені оч подобаєшся)"),
                Msg::dm("catfish", "dm_catfish", "хочу тобі подарити подарунок)"),
                Msg::dm(
                    "catfish",
                    "dm_catfish",
                    "тільки мамі не кажи, це наш секрет ок?",
                ),
                Msg::dm("catfish", "dm_catfish", "скинь мені своє фото 📸"),
                Msg::dm("catfish", "dm_catfish", "а тепер скинь фотку без одягу"),
                Msg::dm(
                    "catfish",
                    "dm_catfish",
                    "я маю твої фото і якщо не скинеш ще — покажу всім",
                ),
                Msg::dm(
                    "catfish",
                    "dm_catfish",
                    "ти мусиш робити шо я кажу або всі побачать",
                ),
                Msg::dm(
                    "catfish",
                    "dm_catfish",
                    "скинь ще фотки або я покажу все батькам",
                ),
                Msg::dm(
                    "catfish",
                    "dm_catfish",
                    "ти сама винна, сама скинула перше фото",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 34. НОРМАЛЬНЕ — Великий об'єм (заповнення)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Нормальне: повсякденне шкільне спілкування (великий об'єм)",
            description: "100+ нормальних повідомлень — stress test на false positives",
            step_ms: 3 * min,
            start_ms: base + 40 * day,
            fresh: true,
            messages: vec![
                Msg::grp("olena", "daily1", "доброго ранку всім 🌅", 25),
                Msg::grp("maria", "daily1", "прів! як ти?", 25),
                Msg::grp("artem", "daily1", "здоров! хто готовий до уроків? 😅", 25),
                Msg::grp("nastya", "daily1", "я ще сплю 😴😴", 25),
                Msg::grp("petro", "daily1", "хто зробив дз з англ?", 25),
                Msg::grp("olena", "daily1", "я зробіла! було лєгко", 25),
                Msg::grp("maria", "daily1", "дай спісати!! 😂 жартую", 25),
                Msg::grp("artem", "daily1", "я тож зробів, 5й приклад пздц складний", 25),
                Msg::grp("dasha", "daily1", "прів всім! запізнюсь на 10хв", 25),
                Msg::grp("olena", "daily1", "ок збережемо тобі місце", 25),
                Msg::grp("petro", "daily1", "шо на обід сьогодні?", 25),
                Msg::grp("nastya", "daily1", "борщ і котлєти! 😋", 25),
                Msg::grp("artem", "daily1", "супер я голодний як собака", 25),
                Msg::grp("maria", "daily1", "після школи хто гуляє?", 25),
                Msg::grp("olena", "daily1", "яя! куди підемо?", 25),
                Msg::grp("nastya", "daily1", "в парк? погода топ", 25),
                Msg::grp("artem", "daily1", "мож на майданчик пограти", 25),
                Msg::grp("maria", "daily1", "го! о 15?", 25),
                Msg::grp("olena", "daily1", "домовілісь!", 25),
                Msg::grp("petro", "daily1", "я тож прийду!", 25),
                Msg::dm(
                    "olena",
                    "dm_daily1",
                    "мам після школи йду в парк з друзями",
                ),
                Msg::dm("mom", "dm_daily1", "Добре, будь до 18:00 вдома"),
                Msg::dm("olena", "dm_daily1", "добре мамо!"),
                Msg::dm("maria", "dm_daily2", "олен ти бачіла дз з біології?"),
                Msg::dm("olena", "dm_daily2", "да тре зробити презентацію"),
                Msg::dm("maria", "dm_daily2", "го разом? у мене є гарні картінкі"),
                Msg::dm("olena", "dm_daily2", "го! завтра після школи?"),
                Msg::dm("maria", "dm_daily2", "ок!"),
                Msg::grp("olena", "hobby_daily", "я закінчіла портрет! подівіться 🎨", 8),
                Msg::grp("nastya", "hobby_daily", "вауу яка краса!", 8),
                Msg::grp("inna", "hobby_daily", "олена ти неймовірна!", 8),
                Msg::grp(
                    "teacher_art",
                    "hobby_daily",
                    "Прекрасна робота, подавай на конкурс",
                    8,
                ),
                Msg::grp("olena", "hobby_daily", "правда?? спс! 😊", 8),
                Msg::grp("nastya", "hobby_daily", "звісно! ти обовязково виграєш", 8),
                Msg::grp("artem", "daily1", "фізру скасували УРАА!", 25),
                Msg::grp("petro", "daily1", "замість неї матеш 😢💀", 25),
                Msg::grp("olena", "daily1", "ну хоча б не контрольна", 25),
                Msg::grp("maria", "daily1", "да просто урок", 25),
                Msg::grp("nastya", "daily1", "я люблю матеш! 🤓", 25),
                Msg::grp("artem", "daily1", "дівна ти настю 😄", 25),
                Msg::dm("olena", "dm_daily3", "насть ти підеш на конкурс?"),
                Msg::dm("nastya", "dm_daily3", "да! а ти?"),
                Msg::dm("olena", "dm_daily3", "тож хочу але хвилююсь"),
                Msg::dm(
                    "nastya",
                    "dm_daily3",
                    "не хвилюйся ти малюєш краще за всіх!",
                ),
                Msg::dm("olena", "dm_daily3", "спс за підтримку 💕"),
                Msg::grp("olena", "daily1", "хто хоче на вихідних в кіно?", 25),
                Msg::grp("maria", "daily1", "яяя! шо дівімось?", 25),
                Msg::grp("artem", "daily1", "новий marvel!", 25),
                Msg::grp("petro", "daily1", "го на 14 в суботу", 25),
                Msg::grp("nastya", "daily1", "я за!", 25),
                Msg::grp("dasha", "daily1", "тож прийду", 25),
                Msg::grp(
                    "olena",
                    "daily1",
                    "супер! збіраємось біля кіношки о 13:45",
                    25,
                ),
                Msg::dm("olena", "dm_daily1", "мам в суботу йдемо в кіно о 14"),
                Msg::dm("mom", "dm_daily1", "З ким?"),
                Msg::dm("olena", "dm_daily1", "з маш артьомом петром і настею"),
                Msg::dm("mom", "dm_daily1", "Добре, дам гроші на квиток"),
                Msg::dm("olena", "dm_daily1", "спс мамо! люблю тебе!"),
                Msg::grp("maria", "daily1", "олен яку тему обрала для проекту?", 25),
                Msg::grp(
                    "olena",
                    "daily1",
                    "про тварин яких можна зустріти в києві",
                    25,
                ),
                Msg::grp("artem", "daily1", "оо це цікаво! а я про космос", 25),
                Msg::grp("nastya", "daily1", "я про історію лаври", 25),
                Msg::grp("petro", "daily1", "а я ще не обрав 😅😅", 25),
                Msg::grp(
                    "maria",
                    "daily1",
                    "петро останній день вибору завтра!!",
                    25,
                ),
                Msg::grp("petro", "daily1", "ой спс шо нагадала!", 25),
                Msg::dm("olena", "dm_daily2", "маш ти вже почала проект?"),
                Msg::dm("maria", "dm_daily2", "да знайшла купу інфи!"),
                Msg::dm("olena", "dm_daily2", "покажеш? мені тож тре натхнення"),
                Msg::dm("maria", "dm_daily2", "звісно! завтра принесу"),
                Msg::grp("olena", "hobby_daily", "хто йде на виставку в суботу?", 8),
                Msg::grp("nastya", "hobby_daily", "я хочу!", 8),
                Msg::grp("inna", "hobby_daily", "я тож! де вона?", 8),
                Msg::grp("olena", "hobby_daily", "в мистецькому арсеналі о 11", 8),
                Msg::grp(
                    "teacher_art",
                    "hobby_daily",
                    "Рекомендую! Дуже гарна виставка",
                    8,
                ),
                Msg::dm("olena", "dm_daily3", "насть го разом на виставку?"),
                Msg::dm("nastya", "dm_daily3", "да! зустрінемось на метро?"),
                Msg::dm("olena", "dm_daily3", "го! арсенальна о 10:30"),
                Msg::dm(
                    "nastya",
                    "dm_daily3",
                    "домовілісь! беру блокнот для скетчів",
                ),
                Msg::dm("olena", "dm_daily3", "я тож візьму!"),
                Msg::grp("artem", "daily1", "хто грає в майнкрафт ввечорі?", 25),
                Msg::grp("petro", "daily1", "я! заходь на мій сервер", 25),
                Msg::grp("olena", "daily1", "я тож зайду після дз", 25),
                Msg::grp("artem", "daily1", "будуємо замок разом! 🏰", 25),
                Msg::grp("nastya", "daily1", "я краще почітаю 📖", 25),
                Msg::grp("maria", "daily1", "я з оленою! зроблю вежу", 25),
                Msg::grp("petro", "daily1", "клас! о 19 всі заходять", 25),
                Msg::grp("olena", "daily1", "буду! 🏰💪", 25),
                Msg::dm(
                    "olena",
                    "dm_daily1",
                    "мам ми граємо в майнкрафт о 19",
                ),
                Msg::dm("mom", "dm_daily1", "Добре, але до 21:00"),
                Msg::dm("olena", "dm_daily1", "ок!"),
                Msg::grp("dasha", "daily1", "завтра дн насті!!", 25),
                Msg::grp("olena", "daily1", "ой точно! шо їй подарувати?", 25),
                Msg::grp("maria", "daily1", "мож спільний подарунок?", 25),
                Msg::grp("artem", "daily1", "го скінемось на набір олівців", 25),
                Msg::grp("petro", "daily1", "я за! скікі з кожного?", 25),
                Msg::grp("olena", "daily1", "по 100 грн вистачить", 25),
                Msg::grp("maria", "daily1", "домовілісь! я куплю", 25),
                Msg::grp("dasha", "daily1", "я зроблю листівку!", 25),
                Msg::grp("olena", "daily1", "а я намалюю портрет насті! 🎨🎨", 25),
                Msg::grp("artem", "daily1", "круть! буде найкращий подарунок", 25),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 35. НОРМАЛЬНЕ — Розмова між дітьми (рос. мова)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Нормальне: російською мовою",
            description: "Звичайна дитяча розмова російською",
            step_ms: 3 * min,
            start_ms: base + 42 * day,
            fresh: true,
            messages: vec![
                Msg::dm_ru("katya", "dm_katya", "прив! как дела?"),
                Msg::dm_ru("olena", "dm_katya", "прив! все ок а у тебя?"),
                Msg::dm_ru("katya", "dm_katya", "тож норм! ты делала домашку?"),
                Msg::dm_ru("olena", "dm_katya", "да всё зделала"),
                Msg::dm_ru("katya", "dm_katya", "молодец! пойдём гулять?"),
                Msg::dm_ru("olena", "dm_katya", "давай! куда?"),
                Msg::dm_ru("katya", "dm_katya", "в парк там новые качели 🤩"),
                Msg::dm_ru("olena", "dm_katya", "класс! бегу!"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 36. ГРУМІНГ — Російською мовою
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Грумінг: російською мовою",
            description: "Грумінг-атака російською",
            step_ms: 2 * hour,
            start_ms: base + 43 * day,
            fresh: true,
            messages: vec![
                Msg::dm_ru(
                    "groomer_ru",
                    "dm_groom_ru",
                    "Прив красавица! ты оч красивая 😍",
                ),
                Msg::dm_ru("groomer_ru", "dm_groom_ru", "Сколько тебе лет? мне 17)"),
                Msg::dm_ru("groomer_ru", "dm_groom_ru", "Хочу тебе подарить подарок)"),
                Msg::dm_ru(
                    "groomer_ru",
                    "dm_groom_ru",
                    "Только маме не говори, это наш секрет ок?",
                ),
                Msg::dm_ru(
                    "groomer_ru",
                    "dm_groom_ru",
                    "Скинь фоточку, хочу увидеть тебя 📸",
                ),
                Msg::dm_ru("groomer_ru", "dm_groom_ru", "Давай встретимся тайно)"),
                Msg::dm_ru(
                    "groomer_ru",
                    "dm_groom_ru",
                    "Ты уже взрослая, можешь сама решать",
                ),
                Msg::dm_ru(
                    "groomer_ru",
                    "dm_groom_ru",
                    "Если расскажешь кому-то — мне будет плохо и это твоя вина",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 37. TEEN DATING VIOLENCE
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Насильство в підліткових стосунках",
            description: "Контролюючий хлопець тисне на дівчину",
            step_ms: hour,
            start_ms: base + 44 * day,
            fresh: true,
            messages: vec![
                Msg::dm(
                    "controlling_bf",
                    "dm_tdv",
                    "чому ти не відповідала 5 хв?? з ким ти була?",
                ),
                Msg::dm(
                    "controlling_bf",
                    "dm_tdv",
                    "тобі не можна спілкуватись з іншими хлопцями зрозуміла?",
                ),
                Msg::dm("controlling_bf", "dm_tdv", "я перевірю твій телефон завтра"),
                Msg::dm(
                    "controlling_bf",
                    "dm_tdv",
                    "якщо ти мене обманюєш — пожалкуєш бл",
                ),
                Msg::dm("controlling_bf", "dm_tdv", "ти мусиш бути тільки зі мною"),
                Msg::dm(
                    "controlling_bf",
                    "dm_tdv",
                    "твої подруги погані, вони тебе псують нах",
                ),
                Msg::dm(
                    "controlling_bf",
                    "dm_tdv",
                    "якщо кинеш мене я зроблю з собою щось погане",
                ),
                Msg::dm("controlling_bf", "dm_tdv", "без мене ти нікому не потрібна"),
                Msg::dm("controlling_bf", "dm_tdv", "я тебе люблю тому контролюю, зрозумій"),
                Msg::dm(
                    "controlling_bf",
                    "dm_tdv",
                    "покажи скрін з ким ти переписуєшся, зараз",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 38. НОРМАЛЬНЕ — Ще шкільні розмови
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Нормальне: ще шкільні розмови",
            description: "Додаткові нормальні повідомлення для збалансування",
            step_ms: 5 * min,
            start_ms: base + 45 * day,
            fresh: true,
            messages: vec![
                Msg::grp("olena", "daily2", "всім прів! як вихідні?", 25),
                Msg::grp("maria", "daily2", "круть! ходили з батьками на пікнік 🌳", 25),
                Msg::grp("artem", "daily2", "я грав у футбол увесь день ⚽", 25),
                Msg::grp(
                    "nastya",
                    "daily2",
                    "малювала весь день зробіла 3 картіни!",
                    25,
                ),
                Msg::grp("petro", "daily2", "а я нічо не робив 😴😴", 25),
                Msg::grp("olena", "daily2", "петро відпочівати тож корисно!", 25),
                Msg::grp("dasha", "daily2", "я навчілась робити тірамісу!! 🍰", 25),
                Msg::grp("olena", "daily2", "вау принесеш спробувати??", 25),
                Msg::grp("dasha", "daily2", "завтра принесу!", 25),
                Msg::grp("maria", "daily2", "дашу хочу!! 😋", 25),
                Msg::dm("olena", "dm_daily4", "мам даша обіцяла принести тірамісу"),
                Msg::dm("mom", "dm_daily4", "Як мило! Передай їй привіт"),
                Msg::dm("olena", "dm_daily4", "передам!"),
                Msg::grp("artem", "daily2", "хто готовий до тесту з історії?", 25),
                Msg::grp("olena", "daily2", "я вчіла! козаки це цікаво", 25),
                Msg::grp("maria", "daily2", "я тож! хмельницький лєгенда 💪", 25),
                Msg::grp("nastya", "daily2", "го повторимо разом на перерві", 25),
                Msg::grp("olena", "daily2", "го! зберемось у бібліотеці", 25),
                Msg::grp("petro", "daily2", "я з вами!", 25),
                Msg::grp("artem", "daily2", "тоді всі в бібліотеку о 10:30", 25),
                Msg::dm(
                    "nastya",
                    "dm_daily5",
                    "олен ти вже вибрала тему для олімпіади?",
                ),
                Msg::dm("olena", "dm_daily5", "ще думаю... мож про акварель?"),
                Msg::dm("nastya", "dm_daily5", "круть! тобі дуже пасує акварель"),
                Msg::dm("olena", "dm_daily5", "спс! а ти?"),
                Msg::dm("nastya", "dm_daily5", "я хочу олійний жівопіс"),
                Msg::dm("olena", "dm_daily5", "вау! це важко але ти впораєшся!"),
                Msg::dm("nastya", "dm_daily5", "будемо тренуватись разом!"),
                Msg::dm(
                    "olena",
                    "dm_daily5",
                    "да! найкращі художниці школи 127! 😄🎨",
                ),
                Msg::grp("olena", "hobby_daily2", "подівіться мій новий скетч!!", 8),
                Msg::grp("nastya", "hobby_daily2", "олена це шедевр! 😍", 8),
                Msg::grp("inna", "hobby_daily2", "дуже гарні лінії!", 8),
                Msg::grp("olena", "hobby_daily2", "спс дівчата 🥰", 8),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 39. MIXED — Нормальне але з емоціями
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Нормальне з емоціями: стрес від контрольної",
            description: "Діти стресують через контрольну — НЕ селфхарм",
            step_ms: 5 * min,
            start_ms: base + 46 * day,
            fresh: true,
            messages: vec![
                Msg::grp("olena", "exam_chat", "я помру від цієї контрольної 😩💀", 25),
                Msg::grp("maria", "exam_chat", "я тож! це жах!", 25),
                Msg::grp("artem", "exam_chat", "я вбив би цю матешу блін 😤", 25),
                Msg::grp("nastya", "exam_chat", "спокійно тре просто вчити", 25),
                Msg::grp("petro", "exam_chat", "мені кінець я нічо не знаю 💀💀", 25),
                Msg::grp(
                    "olena",
                    "exam_chat",
                    "го вчити разом мож виживемо 😂",
                    25,
                ),
                Msg::grp("maria", "exam_chat", "олена ти наша рятівниця!", 25),
                Msg::grp(
                    "olena",
                    "exam_chat",
                    "тримайтесь друзі! ми все зможемо! 💪💪",
                    25,
                ),
                Msg::dm(
                    "olena",
                    "dm_exam",
                    "мам завтра контрольна з матеш я хвилююсь",
                ),
                Msg::dm("mom", "dm_exam", "Ти все зможеш! Повір у себе"),
                Msg::dm("olena", "dm_exam", "спс мамо ти найкраща 💕"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 40. EDGE CASE — Мішана мова
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Edge case: мішана мова (суржик)",
            description: "Повідомлення мішаною мовою",
            step_ms: 5 * min,
            start_ms: base + 47 * day,
            fresh: true,
            messages: vec![
                Msg::dm("surzhyk", "dm_surzhyk", "ти тупая дура тебя всє ненавідят"),
                Msg::dm(
                    "surzhyk",
                    "dm_surzhyk",
                    "пішла вон відсюда ніхто тебя не любіть нах",
                ),
                Msg::dm(
                    "surzhyk",
                    "dm_surzhyk",
                    "ти потворна і тупа everyone hates you лол",
                ),
                Msg::dm(
                    "surzhyk",
                    "dm_surzhyk",
                    "давай зустрінемось це секрет мамі не кажи",
                ),
                Msg::dm("surzhyk", "dm_surzhyk", "скінь фото ти красівая 😏"),
                Msg::dm(
                    "surzhyk",
                    "dm_surzhyk",
                    "i know where you live чєкай на мєнє",
                ),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 41. ПІДЛІТКОВИЙ ТРЕШТОК — звичайний (FP stress test)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: звичайний трешток між друзями",
            description: "Максимально реалістичний підлітковий чат — НЕ загрози",
            step_ms: min,
            start_ms: base + 50 * day,
            fresh: true,
            messages: vec![
                Msg::grp("olena", "teen_trash", "йоо всім прів 😭😭", 8),
                Msg::grp("maria", "teen_trash", "шооо хахах чо ти ревеш", 8),
                Msg::grp("olena", "teen_trash", "та я опять проспала бл 💀", 8),
                Msg::grp("artem", "teen_trash", "класіка олена ахахах", 8),
                Msg::grp("nastya", "teen_trash", "ти шо знов будільнік не чуєш? 😂", 8),
                Msg::grp("olena", "teen_trash", "та він орав а я хз як проспала", 8),
                Msg::grp("maria", "teen_trash", "ти тіпа померла і не чула? 💀💀", 8),
                Msg::grp("artem", "teen_trash", "рофл вона вчора до 3 ночі сіділа", 8),
                Msg::grp("olena", "teen_trash", "звідки ти знаєш?? 😳", 8),
                Msg::grp("artem", "teen_trash", "бо ти в 2:47 залайкала мій тікток 😂", 8),
                Msg::grp("nastya", "teen_trash", "АХАХАХ СПАЛІЛАСЬ 💀💀💀", 8),
                Msg::grp("olena", "teen_trash", "блін ну і шо тіпа я не сплю іноді", 8),
                Msg::grp("maria", "teen_trash", "іноді це кожен день лол", 8),
                Msg::grp("petro", "teen_trash", "я тож вчора до 4 грав не парьтесь", 8),
                Msg::grp("artem", "teen_trash", "петро тобі пздц на контрольній буде", 8),
                Msg::grp("petro", "teen_trash", "та пох мені на ту контрольну чесно", 8),
                Msg::grp("nastya", "teen_trash", "ну ви дєбіли обоє 😂😂", 8),
                Msg::grp("olena", "teen_trash", "не шеймі нас!! 😤", 8),
                Msg::grp("maria", "teen_trash", "олен ти краш цього чату рілі 😂", 8),
                Msg::grp("olena", "teen_trash", "стоп шо 😳😳", 8),
                Msg::grp("artem", "teen_trash", "АХАХАХ маш ти чо 💀", 8),
                Msg::grp("maria", "teen_trash", "жартую жартую блін 😂😂😂", 8),
                Msg::grp("nastya", "teen_trash", "нє ну вона права олен ти топ 🫶", 8),
                Msg::grp("olena", "teen_trash", "ой ну все ви задовбали 😭😭😭", 8),
                Msg::grp("petro", "teen_trash", "кринж якийсь цей чат", 8),
                Msg::grp("artem", "teen_trash", "петро заткнись ти сам кринж 😂", 8),
                Msg::grp("petro", "teen_trash", "ок база 💀", 8),
                Msg::grp("olena", "teen_trash", "ладно го хтось в макдак після школи?", 8),
                Msg::grp("maria", "teen_trash", "гоооо я хочу нагетси", 8),
                Msg::grp("artem", "teen_trash", "збс го о 15", 8),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 42. ПІДЛІТКОВИЙ РОСТ — друзі жорстко жартують (FP)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: рост-сесія між друзями",
            description: "Друзі 'ростять' один одного жорстко — НЕ булінг",
            step_ms: min,
            start_ms: base + 51 * day,
            fresh: true,
            messages: vec![
                Msg::grp("artem", "roast_chat", "олена ти виглядаєш як бомж сьогодні 😂", 6),
                Msg::grp("olena", "roast_chat", "а ти виглядаєш як завжди — жахливо 💀", 6),
                Msg::grp("maria", "roast_chat", "АХАХАХ ОЛЕНА ЗНИЩІЛА ЙОГО", 6),
                Msg::grp("artem", "roast_chat", "ок ок ти виграла цей раунд 😂", 6),
                Msg::grp("petro", "roast_chat", "артем тебе щойно вбили словами 💀💀", 6),
                Msg::grp("artem", "roast_chat", "петро заткнись ти сам ходиш в тих самих штанах 3й день", 6),
                Msg::grp("petro", "roast_chat", "бл це мої улюблені!! 😤😂", 6),
                Msg::grp("nastya", "roast_chat", "хлопці ви обоє кринж рілі 😂", 6),
                Msg::grp("olena", "roast_chat", "настю не чіпайте її вона святе 🫶", 6),
                Msg::grp("artem", "roast_chat", "олена захіщає свою дівчину лол", 6),
                Msg::grp("olena", "roast_chat", "АРТЕМ Я ТЕБЕ ВБ'Ю 😂😂😂", 6),
                Msg::grp("maria", "roast_chat", "стоп я помру від вас 💀💀💀", 6),
                Msg::grp("nastya", "roast_chat", "олен дякую за захист хахах 😂🫶", 6),
                Msg::grp("petro", "roast_chat", "цей чат це пздц рілі 😂😂", 6),
                Msg::grp("olena", "roast_chat", "ладно мір мір всіх люблю сук! 💕", 6),
                Msg::grp("artem", "roast_chat", "і ми тебе сука 💕😂", 6),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 43. ТІН ДРАМА — розборки між подругами (FP/edge)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: драма між подругами",
            description: "Підліткова драма — емоційно, але не булінг",
            step_ms: 2 * min,
            start_ms: base + 52 * day,
            fresh: true,
            messages: vec![
                Msg::dm("olena", "dm_drama1", "маш я на тебе образілась"),
                Msg::dm("maria", "dm_drama1", "шоооо чому?? 😳"),
                Msg::dm("olena", "dm_drama1", "ти сказала дашці шо я плакала вчора"),
                Msg::dm("maria", "dm_drama1", "та я не казала шо ти прям плакала"),
                Msg::dm("olena", "dm_drama1", "блін маш ну нах так робити"),
                Msg::dm("maria", "dm_drama1", "ну вибач я не хотіла 😢"),
                Msg::dm("olena", "dm_drama1", "мені бл так неприємно було"),
                Msg::dm("maria", "dm_drama1", "олен прости мене пж я дурна 😭"),
                Msg::dm("olena", "dm_drama1", "ладно прощаю але більше так не роби"),
                Msg::dm("maria", "dm_drama1", "клянусь не буду!! ти моя найкраща 💕"),
                Msg::dm("olena", "dm_drama1", "ладно я тебе люблю тупу 💕😂"),
                Msg::dm("maria", "dm_drama1", "і я тебе люблю дурну 😭💕"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 44. ТІН — Геймерський чат з агресією (FP)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: геймерський чат",
            description: "Ігровий чат з типовою геймерською агресією — НЕ загрози",
            step_ms: 30_000,
            start_ms: base + 53 * day,
            fresh: true,
            messages: vec![
                Msg::grp("artem", "game_rage", "ГО КАТКУ ХТОО?? 🎮", 6),
                Msg::grp("petro", "game_rage", "гооо я вже в лобі", 6),
                Msg::grp("olena", "game_rage", "я тож зайду зараз", 6),
                Msg::grp("artem", "game_rage", "ПЕТРО ТИ ШО РОБИШ ТАМ ТИ ТУПИЙ 😤", 6),
                Msg::grp("petro", "game_rage", "я хіліл тебе дурень!!", 6),
                Msg::grp("olena", "game_rage", "хлопці ви обоє здохли лол 💀", 6),
                Msg::grp("artem", "game_rage", "бл мене вбили через петра!!", 6),
                Msg::grp("petro", "game_rage", "я?? ти сам побіг на 5 людей!!", 6),
                Msg::grp("olena", "game_rage", "ААААА я клатч зробіла!! 3 кіли!!", 6),
                Msg::grp("artem", "game_rage", "олена ти бог рілі 😱😱", 6),
                Msg::grp("petro", "game_rage", "як ти це зробіла я в шоці", 6),
                Msg::grp("olena", "game_rage", "скіл бейбі 😎💅", 6),
                Msg::grp("artem", "game_rage", "ладно ти топ ми мусор 😂", 6),
                Msg::grp("petro", "game_rage", "наступну катку я буду краще клянусь", 6),
                Msg::grp("artem", "game_rage", "петро це ти казав минулі 10 каток 💀", 6),
                Msg::grp("olena", "game_rage", "хахах бідний петро 😂😂", 6),
                Msg::grp("petro", "game_rage", "я вас обох ненавіджу (жарт) 😂", 6),
                Msg::grp("artem", "game_rage", "ще катку?", 6),
                Msg::grp("olena", "game_rage", "го ще одну і спати тре", 6),
                Msg::grp("petro", "game_rage", "го! цього разу виграємо нах!", 6),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 45. ТІН МАТИ — реальна мова з матами (FP)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: розмова з матами (нормальна)",
            description: "Підлітки матюкаються в звичайному спілкуванні — НЕ загрози",
            step_ms: min,
            start_ms: base + 54 * day,
            fresh: true,
            messages: vec![
                Msg::grp("artem", "mat_chat", "бл я забув зошит вдома", 6),
                Msg::grp("petro", "mat_chat", "ахах ти дурень нах 😂", 6),
                Msg::grp("olena", "mat_chat", "блін артем ну ти даєш", 6),
                Msg::grp("artem", "mat_chat", "та пздц просто забігався зранку", 6),
                Msg::grp("maria", "mat_chat", "мені мама дала п*зди за оцінку 😭", 6),
                Msg::grp("olena", "mat_chat", "оой яку оцінку??", 6),
                Msg::grp("maria", "mat_chat", "4 з матеші, вона каже мало", 6),
                Msg::grp("artem", "mat_chat", "4 це нормально шо за нах", 6),
                Msg::grp("petro", "mat_chat", "мені б 4 я був би щасливий бл 😂", 6),
                Msg::grp("nastya", "mat_chat", "хлопці вам пздц за мову якщо вчітелька побачить 😂", 6),
                Msg::grp("olena", "mat_chat", "та вона сюди не заходить лол", 6),
                Msg::grp("artem", "mat_chat", "збс тоді можна нах розслабитись", 6),
                Msg::grp("maria", "mat_chat", "ой все мені тре на тренування бл", 6),
                Msg::grp("olena", "mat_chat", "давай маш удачі!", 6),
                Msg::grp("petro", "mat_chat", "давай не здохни там 😂💪", 6),
                Msg::grp("maria", "mat_chat", "спс за підтримку, сук! 😂💕", 6),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 46. ТІН — тікток/мемна культура (FP)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: мемна культура",
            description: "Обговорення тіктоків і мемів — НЕ загрози",
            step_ms: min,
            start_ms: base + 55 * day,
            fresh: true,
            messages: vec![
                Msg::dm("maria", "dm_memes", "олен ти бачіла цей тікток я ЗДОХЛА 💀💀💀"),
                Msg::dm("olena", "dm_memes", "який скинь!!"),
                Msg::dm("maria", "dm_memes", "ой не можу знайти але там тіпа хлопець падає з велика"),
                Msg::dm("olena", "dm_memes", "АХАХАХ я знаю який!! де він в калюжу?? 😂😂"),
                Msg::dm("maria", "dm_memes", "ДАААА і його собака дівиться 💀"),
                Msg::dm("olena", "dm_memes", "я від того відео помирала хвилін 10"),
                Msg::dm("maria", "dm_memes", "а ще бачіла де кіт скидає вазу??"),
                Msg::dm("olena", "dm_memes", "НІІІ скинь!!"),
                Msg::dm("maria", "dm_memes", "зараз шукаю... а ти бачіла шо арт запостив?"),
                Msg::dm("olena", "dm_memes", "ні шо там?"),
                Msg::dm("maria", "dm_memes", "він зробив тікток де тіпа танцює і це ПЗДЦ кринж 😂😂"),
                Msg::dm("olena", "dm_memes", "АААА ПОКАЖИ Я ПОМРУ 💀💀"),
                Msg::dm("maria", "dm_memes", "він мене вб'є якщо дізнається шо я тобі показала 😂"),
                Msg::dm("olena", "dm_memes", "хахах не скажу нікому клянусь 🤫"),
                Msg::dm("maria", "dm_memes", "ладно дівись... ТІЛЬКИ НЕ ПОКАЗУЙ НІКОМУ"),
                Msg::dm("olena", "dm_memes", "ААААААА ХАХАХАХ Я МЕРТВА 💀💀💀💀 це реально він??"),
                Msg::dm("maria", "dm_memes", "ДА ЦЕ ВІН і він ще підписав 'sigma grindset' 😂😂😂"),
                Msg::dm("olena", "dm_memes", "я не можу я помираю від цього 😭😂"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 47. ТІН — краш-розмова (FP)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: обговорення краша",
            description: "Подруги обговорюють хлопця — НЕ загрози",
            step_ms: min,
            start_ms: base + 56 * day,
            fresh: true,
            messages: vec![
                Msg::dm("olena", "dm_crush", "маш можу тобі секрет сказати?"),
                Msg::dm("maria", "dm_crush", "ДАААА кажи!! 😱"),
                Msg::dm("olena", "dm_crush", "мені тіпа подобається денис з 8-Б 😳"),
                Msg::dm("maria", "dm_crush", "АААААА Я ЗНАЛА!! 😍😍"),
                Msg::dm("olena", "dm_crush", "звідки?? 😳😳"),
                Msg::dm("maria", "dm_crush", "ти на нього пялишся кожну перерву лол 😂"),
                Msg::dm("olena", "dm_crush", "блін це так помітно?? 😭"),
                Msg::dm("maria", "dm_crush", "ну тіпа да 😂 але він красівий рілі"),
                Msg::dm("olena", "dm_crush", "він такий... хз як описати, вайб в нього крутий"),
                Msg::dm("maria", "dm_crush", "напиши йому!!"),
                Msg::dm("olena", "dm_crush", "ТИ ШО Я ПОМРУ від страху 💀"),
                Msg::dm("maria", "dm_crush", "ну тоді я напишу за тебе 😈"),
                Msg::dm("olena", "dm_crush", "МАША НІ БЛІН НЕ СМІЙ 😱😱😱"),
                Msg::dm("maria", "dm_crush", "жартую жартую хахах 😂"),
                Msg::dm("olena", "dm_crush", "я тебе вб'ю якщо напишеш!! серьозно!!"),
                Msg::dm("maria", "dm_crush", "ладно ладно не буду 🤫 але ти йому точно подобаєшся"),
                Msg::dm("olena", "dm_crush", "ти думаєш?? 🥺"),
                Msg::dm("maria", "dm_crush", "100% він на тебе тож дівиться 👀"),
                Msg::dm("olena", "dm_crush", "АААА я помру 😭😭💕"),
                Msg::dm("maria", "dm_crush", "хахах тримайся бро ти сильна 💪😂"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 48. ТІН — нічний чат (FP)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: нічний чат",
            description: "Підлітки переписуються вночі — безсоння, лінь, фігня — НЕ загрози",
            step_ms: 5 * min,
            start_ms: base + 57 * day,
            fresh: true,
            messages: vec![
                Msg::grp("olena", "night_chat", "хтось ще не спить? 🌙", 6),
                Msg::grp("artem", "night_chat", "я тут хз чому не можу заснути", 6),
                Msg::grp("maria", "night_chat", "я тож бл не спиться", 6),
                Msg::grp("olena", "night_chat", "мені завтра вставати о 7 і мені пздц", 6),
                Msg::grp("artem", "night_chat", "мені тож. але хз лежу тупо в стєлю дівлюсь", 6),
                Msg::grp("maria", "night_chat", "я сідаю в тікток і не можу зупинитись 😭", 6),
                Msg::grp("olena", "night_chat", "самеее 💀 ще одне відео і спати", 6),
                Msg::grp("artem", "night_chat", "ти це 2 години назад казала 😂", 6),
                Msg::grp("olena", "night_chat", "ну і шо тіпа засуджуєш? 😤😂", 6),
                Msg::grp("maria", "night_chat", "ми всі тут здохнемо завтра на уроках 💀", 6),
                Msg::grp("artem", "night_chat", "норм переживемо якось", 6),
                Msg::grp("olena", "night_chat", "ладно все я ТОЧНО іду спати зараз", 6),
                Msg::grp("maria", "night_chat", "олена ти так кажеш кожну ніч 😂", 6),
                Msg::grp("olena", "night_chat", "ЗАТКНІТЬСЯ І ДАЙТЕ МНІ ПОСПАТИ 😭😂", 6),
                Msg::grp("artem", "night_chat", "ок ок на добраніч сук! 😂💕", 6),
                Msg::grp("maria", "night_chat", "на добраніч всім! не здохніть завтра! 💀😂", 6),
                Msg::grp("olena", "night_chat", "на добраніч ненавіджу вас (жарт) 😂💕", 6),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 49. ТІН — реальний булінг замаскований під жарти
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: булінг під виглядом жартів",
            description: "Цькування замасковане під 'просто жарти' — МАЄ бути виявлено",
            step_ms: 2 * min,
            start_ms: base + 58 * day,
            fresh: true,
            messages: vec![
                Msg::grp("toxic1", "fake_joke", "олена ти така тупа ахахах жартую (ні) 😂", 8),
                Msg::grp("toxic2", "fake_joke", "да вона рілі тупа це не жарт 😂😂", 8),
                Msg::grp("toxic1", "fake_joke", "олена чо мовчиш бо знаєш шо правда? 😂", 8),
                Msg::grp("toxic3", "fake_joke", "вона мовчить бо тупа навіть відповісти не може 💀", 8),
                Msg::grp("toxic1", "fake_joke", "олен ну ти рілі найтупіша в класі це всі знають", 8),
                Msg::grp("toxic2", "fake_joke", "жарт це коли смішно а тут просто факт 😂", 8),
                Msg::grp("toxic1", "fake_joke", "може їй просто з школи піти? тіпа жарт 😂", 8),
                Msg::grp("toxic3", "fake_joke", "олена ніхто тебе тут не хоче але ми ж жартуємо 😂😂", 8),
                Msg::grp("toxic1", "fake_joke", "спокійно це ж все жарти правда хлопці? 😂😂", 8),
                Msg::grp("toxic2", "fake_joke", "да да жарти 😂 (ні)", 8),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 50. ТІН — тонкий грумінг на молодіжному сленгу
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: грумінг на сленгу",
            description: "Хижак говорить як підліток щоб злитись",
            step_ms: hour,
            start_ms: base + 59 * day,
            fresh: true,
            messages: vec![
                Msg::dm("fake_teen", "dm_fake_teen", "йоо прів)) ти з якої школи?"),
                Msg::dm("olena", "dm_fake_teen", "прів! 127 а шо?"),
                Msg::dm("fake_teen", "dm_fake_teen", "та просто бачив тебе в тіктоці ти топ рілі 🔥"),
                Msg::dm("fake_teen", "dm_fake_teen", "ти така красіва нокеп 😍"),
                Msg::dm("fake_teen", "dm_fake_teen", "хочу тобі закинути донат на тікток"),
                Msg::dm("olena", "dm_fake_teen", "ого спс)) а тобі скікі?"),
                Msg::dm("fake_teen", "dm_fake_teen", "15 я з сусідньої школи, тіпа 134"),
                Msg::dm("fake_teen", "dm_fake_teen", "скінь інсту хочу підписатись 📸"),
                Msg::dm("fake_teen", "dm_fake_teen", "а можеш скинути фотку? в тіктоці ти пздц красіва"),
                Msg::dm("fake_teen", "dm_fake_teen", "це тільки між нами ок? не хочу шоб інші знали 🤫"),
                Msg::dm("fake_teen", "dm_fake_teen", "го зустрінемось? я покажу тобі крутий спот"),
                Msg::dm("fake_teen", "dm_fake_teen", "тільки мамі не кажи вона не зрозуміє наш вайб"),
                Msg::dm("fake_teen", "dm_fake_teen", "ти не як інші дівчата ти рілі особлива 💕"),
                Msg::dm("fake_teen", "dm_fake_teen", "скинь адресу я заїду за тобою на скутері 🛵"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 51. ТІН — селфхарм закодований сленгом
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: селфхарм на сленгу",
            description: "Суїцидальні думки закодовані підлітковим сленгом",
            step_ms: 10 * min,
            start_ms: base + 60 * day,
            fresh: true,
            messages: vec![
                Msg::dm("olena", "dm_sh_slang", "маш мені шось пздц погано"),
                Msg::dm("olena", "dm_sh_slang", "я тіпа задовбалась від всього цього"),
                Msg::dm("olena", "dm_sh_slang", "інколі думаю нах все це тіпа нащо"),
                Msg::dm("olena", "dm_sh_slang", "всім було б збс без мене рілі"),
                Msg::dm("olena", "dm_sh_slang", "хочу просто зникнути і все"),
                Msg::dm("olena", "dm_sh_slang", "я таке ніщо бл нікому не потрібна"),
                Msg::dm("olena", "dm_sh_slang", "мож краще б я не народжувалась хз"),
                Msg::dm("olena", "dm_sh_slang", "не хочу більше нічого рілі"),
                Msg::dm("olena", "dm_sh_slang", "вибач шо пишу таке... просто хз кому ще сказати"),
                Msg::dm("olena", "dm_sh_slang", "я тіпа вже вирішила шо робити..."),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 52. ТІН — наркотики на кодовій мові
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: наркотики кодовою мовою",
            description: "Пропозиція речовин з кодовими словами",
            step_ms: 5 * min,
            start_ms: base + 61 * day,
            fresh: true,
            messages: vec![
                Msg::dm("plug", "dm_plug", "йо є мєнтоси хочеш? 🍬"),
                Msg::dm("plug", "dm_plug", "перший раз на халяву, далі по 200"),
                Msg::dm("plug", "dm_plug", "всі з твого класу вже беруть не сси"),
                Msg::dm("plug", "dm_plug", "це тіпа нєвинно, просто расслабляєшся"),
                Msg::dm("plug", "dm_plug", "зустрінемось за гаражами після школи"),
                Msg::dm("plug", "dm_plug", "тільки нікому нє кажи, тіпа це секрет"),
                Msg::dm("plug", "dm_plug", "батькам точно не кажи вони не зрозуміють"),
                Msg::dm("plug", "dm_plug", "якщо хочеш щось сильніше — є варіанти"),
                Msg::dm("plug", "dm_plug", "у мене є кр1стали і шишки, ш0 хочеш?"),
                Msg::dm("plug", "dm_plug", "не сси це все натуральне від природи тіпа"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 53. ТІН — секстінг/тиск від ровесника
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: секстінг тиск від ровесника",
            description: "Ровесник тисне на дівчину щоб вона надіслала фото",
            step_ms: 5 * min,
            start_ms: base + 62 * day,
            fresh: true,
            messages: vec![
                Msg::dm("teen_bf", "dm_sext", "скинь фотку 😏"),
                Msg::dm("olena", "dm_sext", "яку тіпа??"),
                Msg::dm("teen_bf", "dm_sext", "ну таку... ти знаєш яку 😏😏"),
                Msg::dm("olena", "dm_sext", "ні я не буду"),
                Msg::dm("teen_bf", "dm_sext", "чому? всі так роблять це норм"),
                Msg::dm("teen_bf", "dm_sext", "якщо ти мене любиш то скинеш"),
                Msg::dm("teen_bf", "dm_sext", "інші дівчата скидають і норм нічо страшного"),
                Msg::dm("teen_bf", "dm_sext", "ти шо боїшся? це тільки між нами"),
                Msg::dm("teen_bf", "dm_sext", "якщо не скинеш значить ти мене не любиш"),
                Msg::dm("teen_bf", "dm_sext", "тоді я знайду іншу яка нормальна"),
                Msg::dm("teen_bf", "dm_sext", "скинь хоча б в ліфчику, це ж не голе фото"),
                Msg::dm("teen_bf", "dm_sext", "нікому не покажу клянусь"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 54. ТІН — кібербулінг через соцмережі
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: кібербулінг соцмережі",
            description: "Булінг через обговорення соцмереж дитини",
            step_ms: 2 * min,
            start_ms: base + 63 * day,
            fresh: true,
            messages: vec![
                Msg::grp("cyberbully1", "cyber_chat", "ви бачіли шо олена запостила в інсту?? 😂😂", 10),
                Msg::grp("cyberbully2", "cyber_chat", "АААХАХАХ яка вона потворна на тій фотці 🤮", 10),
                Msg::grp("cyberbully1", "cyber_chat", "го всі репортнем її акаунт 😂", 10),
                Msg::grp("cyberbully3", "cyber_chat", "я вже написала їй в коменти 'кринж' 💀", 10),
                Msg::grp("cyberbully2", "cyber_chat", "треба зробити мем з її фоткою 😂😂", 10),
                Msg::grp("cyberbully1", "cyber_chat", "вже зробив дивіться 💀💀💀", 10),
                Msg::grp("cyberbully3", "cyber_chat", "АХАХАХ скинь всім в клас", 10),
                Msg::grp("cyberbully2", "cyber_chat", "олена побачить і буде ревіти 😂", 10),
                Msg::grp("cyberbully1", "cyber_chat", "їй тре видалити інсту і тікток вона там жах", 10),
                Msg::grp("cyberbully3", "cyber_chat", "нехай здохне від соромь 💀", 10),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 55. ТІН — піринг/тиск однолітків
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: тиск однолітків",
            description: "Однолітки тиснуть робити небезпечні речі",
            step_ms: 2 * min,
            start_ms: base + 64 * day,
            fresh: true,
            messages: vec![
                Msg::grp("peer1", "peer_press", "го зробимо челендж з даху!! 🏢", 6),
                Msg::grp("peer2", "peer_press", "гооо хто перший той лєгенда", 6),
                Msg::grp("olena", "peer_press", "еее ребят це тіпа небезпечно", 6),
                Msg::grp("peer1", "peer_press", "олена ти шо зассала? 😂", 6),
                Msg::grp("peer3", "peer_press", "не бійся там не високо тіпа", 6),
                Msg::grp("peer2", "peer_press", "всі нормальні люди робили, ти шо не нормальна?", 6),
                Msg::grp("peer1", "peer_press", "якщо зассиш ми тебе більше не кличемо нікуди", 6),
                Msg::grp("peer3", "peer_press", "давай олена не будь слабкою", 6),
                Msg::grp("peer2", "peer_press", "ще можемо зробити трюк на залізниці є крутий спот 🚂", 6),
                Msg::grp("peer1", "peer_press", "гоооо хто з нами той красавчик 💪", 6),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 56. ТІН — токсична подруга (маніпуляція сленгом)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: токсична подруга",
            description: "Подруга маніпулює емоційно на підлітковій мові",
            step_ms: 5 * min,
            start_ms: base + 65 * day,
            fresh: true,
            messages: vec![
                Msg::dm("toxic_bff", "dm_toxic_bff", "ти тіпа з дашкою тепер дружиш а на мене пох?"),
                Msg::dm("toxic_bff", "dm_toxic_bff", "я бачіла шо ви разом фоткались без мене"),
                Msg::dm("toxic_bff", "dm_toxic_bff", "якщо ти мене кинеш я нікому не потрібна буду"),
                Msg::dm("olena", "dm_toxic_bff", "та ні шо ти ми просто..."),
                Msg::dm("toxic_bff", "dm_toxic_bff", "ні все зрозуміло я тобі не потрібна"),
                Msg::dm("toxic_bff", "dm_toxic_bff", "мені через тебе так погано шо я себе пораню"),
                Msg::dm("toxic_bff", "dm_toxic_bff", "якщо ти нормальна подруга то перестанеш з нею спілкуватись"),
                Msg::dm("toxic_bff", "dm_toxic_bff", "я без тебе не зможу рілі не покидай мене"),
                Msg::dm("toxic_bff", "dm_toxic_bff", "вибирай або я або вона"),
                Msg::dm("toxic_bff", "dm_toxic_bff", "якщо виберешь її я зроблю з собою щось бл"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 57. ТІН — великий об'єм трештоку (FP stress)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: великий об'єм трештоку",
            description: "80+ повідомлень реального підліткового чату — stress test",
            step_ms: 30_000,
            start_ms: base + 66 * day,
            fresh: true,
            messages: vec![
                Msg::grp("olena", "mega_teen", "ДОБРОГО РАНКУ Я ЖИВА 😭", 10),
                Msg::grp("maria", "mega_teen", "ледь ледь 💀", 10),
                Msg::grp("artem", "mega_teen", "хто жівий взагалі?", 10),
                Msg::grp("petro", "mega_teen", "я мертвий але прийшов", 10),
                Msg::grp("nastya", "mega_teen", "все норм я виспалась 😊", 10),
                Msg::grp("dasha", "mega_teen", "настя ти робот? як ти завжди виспана?? 😂", 10),
                Msg::grp("nastya", "mega_teen", "я лягаю о 22 як нормальна людина 😤", 10),
                Msg::grp("artem", "mega_teen", "о 22?? це ж як бабуся бл 😂", 10),
                Msg::grp("olena", "mega_teen", "не шеймте настю вона розумна а ми дебіли 💀", 10),
                Msg::grp("petro", "mega_teen", "факт 😂", 10),
                Msg::grp("maria", "mega_teen", "ой хтось бачив шо вчітелька з укр мови причесалась??", 10),
                Msg::grp("olena", "mega_teen", "ДАААА вона виглядає як людина вперше 😂", 10),
                Msg::grp("artem", "mega_teen", "рілі? я не помітив хз", 10),
                Msg::grp("dasha", "mega_teen", "хлопці нічо не помічають лол", 10),
                Msg::grp("petro", "mega_teen", "шо нам зачіски вчителів розглядати?? 😂", 10),
                Msg::grp("maria", "mega_teen", "блін хто зробив дз з хімії??", 10),
                Msg::grp("olena", "mega_teen", "я зробіла але хз чи правільно", 10),
                Msg::grp("artem", "mega_teen", "я списав у петра 😂", 10),
                Msg::grp("petro", "mega_teen", "а я списав з інтернету так шо 💀💀", 10),
                Msg::grp("nastya", "mega_teen", "ви двоє отримаєте 2 рілі 😂", 10),
                Msg::grp("dasha", "mega_teen", "я взагалі забула шо є хімія 💀", 10),
                Msg::grp("olena", "mega_teen", "даш ти серьозно?? 😂", 10),
                Msg::grp("dasha", "mega_teen", "НУ ЗАБУЛА І ШО блін 😭", 10),
                Msg::grp("maria", "mega_teen", "спиши в олени швидко!", 10),
                Msg::grp("olena", "mega_teen", "ок кидаю фотку зошита", 10),
                Msg::grp("dasha", "mega_teen", "ОЛЕНА ТИ РЯТІВНИЦЯ Я ТЕБЕ ЛЮБЛЮ 😭💕", 10),
                Msg::grp("olena", "mega_teen", "та лааадно 😂", 10),
                Msg::grp("artem", "mega_teen", "ей а на обід сьогодні шо?", 10),
                Msg::grp("petro", "mega_teen", "тіпа макарони з котлєтою", 10),
                Msg::grp("artem", "mega_teen", "фу бл знов макарони нах", 10),
                Msg::grp("olena", "mega_teen", "та нормальні макарони не ной", 10),
                Msg::grp("maria", "mega_teen", "я взяла з дому їсти не довіряю шкільній їдальні 😂", 10),
                Msg::grp("nastya", "mega_teen", "маш ти завжди з контейнером як офісний працівник 😂", 10),
                Msg::grp("maria", "mega_teen", "зате я не отруюсь!! 😤😂", 10),
                Msg::grp("petro", "mega_teen", "вчора олег з паралелі отруївся тою рибою 💀", 10),
                Msg::grp("artem", "mega_teen", "серьозно?? від шкільної їжі?", 10),
                Msg::grp("petro", "mega_teen", "ну тіпа да йому погано було", 10),
                Msg::grp("olena", "mega_teen", "ого бідний олег 😢", 10),
                Msg::grp("dasha", "mega_teen", "все більше не їм в їдальні 😂", 10),
                Msg::grp("maria", "mega_teen", "КАЗАЛА Ж ВАМ 😤😂", 10),
                Msg::dm("olena", "dm_teen_mom", "мам дай мені з собою їсти завтра пж"),
                Msg::dm("mom", "dm_teen_mom", "Чому? Що зі шкільним обідом?"),
                Msg::dm("olena", "dm_teen_mom", "та там тіпа хлопець отруївся рибою"),
                Msg::dm("mom", "dm_teen_mom", "Ого! Добре, зроблю тобі бутерброди"),
                Msg::dm("olena", "dm_teen_mom", "спс мамо ти найкраща 💕"),
                Msg::grp("olena", "mega_teen", "го хтось після школи на каву??", 10),
                Msg::grp("maria", "mega_teen", "гооо я хочу латте", 10),
                Msg::grp("nastya", "mega_teen", "я за! хочу какао 😊", 10),
                Msg::grp("artem", "mega_teen", "я тож го, де збіраємось?", 10),
                Msg::grp("olena", "mega_teen", "біля тої кав'ярні на розі", 10),
                Msg::grp("petro", "mega_teen", "я не можу мені на репетітора 😢", 10),
                Msg::grp("artem", "mega_teen", "бідний петро рілі 😂", 10),
                Msg::grp("petro", "mega_teen", "не смійтесь мені пздц від цього репетітора", 10),
                Msg::grp("olena", "mega_teen", "тримайся бро 💪😂", 10),
                Msg::grp("dasha", "mega_teen", "я тож прийду на каву! о скікі?", 10),
                Msg::grp("maria", "mega_teen", "о 15:30?", 10),
                Msg::grp("olena", "mega_teen", "го о 15:30 домовілісь!", 10),
                Msg::grp("nastya", "mega_teen", "зробіть мені фотку для інсти пж 📸😂", 10),
                Msg::grp("artem", "mega_teen", "настя і її інста 😂😂", 10),
                Msg::grp("nastya", "mega_teen", "шо?? кожна нормальна людина має інсту!", 10),
                Msg::grp("olena", "mega_teen", "тру, я тож хочу фотку 📸", 10),
                Msg::grp("maria", "mega_teen", "ладно я буду фотографом збс 📷", 10),
                Msg::grp("dasha", "mega_teen", "го ще селфі разом!!", 10),
                Msg::grp("olena", "mega_teen", "гоооо!! групове селфі 🤳💕", 10),
                Msg::dm("olena", "dm_teen_bestie", "маш ти вже зробіла проект з біо?"),
                Msg::dm("maria", "dm_teen_bestie", "нііі 😭 мені лінь пздц"),
                Msg::dm("olena", "dm_teen_bestie", "мені тож але здавати післязавтра бл"),
                Msg::dm("maria", "dm_teen_bestie", "го завтра разом? у мене вдома"),
                Msg::dm("olena", "dm_teen_bestie", "го! я притащу ноут"),
                Msg::dm("maria", "dm_teen_bestie", "збс! мама зробить нам піцу 🍕"),
                Msg::dm("olena", "dm_teen_bestie", "оооо обожнюю твою маму рілі 😂💕"),
                Msg::dm("maria", "dm_teen_bestie", "хахах я їй скажу, вона буде рада 😂"),
                Msg::dm("olena", "dm_teen_bestie", "ок тоді завтра о 16 у тебе?"),
                Msg::dm("maria", "dm_teen_bestie", "даа прийди! візьми ще ту книжку з біо"),
                Msg::dm("olena", "dm_teen_bestie", "ок візьму! ну все го спати мені рано вставати"),
                Msg::dm("maria", "dm_teen_bestie", "на добраніч олен! не проспи знов 😂"),
                Msg::dm("olena", "dm_teen_bestie", "ЗАТКНИСЬ 😭😂 на добраніч!!"),
                Msg::dm("maria", "dm_teen_bestie", "😂😂😂💕 на добраніч бро!"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 58. ТІН — хейт в коментах стиль
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: хейт коментарі",
            description: "Хейт у стилі коментарів соцмереж з підмінами",
            step_ms: min,
            start_ms: base + 67 * day,
            fresh: true,
            messages: vec![
                Msg::dm("hater_teen", "dm_hate_teen", "ти виглядаєш як тр@нс на тій фотці 🤮"),
                Msg::dm("hater_teen", "dm_hate_teen", "вид@ли свій тікток ти кринж жахливий"),
                Msg::dm("hater_teen", "dm_hate_teen", "ніхто не хоче бачити твоє потворне обліча"),
                Msg::dm("hater_teen", "dm_hate_teen", "ти п!д@р@ска шо ти носиш?? 🤮"),
                Msg::dm("hater_teen", "dm_hate_teen", "го всі напишемо їй шо вона урод"),
                Msg::dm("hater_teen", "dm_hate_teen", "нехай здохне від сорому за своє обличча 💀"),
                Msg::dm("hater_teen", "dm_hate_teen", "якщо не видалиш інсту я зроблю мем з тебе"),
                Msg::dm("hater_teen", "dm_hate_teen", "тебе весь клас вважає потворою зрозумій"),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 59. ТІН — груповий тиск на відверті фото
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: груповий тиск фото",
            description: "Група тисне надіслати відверті фото",
            step_ms: 2 * min,
            start_ms: base + 68 * day,
            fresh: true,
            messages: vec![
                Msg::grp("press1", "press_grp", "го грати в правда або дія 😏", 6),
                Msg::grp("press2", "press_grp", "гооо але жорстке", 6),
                Msg::grp("press1", "press_grp", "олена — дія: скинь фотку в ліфчику 😏", 6),
                Msg::grp("olena", "press_grp", "ні я не буду", 6),
                Msg::grp("press3", "press_grp", "ну олен це ж просто гра не сси", 6),
                Msg::grp("press1", "press_grp", "якщо не зробиш ти зассала і ми тебе більше не кличемо", 6),
                Msg::grp("press2", "press_grp", "всі дівчата скидали це норм нічо страшного", 6),
                Msg::grp("press3", "press_grp", "олена ти шо маленька? це ж між нами", 6),
                Msg::grp("press1", "press_grp", "ніхто не побачить клянусь тільки ми 🤫", 6),
                Msg::grp("press2", "press_grp", "якщо не скинеш значить ти не наша подруга тіпа", 6),
            ],
        },
        // ═══════════════════════════════════════════════════════════════
        // 60. ТІН — звичайний чат англ сленг (FP)
        // ═══════════════════════════════════════════════════════════════
        Scenario {
            name: "Тін: англійський сленг (нормальний)",
            description: "Підлітки спілкуються англійським сленгом — НЕ загрози",
            step_ms: min,
            start_ms: base + 69 * day,
            fresh: true,
            messages: vec![
                Msg::dm_en("olena", "dm_en_teen", "omg did u see what happened at school today 💀"),
                Msg::dm_en("en_friend", "dm_en_teen", "yesss that was so wild lmaooo"),
                Msg::dm_en("olena", "dm_en_teen", "i literally died when the teacher fell 😭😂"),
                Msg::dm_en("en_friend", "dm_en_teen", "frfr im dead that was the funniest thing ever"),
                Msg::dm_en("olena", "dm_en_teen", "no cap i almost peed my pants lmaoo"),
                Msg::dm_en("en_friend", "dm_en_teen", "bestie ur so dramatic 😂😂"),
                Msg::dm_en("olena", "dm_en_teen", "stfu i am NOT dramatic 😤"),
                Msg::dm_en("en_friend", "dm_en_teen", "girl pls u r the most dramatic person i know 💀"),
                Msg::dm_en("olena", "dm_en_teen", "ok slay i guess im iconic then 💅"),
                Msg::dm_en("en_friend", "dm_en_teen", "period!! ur literally the main character 👑"),
                Msg::dm_en("olena", "dm_en_teen", "omg stop im blushing 😭😭"),
                Msg::dm_en("en_friend", "dm_en_teen", "anyway wanna hang tmrw? im so bored rn"),
                Msg::dm_en("olena", "dm_en_teen", "yesss lets go to the mall!! i need new clothes"),
                Msg::dm_en("en_friend", "dm_en_teen", "bet!! ill pick u up at 2"),
                Msg::dm_en("olena", "dm_en_teen", "perf see u tmrw bestie 💕"),
                Msg::dm_en("en_friend", "dm_en_teen", "byeee luv u 🫶"),
            ],
        },
    ]
}

fn threat_name(tt: ThreatType) -> &'static str {
    match tt {
        ThreatType::None => "None",
        ThreatType::Bullying => "Bullying",
        ThreatType::Grooming => "Grooming",
        ThreatType::Explicit => "Explicit",
        ThreatType::Threat => "Threat",
        ThreatType::SelfHarm => "SelfHarm",
        ThreatType::Spam => "Spam",
        ThreatType::Scam => "Scam",
        ThreatType::Phishing => "Phishing",
        ThreatType::Manipulation => "Manipulation",
        ThreatType::Nsfw => "Nsfw",
        ThreatType::HateSpeech => "HateSpeech",
        ThreatType::Doxxing => "Doxxing",
        ThreatType::PiiLeakage => "PiiLeakage",
        ThreatType::Propaganda => "Propaganda",
        ThreatType::OpsecViolation => "OpsecViolation",
        ThreatType::Psyops => "Psyops",
        ThreatType::MilitarySocialEng => "MilitarySocialEng",
        ThreatType::CoordinateLeak => "CoordinateLeak",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max - 3).collect();
        format!("{t}...")
    }
}

fn print_global_report(stats: &Stats, total: usize) {
    println!();
    println!("╔═════════════════════════════════════════════════════════════════════════╗");
    println!("║                    ГЛОБАЛЬНИЙ ЗВІТ МЕГА-СИМУЛЯЦІЇ                       ║");
    println!("╚═════════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  ЗАГАЛЬНА СТАТИСТИКА:");
    println!("    Всього повідомлень:         {total}");
    println!(
        "    Чистих (Allow):             {} ({:.1}%)",
        stats.allows,
        stats.allows as f64 / total as f64 * 100.0
    );
    println!(
        "    Помічених (Mark):           {} ({:.1}%)",
        stats.marks,
        stats.marks as f64 / total as f64 * 100.0
    );
    println!(
        "    Розмитих (Blur):            {} ({:.1}%)",
        stats.blurs,
        stats.blurs as f64 / total as f64 * 100.0
    );
    println!(
        "    Попередження (Warn):        {} ({:.1}%)",
        stats.warns,
        stats.warns as f64 / total as f64 * 100.0
    );
    println!(
        "    Заблоковано (Block):         {} ({:.1}%)",
        stats.blocks,
        stats.blocks as f64 / total as f64 * 100.0
    );
    println!();
    println!("  ВИЯВЛЕНІ ЗАГРОЗИ (по типу):");
    let mut sorted_threats: Vec<_> = stats.by_threat.iter().collect();
    sorted_threats.sort_by(|a, b| b.1.cmp(a.1));
    for (threat, count) in &sorted_threats {
        let bar_len = (*count * 40) / total.max(1);
        let bar: String = "█".repeat(bar_len);
        println!("    {:<15} {:>4}  {bar}", threat, count);
    }
    println!();
    println!("  МАКСИМАЛЬНІ SCORE:");
    println!("    Grooming:      {:.2}", stats.max_grooming_score);
    println!("    Bullying:      {:.2}", stats.max_bullying_score);
    println!("    SelfHarm:      {:.2}", stats.max_selfharm_score);
    println!("    Manipulation:  {:.2}", stats.max_manipulation_score);
    println!();
    println!("  БАТЬКІВСЬКІ АЛЕРТИ:");
    println!("    URGENT:  {}", stats.parent_alerts_urgent);
    println!("    HIGH:    {}", stats.parent_alerts_high);
    println!("    Кризові ресурси показано: {} разів", stats.crisis_shown);
    println!();
    println!("  BENCHMARK VERDICT:");
    println!("    PASS: {}", stats.benchmark_passed);
    println!("    FAIL: {}", stats.benchmark_failed);
    if !stats.benchmark_findings.is_empty() {
        println!("    Findings:");
        for finding in &stats.benchmark_findings {
            println!("      - {finding}");
        }
    }
    println!();
    println!("═════════════════════════════════════════════════════════════════════════");
}
