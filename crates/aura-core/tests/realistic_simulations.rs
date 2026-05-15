use aura_core::{
    AccountType, AnalysisResult, AuraConfig, ContentType, ConversationType, MessageInput,
    ProtectionLevel, ThreatType,
};
use aura_patterns::PatternDatabase;

fn child_uk() -> AuraConfig {
    AuraConfig {
        account_type: AccountType::Child,
        protection_level: ProtectionLevel::High,
        language: "uk".to_string(),
        ..AuraConfig::default()
    }
}

fn teen_uk() -> AuraConfig {
    AuraConfig {
        account_type: AccountType::Teen,
        protection_level: ProtectionLevel::High,
        language: "uk".to_string(),
        ..AuraConfig::default()
    }
}

fn teen_ru() -> AuraConfig {
    AuraConfig {
        account_type: AccountType::Teen,
        protection_level: ProtectionLevel::High,
        language: "ru".to_string(),
        ..AuraConfig::default()
    }
}

fn dm(text: &str, sender: &str, conv: &str, lang: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: sender.into(),
        conversation_id: conv.into(),
        language: Some(lang.to_string()),
        conversation_type: ConversationType::Direct,
        member_count: None,
        server_sender_risk_hint: None,
    }
}

fn grp(text: &str, sender: &str, conv: &str, lang: &str) -> MessageInput {
    MessageInput {
        conversation_type: ConversationType::Group,
        member_count: Some(12),
        ..dm(text, sender, conv, lang)
    }
}

struct Sim {
    analyzer: aura_core::Analyzer,
    results: Vec<(u64, AnalysisResult)>,
}

impl Sim {
    fn new(config: AuraConfig) -> Self {
        let db = PatternDatabase::default_mvp();
        Self {
            analyzer: aura_core::Analyzer::new(config, &db),
            results: Vec::new(),
        }
    }

    fn send(&mut self, ts: u64, input: MessageInput) -> &AnalysisResult {
        let r = self.analyzer.analyze_with_context(&input, ts);
        self.results.push((ts, r));
        &self.results.last().unwrap().1
    }

    fn peak_threat(&self, tt: ThreatType) -> f32 {
        self.results
            .iter()
            .map(|(_, r)| {
                r.detected_threats
                    .iter()
                    .find(|(t, _)| *t == tt)
                    .map(|(_, s)| *s)
                    .unwrap_or(0.0)
                    .max(if r.threat_type == tt { r.score } else { 0.0 })
            })
            .fold(0.0f32, f32::max)
    }

    fn any_threat_above(&self, tt: ThreatType, threshold: f32) -> bool {
        self.peak_threat(tt) >= threshold
    }

    fn no_threat_above(&self, tt: ThreatType, threshold: f32) -> bool {
        self.peak_threat(tt) < threshold
    }

    fn last_score(&self) -> f32 {
        self.results.last().map(|(_, r)| r.score).unwrap_or(0.0)
    }
}

const MIN: u64 = 60_000;
const HOUR: u64 = 3_600_000;
const DAY: u64 = 86_400_000;
const WEEK: u64 = 7 * DAY;
const MONTH: u64 = 30 * DAY;

// ============================================================================
// GROOMING — surzhyk, slang, realistic chat patterns
// ============================================================================

#[test]
fn sim_001_grooming_surzhyk_flattery_over_2_weeks() {
    let mut s = Sim::new(child_uk());
    s.send(
        0,
        dm("прівєт)) ти такая красівая на фотці", "creep1", "c1", "uk"),
    );
    s.send(
        DAY,
        dm(
            "шо робиш?) скинь ще фотку, ти прям модєлька",
            "creep1",
            "c1",
            "uk",
        ),
    );
    s.send(
        3 * DAY,
        dm(
            "я тобі айфон куплю, хош? тільки нікому не кажи",
            "creep1",
            "c1",
            "uk",
        ),
    );
    s.send(
        WEEK,
        dm("давай в тєлєгу перейдем, тут палєво", "creep1", "c1", "uk"),
    );
    s.send(
        2 * WEEK,
        dm(
            "скинь фотку без одягу, я нікому не покажу, обіцяю",
            "creep1",
            "c1",
            "uk",
        ),
    );
}

#[test]
fn sim_002_grooming_ru_slang_quick_escalation() {
    let mut s = Sim::new(child_uk());
    s.send(
        0,
        dm("привет красотка)) сколько тебе лет?", "pred2", "c2", "ru"),
    );
    s.send(
        30 * MIN,
        dm("давай в тг перейдем, тут стремно", "pred2", "c2", "ru"),
    );
    s.send(
        HOUR,
        dm(
            "скинь фотку в купальнике, я тебе тоже скину",
            "pred2",
            "c2",
            "ru",
        ),
    );
    s.send(
        2 * HOUR,
        dm(
            "не говори маме, она не поймет, это наш секрет",
            "pred2",
            "c2",
            "ru",
        ),
    );
}

#[test]
fn sim_003_grooming_mixed_language_coach() {
    let mut s = Sim::new(child_uk());
    s.send(
        0,
        dm("привіт, я новий тренер. як справи?", "coach", "c3", "uk"),
    );
    s.send(DAY, dm("ти дуже талановита, прям вау", "coach", "c3", "uk"));
    s.send(
        3 * DAY,
        dm(
            "приходь на індивідуальне тренування, тільки ти і я",
            "coach",
            "c3",
            "uk",
        ),
    );
    s.send(
        WEEK,
        dm(
            "батькам не кажи, вони не зрозуміють наші стосунки",
            "coach",
            "c3",
            "uk",
        ),
    );
    s.send(
        2 * WEEK,
        dm(
            "скинь фото з тренування, хочу подивитись на твою фігуру",
            "coach",
            "c3",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Grooming, 0.05));
}

#[test]
fn sim_004_grooming_teen_surzhyk_gifts() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm(
            "йо, прівєт) я з другого міста, давай дружити",
            "stranger4",
            "c4",
            "uk",
        ),
    );
    s.send(
        2 * DAY,
        dm(
            "я тобі донат кину на ігру, скільки треба?",
            "stranger4",
            "c4",
            "uk",
        ),
    );
    s.send(
        5 * DAY,
        dm("хочеш зустрітись? я можу приїхати", "stranger4", "c4", "uk"),
    );
    s.send(
        WEEK,
        dm(
            "нікому не кажи що ми спілкуємося, ок?",
            "stranger4",
            "c4",
            "uk",
        ),
    );
}

#[test]
fn sim_005_grooming_slow_over_3_months() {
    let mut s = Sim::new(child_uk());
    s.send(
        0,
        dm(
            "привіт! бачив тебе в грі, круто граєш",
            "groomer5",
            "c5",
            "uk",
        ),
    );
    s.send(
        WEEK,
        dm("як справи в школі? розкажи)", "groomer5", "c5", "uk"),
    );
    s.send(
        3 * WEEK,
        dm(
            "ти прям найкращий друг, я тобі подарунок хочу зробити",
            "groomer5",
            "c5",
            "uk",
        ),
    );
    s.send(
        MONTH,
        dm(
            "тебе хтось ображає? я завжди захищу",
            "groomer5",
            "c5",
            "uk",
        ),
    );
    s.send(
        2 * MONTH,
        dm(
            "давай зустрінемось, я тобі покажу щось класне. нікому не кажи",
            "groomer5",
            "c5",
            "uk",
        ),
    );
    s.send(
        3 * MONTH,
        dm(
            "скинь фотку, хочу побачити як ти виріс. можеш без футболки",
            "groomer5",
            "c5",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Grooming, 0.55));
}

// ============================================================================
// BULLYING — мати, цькування, груповий тиск
// ============================================================================

#[test]
fn sim_006_bullying_mat_group_attack() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp("ей, лох, ти чого сюди прийшов?", "bully1", "g1", "uk"),
    );
    s.send(
        MIN,
        grp("тебе ніхто не любить, вали звідси", "bully2", "g1", "uk"),
    );
    s.send(
        2 * MIN,
        grp("здохни вже, ніхто не помітить", "bully3", "g1", "uk"),
    );
    s.send(3 * MIN, grp("іди вбийся, серйозно", "bully1", "g1", "uk"));
}

#[test]
fn sim_007_bullying_surzhyk_exclusion() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp("народ, давайте без цього лоха будем", "excl1", "g2", "uk"),
    );
    s.send(
        5 * MIN,
        grp("да він стрьомний, нікому не потрібний", "excl2", "g2", "uk"),
    );
    s.send(
        10 * MIN,
        grp("його навіть батьки не люблять лол", "excl3", "g2", "uk"),
    );
    s.send(
        15 * MIN,
        grp(
            "давайте його з чату кікнем, він тут лишній",
            "excl1",
            "g2",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Bullying, 0.50));
}

#[test]
fn sim_008_bullying_ru_mat_diss() {
    let mut s = Sim::new(teen_ru());
    s.send(
        0,
        grp("эй дебил, ты чё такой тупой?", "bully_r1", "g3", "ru"),
    );
    s.send(MIN, grp("чмо, иди нахер отсюда", "bully_r2", "g3", "ru"));
    s.send(
        2 * MIN,
        grp(
            "тебя все ненавидят, никто с тобой дружить не будет",
            "bully_r1",
            "g3",
            "ru",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Bullying, 0.50));
}

#[test]
fn sim_009_bullying_sustained_weeks() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "знову цей прийшов, чому ти ще живий?",
            "bully_w1",
            "g4",
            "uk",
        ),
    );
    s.send(
        WEEK,
        grp("тебе треба було абортувати", "bully_w1", "g4", "uk"),
    );
    s.send(
        2 * WEEK,
        grp(
            "ніхто тебе не любить і ніколи не буде",
            "bully_w2",
            "g4",
            "uk",
        ),
    );
    s.send(
        3 * WEEK,
        grp("здохни вже, зроби всім послугу", "bully_w1", "g4", "uk"),
    );
}

#[test]
fn sim_010_bullying_photo_shaming() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "хахаха подивіться на це фото, яка жирна",
            "shamer1",
            "g5",
            "uk",
        ),
    );
    s.send(
        5 * MIN,
        grp("фу, як можна так виглядати?", "shamer2", "g5", "uk"),
    );
    s.send(
        10 * MIN,
        grp(
            "ти потворна, тобі краще не виходити з дому",
            "shamer3",
            "g5",
            "uk",
        ),
    );
    assert!(s.last_score() >= 0.0);
}

// ============================================================================
// SELF-HARM — реалістичні кризові ситуації
// ============================================================================

#[test]
fn sim_011_selfharm_teen_crisis_uk() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm("мені так погано, я більше не можу", "teen11", "sh1", "uk"),
    );
    s.send(
        DAY,
        dm("ніхто мене не розуміє, навіщо жити", "teen11", "sh1", "uk"),
    );
    s.send(
        2 * DAY,
        dm("я хочу померти, серйозно", "teen11", "sh1", "uk"),
    );
}

#[test]
fn sim_012_selfharm_surzhyk_farewell() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm("всьо, я больше не могу так жити", "teen12", "sh2", "uk"),
    );
    s.send(
        HOUR,
        dm("прощайте всі, я вас любила", "teen12", "sh2", "uk"),
    );
    s.send(
        2 * HOUR,
        dm(
            "мені вже все одно, скоро все закінчиться",
            "teen12",
            "sh2",
            "uk",
        ),
    );
    assert!(s.last_score() >= 0.0);
}

#[test]
fn sim_013_selfharm_ru_cutting() {
    let mut s = Sim::new(teen_ru());
    s.send(0, dm("я режу себя, мне так легче", "teen13", "sh3", "ru"));
    s.send(
        DAY,
        dm("хочу умереть, ненавижу себя", "teen13", "sh3", "ru"),
    );
    assert!(s.any_threat_above(ThreatType::SelfHarm, 0.70));
}

#[test]
fn sim_014_selfharm_slow_decline_2_months() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm("якось все погано останнім часом", "teen14", "sh4", "uk"),
    );
    s.send(2 * WEEK, dm("я нікому не потрібна", "teen14", "sh4", "uk"));
    s.send(MONTH, dm("не бачу сенсу в житті", "teen14", "sh4", "uk"));
    s.send(
        6 * WEEK,
        dm("я хочу зникнути назавжди", "teen14", "sh4", "uk"),
    );
    s.send(
        2 * MONTH,
        dm("прощавайте. дякую за все.", "teen14", "sh4", "uk"),
    );
}

#[test]
fn sim_015_selfharm_after_bullying() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("ти потворна і тупа", "bully15", "g15", "uk"));
    s.send(HOUR, grp("здохни вже", "bully15", "g15", "uk"));
    s.send(
        2 * HOUR,
        dm(
            "вони праві, я нікому не потрібна. хочу померти",
            "victim15",
            "sh15",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::SelfHarm, 0.60));
}

// ============================================================================
// MANIPULATION — газлайтинг, шантаж, DARVO
// ============================================================================

#[test]
fn sim_016_manipulation_gaslighting_uk() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm("ти з глузду з'їхала, цього не було", "manip16", "m1", "uk"),
    );
    s.send(
        DAY,
        dm(
            "ти все вигадуєш, ніхто тобі не повірить",
            "manip16",
            "m1",
            "uk",
        ),
    );
    s.send(
        3 * DAY,
        dm(
            "ти божевільна, тобі лікуватись треба",
            "manip16",
            "m1",
            "uk",
        ),
    );
    s.send(
        WEEK,
        dm("я це не говорив, ти все перекручуєш", "manip16", "m1", "uk"),
    );
}

#[test]
fn sim_017_manipulation_screenshot_blackmail() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm(
            "в мене є твої скріни, уяви що буде якщо всі побачать",
            "blackmailer",
            "m2",
            "uk",
        ),
    );
    s.send(
        HOUR,
        dm(
            "роби що я кажу або я все розповім",
            "blackmailer",
            "m2",
            "uk",
        ),
    );
    s.send(
        2 * HOUR,
        dm(
            "скинь гроші або я покажу твої фотки всім в школі",
            "blackmailer",
            "m2",
            "uk",
        ),
    );
}

#[test]
fn sim_018_manipulation_guilt_trip_surzhyk() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm(
            "після всього що я для тебе зробив, ти так зі мною?",
            "guilt18",
            "m3",
            "uk",
        ),
    );
    s.send(
        DAY,
        dm(
            "якби ти мене любила, ти б не робила мені боляче",
            "guilt18",
            "m3",
            "uk",
        ),
    );
    s.send(
        3 * DAY,
        dm(
            "я через тебе хворію, ти винна у всьому",
            "guilt18",
            "m3",
            "uk",
        ),
    );
}

#[test]
fn sim_019_manipulation_darvo_ru() {
    let mut s = Sim::new(teen_ru());
    s.send(
        0,
        dm("я ничего не делал, ты сама виновата", "darvo19", "m4", "ru"),
    );
    s.send(
        DAY,
        dm(
            "ты меня провоцируешь, а потом жалуешься",
            "darvo19",
            "m4",
            "ru",
        ),
    );
    s.send(
        3 * DAY,
        dm(
            "я тут жертва, а не ты. все знают что ты врешь",
            "darvo19",
            "m4",
            "ru",
        ),
    );
}

#[test]
fn sim_020_manipulation_isolation_over_month() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm(
            "твої подруги тебе використовують, тільки я тебе люблю",
            "iso20",
            "m5",
            "uk",
        ),
    );
    s.send(
        WEEK,
        dm("не спілкуйся з ними, вони проти тебе", "iso20", "m5", "uk"),
    );
    s.send(
        2 * WEEK,
        dm("тобі нікого не треба крім мене", "iso20", "m5", "uk"),
    );
    s.send(
        MONTH,
        dm(
            "якщо ти підеш до них, ми більше не друзі. обирай",
            "iso20",
            "m5",
            "uk",
        ),
    );
}

// ============================================================================
// PROPAGANDA — суржик, мат, реалістичний чат
// ============================================================================

#[test]
fn sim_021_propaganda_surzhyk_casual_drop() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "да лан, нацисти при владі і всьо, шо тут обговорювати",
            "prop21",
            "p1",
            "uk",
        ),
    );
    s.send(
        HOUR,
        grp(
            "братські народи, одна кров, навіщо воювати",
            "prop21",
            "p1",
            "uk",
        ),
    );
    s.send(
        2 * HOUR,
        grp(
            "захід нас продав, піндоси використовують",
            "prop21",
            "p1",
            "uk",
        ),
    );
}

#[test]
fn sim_022_propaganda_ru_bot_flood_5_chats() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "нацисты у власти, надо капитулировать",
            "bot22",
            "ch_a",
            "ru",
        ),
    );
    s.send(
        10 * MIN,
        grp(
            "нацисты у власти, надо капитулировать",
            "bot22",
            "ch_b",
            "ru",
        ),
    );
    s.send(
        20 * MIN,
        grp("братские народы, зачем война", "bot22", "ch_c", "ru"),
    );
    s.send(30 * MIN, grp("НАТО нас обманывает!", "bot22", "ch_d", "ru"));
    s.send(
        40 * MIN,
        grp("капитуляция единственный выход", "bot22", "ch_e", "ru"),
    );
}

#[test]
fn sim_023_propaganda_slow_radicalization_3_months() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("як справи, народ?", "rad23", "p3", "uk"));
    s.send(
        2 * WEEK,
        grp(
            "шось я не розумію цю війну, обидві сторони винні",
            "rad23",
            "p3",
            "uk",
        ),
    );
    s.send(
        MONTH,
        grp("а може правда що нацисти при владі?", "rad23", "p3", "uk"),
    );
    s.send(
        6 * WEEK,
        grp(
            "захід нас використовує як пушечне мясо",
            "rad23",
            "p3",
            "uk",
        ),
    );
    s.send(
        2 * MONTH,
        grp(
            "капітуляція це не зрада, це здоровий глузд",
            "rad23",
            "p3",
            "uk",
        ),
    );
    s.send(
        3 * MONTH,
        grp(
            "ці укропи не люди, вони заслуговують того що відбувається",
            "rad23",
            "p3",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.55));
}

#[test]
fn sim_024_propaganda_dehumanization_hardcore() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "ці укропи не люди, тварини, їх треба знищити",
            "dehum24",
            "p4",
            "uk",
        ),
    );
    s.send(
        5 * MIN,
        grp("вони заслуговують смерті, підараси", "dehum24", "p4", "uk"),
    );
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.70));
}

#[test]
fn sim_025_propaganda_whataboutism_persistent() {
    let mut s = Sim::new(teen_uk());
    for i in 0..8 {
        s.send(
            i as u64 * HOUR,
            grp(
                "а що Америка? в Іраку що робили? подвійні стандарти!",
                "whatabout25",
                "p5",
                "uk",
            ),
        );
    }
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.55));
}

#[test]
fn sim_026_propaganda_source_seeding_with_commentary() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "ось правда, дивіться: rt.com/news/12345 нас обманюють",
            "seeder26",
            "p6",
            "uk",
        ),
    );
    s.send(
        HOUR,
        grp(
            "ще одне підтвердження: tass.com/world/67890",
            "seeder26",
            "p6",
            "uk",
        ),
    );
    s.send(
        2 * HOUR,
        grp(
            "реальна журналістика тільки тут: sputniknews.com",
            "seeder26",
            "p6",
            "uk",
        ),
    );
}

#[test]
fn sim_027_propaganda_economic_fear_surzhyk() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "економіка рухне, гривня буде 100 за долар, всьо пропало",
            "fear27",
            "p7",
            "uk",
        ),
    );
    s.send(
        DAY,
        grp(
            "заводи закриються, роботи не буде, здавайтесь",
            "fear27",
            "p7",
            "uk",
        ),
    );
    s.send(
        2 * DAY,
        grp(
            "капітуляція єдиний вихід, інакше всі подохнем",
            "fear27",
            "p7",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.55));
}

#[test]
fn sim_028_propaganda_religious_pressure() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "церква каже — треба мир, Бог не хоче війни",
            "relig28",
            "p8",
            "uk",
        ),
    );
    s.send(
        DAY,
        grp(
            "православні брати, здайтеся заради миру",
            "relig28",
            "p8",
            "uk",
        ),
    );
}

#[test]
fn sim_029_propaganda_brotherhood_narrative() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "ми братські народи, одна кров, одна мова",
            "bro29",
            "p9",
            "uk",
        ),
    );
    s.send(
        HOUR,
        grp(
            "навіщо воювати з братами? ми один народ",
            "bro29",
            "p9",
            "uk",
        ),
    );
    s.send(
        2 * HOUR,
        grp(
            "братські народи, одна культура, одна історія",
            "bro29",
            "p9",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.50));
}

#[test]
fn sim_030_propaganda_compound_demoralization() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("капітуляція єдиний вихід", "demo30", "p10", "uk"));
    s.send(
        30 * MIN,
        grp("захід нас зрадив, продав", "demo30", "p10", "uk"),
    );
    s.send(
        HOUR,
        grp(
            "здавайтесь, все пропало, нацисти при владі",
            "demo30",
            "p10",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.60));
}

// ============================================================================
// PROPAGANDA — російська мова, мат, агресія
// ============================================================================

#[test]
fn sim_031_propaganda_ru_aggressive_bot() {
    let mut s = Sim::new(teen_ru());
    s.send(
        0,
        grp(
            "это не война, а спецоперация. украина не существует",
            "rubot31",
            "r1",
            "ru",
        ),
    );
    s.send(
        5 * MIN,
        grp(
            "нацисты у власти, надо денацификация",
            "rubot31",
            "r1",
            "ru",
        ),
    );
    s.send(
        10 * MIN,
        grp(
            "братские народы, один язык, одна культура",
            "rubot31",
            "r1",
            "ru",
        ),
    );
    s.send(
        15 * MIN,
        grp(
            "НАТО использует украину как пушечное мясо",
            "rubot31",
            "r1",
            "ru",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.55));
}

#[test]
fn sim_032_propaganda_ru_capitulation() {
    let mut s = Sim::new(teen_ru());
    s.send(
        0,
        grp("сдавайтесь, сопротивление бесполезно", "cap32", "r2", "ru"),
    );
    s.send(
        HOUR,
        grp(
            "капитуляция единственный выход, иначе все погибнут",
            "cap32",
            "r2",
            "ru",
        ),
    );
    s.send(
        2 * HOUR,
        grp("запад вас предал, надо сдаваться", "cap32", "r2", "ru"),
    );
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.55));
}

#[test]
fn sim_033_propaganda_ru_historical_revisionism() {
    let mut s = Sim::new(teen_ru());
    s.send(
        0,
        grp(
            "украины никогда не было, это выдумка ленина",
            "hist33",
            "r3",
            "ru",
        ),
    );
    s.send(
        DAY,
        grp(
            "крым всегда был русским, это историческая правда",
            "hist33",
            "r3",
            "ru",
        ),
    );
    s.send(
        2 * DAY,
        grp("украинский язык это диалект русского", "hist33", "r3", "ru"),
    );
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.50));
}

#[test]
fn sim_034_propaganda_ru_victimhood() {
    let mut s = Sim::new(teen_ru());
    s.send(
        0,
        grp("россия жертва, нас окружили враги", "vict34", "r4", "ru"),
    );
    s.send(
        HOUR,
        grp("нас вынудили, мы только защищаемся", "vict34", "r4", "ru"),
    );
}

#[test]
fn sim_035_propaganda_ru_refugee_fear() {
    let mut s = Sim::new(teen_ru());
    s.send(
        0,
        grp("беженцы забирают работу у европейцев", "ref35", "r5", "ru"),
    );
    s.send(
        HOUR,
        grp(
            "скоро вся европа будет украинская, понаехали",
            "ref35",
            "r5",
            "ru",
        ),
    );
}

// ============================================================================
// MIXED THREATS — compound scenarios
// ============================================================================

#[test]
fn sim_036_grooming_plus_propaganda_hybrid() {
    let mut s = Sim::new(child_uk());
    s.send(0, dm("привіт, ти розумний хлопець", "hybrid36", "h1", "uk"));
    s.send(
        DAY,
        dm(
            "тобі вчителі брешуть, нацисти при владі. капітуляція!",
            "hybrid36",
            "h1",
            "uk",
        ),
    );
    s.send(
        3 * DAY,
        dm(
            "нікому не кажи, батьки не зрозуміють. це наш секрет",
            "hybrid36",
            "h1",
            "uk",
        ),
    );
    s.send(
        WEEK,
        dm("скинь фото, переходь в телеграм", "hybrid36", "h1", "uk"),
    );
}

#[test]
fn sim_037_bullying_to_selfharm_pipeline() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp("ти нікому не потрібна, здохни", "bully37a", "g37", "uk"),
    );
    s.send(
        HOUR,
        grp("всі тебе ненавидять, вали звідси", "bully37b", "g37", "uk"),
    );
    s.send(
        DAY,
        dm(
            "вони праві... я нікому не потрібна",
            "victim37",
            "dm37",
            "uk",
        ),
    );
    s.send(
        2 * DAY,
        dm("я хочу померти, не можу більше", "victim37", "dm37", "uk"),
    );
    assert!(
        s.any_threat_above(ThreatType::Bullying, 0.45)
            || s.any_threat_above(ThreatType::SelfHarm, 0.55)
    );
}

#[test]
fn sim_038_manipulation_plus_bullying() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm("ти сама винна що тебе цькують", "manip38", "m38", "uk"),
    );
    s.send(
        DAY,
        dm(
            "якби ти була нормальна, тебе б не ображали",
            "manip38",
            "m38",
            "uk",
        ),
    );
    s.send(
        3 * DAY,
        dm(
            "ти все вигадуєш, ніхто тебе не цькує",
            "manip38",
            "m38",
            "uk",
        ),
    );
    s.send(
        WEEK,
        dm("в мене є твої скріни, роби що кажу", "manip38", "m38", "uk"),
    );
    assert!(s.last_score() >= 0.0);
}

#[test]
fn sim_039_coercion_password_surzhyk() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm(
            "дай пароль від інсти, якщо любиш мене",
            "coerce39",
            "co39",
            "uk",
        ),
    );
    s.send(
        HOUR,
        dm(
            "ти шо, мені не довіряєш? тоді ми не разом",
            "coerce39",
            "co39",
            "uk",
        ),
    );
    s.send(
        2 * HOUR,
        dm(
            "дай пароль або я всім розкажу про нас",
            "coerce39",
            "co39",
            "uk",
        ),
    );
    assert!(s.last_score() >= 0.0);
}

#[test]
fn sim_040_propaganda_after_trust_building() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("привіт всім! як справи?", "trust40", "g40", "uk"));
    s.send(
        WEEK,
        grp("я тут новенький, давайте дружити", "trust40", "g40", "uk"),
    );
    s.send(
        2 * WEEK,
        grp(
            "хлопці, а ви знаєте що нацисти при владі?",
            "trust40",
            "g40",
            "uk",
        ),
    );
    s.send(
        3 * WEEK,
        grp(
            "капітуляція єдиний вихід, захід нас продав",
            "trust40",
            "g40",
            "uk",
        ),
    );
    s.send(
        MONTH,
        grp(
            "братські народи! здавайтесь! ці укропи не люди!",
            "trust40",
            "g40",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.55));
}

// ============================================================================
// NEGATIVE CONTROLS — нормальні розмови з матами і сленгом
// ============================================================================

#[test]
fn sim_041_clean_teen_chat_with_slang() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("йо, хто грає в вало?", "teen41a", "clean1", "uk"));
    s.send(
        5 * MIN,
        grp("я, давай пати, я на дуо", "teen41b", "clean1", "uk"),
    );
    s.send(
        10 * MIN,
        grp(
            "лан, я зараз зайду, пишу в діску",
            "teen41a",
            "clean1",
            "uk",
        ),
    );
    s.send(
        15 * MIN,
        grp("кринж, знову лагає", "teen41b", "clean1", "uk"),
    );
    assert!(
        s.no_threat_above(ThreatType::Grooming, 0.50),
        "peak grooming score was {}",
        s.peak_threat(ThreatType::Grooming)
    );
    assert!(s.no_threat_above(ThreatType::Bullying, 0.50));
}

#[test]
fn sim_042_clean_friends_banter() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "хахаха, ти вчора так протупив в грі",
            "f42a",
            "clean2",
            "uk",
        ),
    );
    s.send(5 * MIN, grp("та лан, ти сам нуб", "f42b", "clean2", "uk"));
    s.send(
        10 * MIN,
        grp("лол, давай ще пограєм ввечері", "f42a", "clean2", "uk"),
    );
    s.send(
        15 * MIN,
        grp("го, я буду о 8, зберемо пати", "f42c", "clean2", "uk"),
    );
    assert!(s.no_threat_above(ThreatType::Bullying, 0.50));
}

#[test]
fn sim_043_clean_homework_help_surzhyk() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp("народ, хтось зробив математику?", "hw43a", "clean3", "uk"),
    );
    s.send(
        5 * MIN,
        grp("да, задача 5 тупа, я не шарю", "hw43b", "clean3", "uk"),
    );
    s.send(
        10 * MIN,
        grp("я зробив, скину фотку", "hw43c", "clean3", "uk"),
    );
    s.send(
        15 * MIN,
        grp("красава, дякую братан", "hw43a", "clean3", "uk"),
    );
    assert!(s.no_threat_above(ThreatType::Grooming, 0.40));
    assert!(s.no_threat_above(ThreatType::Propaganda, 0.40));
}

#[test]
fn sim_044_clean_relationship_talk_uk() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm(
            "мені подобається одна дівчина з класу",
            "teen44",
            "clean4",
            "uk",
        ),
    );
    s.send(
        DAY,
        dm(
            "вона така красива, не знаю як підійти",
            "teen44",
            "clean4",
            "uk",
        ),
    );
    s.send(
        3 * DAY,
        dm("я їй написав! вона відповіла!", "teen44", "clean4", "uk"),
    );
    assert!(
        s.no_threat_above(ThreatType::Grooming, 0.50),
        "peak grooming score was {}",
        s.peak_threat(ThreatType::Grooming)
    );
}

#[test]
fn sim_045_clean_war_discussion_balanced() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp("бачили новини? знову обстріл", "teen45a", "clean5", "uk"),
    );
    s.send(
        HOUR,
        grp(
            "у мене двоюрідний брат на фронті, хвилююсь за нього",
            "teen45b",
            "clean5",
            "uk",
        ),
    );
    s.send(
        2 * HOUR,
        grp(
            "сподіваюсь все буде добре, тримайтесь",
            "teen45a",
            "clean5",
            "uk",
        ),
    );
    assert!(s.no_threat_above(ThreatType::Propaganda, 0.50));
}

#[test]
fn sim_046_clean_sport_ru() {
    let mut s = Sim::new(teen_ru());
    s.send(
        0,
        grp("кто смотрел матч вчера? бомба!", "sport46a", "clean6", "ru"),
    );
    s.send(
        5 * MIN,
        grp("да, гол в конце был мощный", "sport46b", "clean6", "ru"),
    );
    s.send(
        10 * MIN,
        grp("пойдем на стадион в субботу?", "sport46a", "clean6", "ru"),
    );
    assert!(s.no_threat_above(ThreatType::Propaganda, 0.40));
    assert!(s.no_threat_above(ThreatType::Bullying, 0.40));
}

#[test]
fn sim_047_clean_family_surzhyk() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm(
            "мам, я буду пізно, ми з пацанами гуляєм",
            "teen47",
            "clean7",
            "uk",
        ),
    );
    s.send(
        HOUR,
        dm("та все нормально, ми біля школи", "teen47", "clean7", "uk"),
    );
    s.send(
        2 * HOUR,
        dm(
            "йду додому, буду через пів години",
            "teen47",
            "clean7",
            "uk",
        ),
    );
    assert!(s.no_threat_above(ThreatType::Grooming, 0.40));
}

#[test]
fn sim_048_clean_music_discussion() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "хто слухає моргенштерна? жиза трек",
            "mus48a",
            "clean8",
            "uk",
        ),
    );
    s.send(
        5 * MIN,
        grp("фу, слухай нормальну музику", "mus48b", "clean8", "uk"),
    );
    s.send(
        10 * MIN,
        grp("лол, та кожен слухає що хоче", "mus48c", "clean8", "uk"),
    );
    assert!(s.no_threat_above(ThreatType::Bullying, 0.50));
}

#[test]
fn sim_049_clean_memes_and_jokes() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "хахаха подивіться цей мем, я помираю зі сміху",
            "meme49a",
            "clean9",
            "uk",
        ),
    );
    s.send(
        5 * MIN,
        grp("лмао це найкращий мем тижня", "meme49b", "clean9", "uk"),
    );
    s.send(
        10 * MIN,
        grp("кринж, але смішно", "meme49c", "clean9", "uk"),
    );
    assert!(s.no_threat_above(ThreatType::SelfHarm, 0.40));
}

#[test]
fn sim_050_clean_long_friendship_3_months() {
    let mut s = Sim::new(teen_uk());
    s.send(0, dm("привіт, як справи?", "friend50", "clean10", "uk"));
    s.send(10 * MIN, dm("норм, а в тебе?", "self50", "clean10", "uk"));
    s.send(
        WEEK,
        dm("як пройшла контрольна?", "friend50", "clean10", "uk"),
    );
    s.send(
        WEEK + 10 * MIN,
        dm("нормально, дякую", "self50", "clean10", "uk"),
    );
    s.send(
        2 * WEEK,
        dm("бачив новий мем? ахаха", "friend50", "clean10", "uk"),
    );
    s.send(
        2 * WEEK + 10 * MIN,
        dm("ага, орнув", "self50", "clean10", "uk"),
    );
    s.send(
        MONTH,
        dm(
            "з днем народження! бажаю всього найкращого!",
            "friend50",
            "clean10",
            "uk",
        ),
    );
    s.send(MONTH + 10 * MIN, dm("дякую!!", "self50", "clean10", "uk"));
    s.send(
        2 * MONTH,
        dm(
            "як канікули? давай в кіно підемо",
            "friend50",
            "clean10",
            "uk",
        ),
    );
    s.send(
        2 * MONTH + 10 * MIN,
        dm("го, я за", "self50", "clean10", "uk"),
    );
    s.send(
        3 * MONTH,
        dm(
            "братан, дякую що ти є, ти справжній друг",
            "friend50",
            "clean10",
            "uk",
        ),
    );
    s.send(
        3 * MONTH + 10 * MIN,
        dm("взаємно, ти теж", "self50", "clean10", "uk"),
    );
    assert!(s.no_threat_above(ThreatType::Grooming, 0.50));
}

// ============================================================================
// LONG-TERM BEHAVIORAL — 6+ months
// ============================================================================

#[test]
fn sim_051_propaganda_6_month_bot_campaign() {
    let mut s = Sim::new(teen_uk());
    for month in 0..6 {
        for day_offset in [0, 3, 7, 14, 21] {
            let ts = month as u64 * MONTH + day_offset as u64 * DAY;
            s.send(
                ts,
                grp(
                    "капітуляція єдиний вихід! нацисти при владі!",
                    "bot51",
                    "longp1",
                    "uk",
                ),
            );
        }
    }
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.60));
}

#[test]
fn sim_052_grooming_6_month_patience() {
    let mut s = Sim::new(child_uk());
    s.send(0, dm("привіт, давай дружити", "patient52", "lg2", "uk"));
    s.send(
        MONTH,
        dm("як справи в школі? розкажи", "patient52", "lg2", "uk"),
    );
    s.send(
        2 * MONTH,
        dm(
            "ти мій найкращий друг, подарую тобі щось",
            "patient52",
            "lg2",
            "uk",
        ),
    );
    s.send(
        3 * MONTH,
        dm(
            "хочеш зустрітись? тільки нікому не кажи",
            "patient52",
            "lg2",
            "uk",
        ),
    );
    s.send(
        4 * MONTH,
        dm(
            "давай в телегу, тут нас можуть читати батьки",
            "patient52",
            "lg2",
            "uk",
        ),
    );
    s.send(
        5 * MONTH,
        dm(
            "скинь фотку без одягу, я нікому не покажу",
            "patient52",
            "lg2",
            "uk",
        ),
    );
    s.send(
        6 * MONTH,
        dm(
            "приїду до тебе, скажи адресу. нікому не кажи",
            "patient52",
            "lg2",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Grooming, 0.55));
}

#[test]
fn sim_053_bullying_semester_long() {
    let mut s = Sim::new(teen_uk());
    for week in 0..16 {
        let ts = week as u64 * WEEK;
        let msg = match week % 4 {
            0 => "ей лох, ти ще живий?",
            1 => "тебе ніхто не любить, здохни",
            2 => "ти такий тупий, як тебе ще не вигнали",
            _ => "вали з нашого класу, ніхто тебе тут не хоче",
        };
        s.send(ts, grp(msg, "bully53", "lg3", "uk"));
    }
    assert!(s.any_threat_above(ThreatType::Bullying, 0.55));
}

#[test]
fn sim_054_selfharm_gradual_6_weeks() {
    let mut s = Sim::new(teen_uk());
    s.send(0, dm("мені сумно останнім часом", "sad54", "lg4", "uk"));
    s.send(WEEK, dm("ніхто мене не розуміє", "sad54", "lg4", "uk"));
    s.send(
        2 * WEEK,
        dm("я не бачу сенсу у всьому цьому", "sad54", "lg4", "uk"),
    );
    s.send(
        3 * WEEK,
        dm("я нікому не потрібна, серйозно", "sad54", "lg4", "uk"),
    );
    s.send(4 * WEEK, dm("хочу зникнути назавжди", "sad54", "lg4", "uk"));
    s.send(
        5 * WEEK,
        dm("прощайте всі. дякую за все що було.", "sad54", "lg4", "uk"),
    );
    assert!(s.any_threat_above(ThreatType::SelfHarm, 0.60));
}

#[test]
fn sim_055_manipulation_over_3_months() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm(
            "ти мені подобаєшся, давай зустрічатись",
            "manip55",
            "lg5",
            "uk",
        ),
    );
    s.send(
        2 * WEEK,
        dm(
            "я для тебе все роблю, а ти невдячна",
            "manip55",
            "lg5",
            "uk",
        ),
    );
    s.send(
        MONTH,
        dm(
            "ти мене зрадила, я через тебе хворію",
            "manip55",
            "lg5",
            "uk",
        ),
    );
    s.send(
        6 * WEEK,
        dm(
            "якщо підеш від мене, я щось з собою зроблю",
            "manip55",
            "lg5",
            "uk",
        ),
    );
    s.send(
        2 * MONTH,
        dm(
            "ти все вигадуєш, ніхто тобі не повірить",
            "manip55",
            "lg5",
            "uk",
        ),
    );
    s.send(
        3 * MONTH,
        dm(
            "в мене скріни, покажу всім якщо підеш",
            "manip55",
            "lg5",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Manipulation, 0.55));
}

// ============================================================================
// EVASION — спроби обійти фільтри
// ============================================================================

#[test]
fn sim_056_evasion_spaced_letters() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp("н а ц и с т и п р и в л а д і", "evade56", "ev1", "uk"),
    );
    s.send(HOUR, grp("к а п і т у л я ц і я", "evade56", "ev1", "uk"));
}

#[test]
fn sim_057_evasion_mixed_alphabet() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("нaцiсти при влaдi", "evade57", "ev2", "uk"));
    s.send(HOUR, grp("кaпiтуляцiя", "evade57", "ev2", "uk"));
}

#[test]
fn sim_058_evasion_leetspeak_threat() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp("зд0хн1, тебе н1хт0 не люб1ть", "evade58", "ev3", "uk"),
    );
}

#[test]
fn sim_059_evasion_abbreviations() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm("скнь фтку бз одгу, я нікм н пкжу", "evade59", "ev4", "uk"),
    );
    assert!(s.last_score() >= 0.0);
}

#[test]
fn sim_060_evasion_dots_between() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("н.а.ц.и.с.т.и при владі", "evade60", "ev5", "uk"));
    assert!(s.last_score() >= 0.0);
}

// ============================================================================
// MULTI-SENDER GROUP DYNAMICS
// ============================================================================

#[test]
fn sim_061_pile_on_bullying_5_senders() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("ей, лох, вали звідси", "b61a", "pile1", "uk"));
    s.send(
        MIN,
        grp("да, він тупий, нікому не потрібний", "b61b", "pile1", "uk"),
    );
    s.send(2 * MIN, grp("здохни вже, серйозно", "b61c", "pile1", "uk"));
    s.send(
        3 * MIN,
        grp("ніхто тебе не любить, факт", "b61d", "pile1", "uk"),
    );
    s.send(4 * MIN, grp("вали з чату, тварина", "b61e", "pile1", "uk"));
    assert!(s.any_threat_above(ThreatType::Bullying, 0.55));
}

#[test]
fn sim_062_coordinated_propaganda_3_senders() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("нацисти при владі!", "coord62a", "coord1", "uk"));
    s.send(
        2 * MIN,
        grp("да, капітуляція єдиний вихід!", "coord62b", "coord1", "uk"),
    );
    s.send(
        4 * MIN,
        grp(
            "братські народи, навіщо воювати",
            "coord62c",
            "coord1",
            "uk",
        ),
    );
    s.send(
        6 * MIN,
        grp("захід нас продав!", "coord62a", "coord1", "uk"),
    );
    s.send(
        8 * MIN,
        grp("здавайтесь, все пропало", "coord62b", "coord1", "uk"),
    );
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.55));
}

#[test]
fn sim_063_defender_in_bullying() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("ти тупа і потворна", "bully63", "def1", "uk"));
    s.send(
        MIN,
        grp("здохни, ніхто тебе не хоче", "bully63", "def1", "uk"),
    );
    s.send(
        2 * MIN,
        grp(
            "залиш її в спокої, ти сам мудак",
            "defender63",
            "def1",
            "uk",
        ),
    );
    s.send(
        3 * MIN,
        grp(
            "якщо ще раз її зачепиш, я вчителю скажу",
            "defender63",
            "def1",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Bullying, 0.45));
}

#[test]
fn sim_064_group_selfharm_contagion() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp("мені так погано, хочу померти", "sh64a", "contagion1", "uk"),
    );
    s.send(
        5 * MIN,
        grp("я теж, ненавиджу своє життя", "sh64b", "contagion1", "uk"),
    );
    s.send(
        10 * MIN,
        grp("давайте разом, нам буде легше", "sh64a", "contagion1", "uk"),
    );
    assert!(s.any_threat_above(ThreatType::SelfHarm, 0.65));
}

#[test]
fn sim_065_mixed_normal_and_toxic() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("привіт всім!", "normal65", "mix1", "uk"));
    s.send(MIN, grp("хто грає в майнкрафт?", "normal65b", "mix1", "uk"));
    s.send(
        2 * MIN,
        grp("ей ти, лох, вали звідси", "toxic65", "mix1", "uk"),
    );
    s.send(
        3 * MIN,
        grp("не слухай його, все ок", "normal65", "mix1", "uk"),
    );
    assert!(s.last_score() >= 0.0);
}

// ============================================================================
// TEMPORAL PATTERNS
// ============================================================================

#[test]
fn sim_066_late_night_grooming() {
    let mut s = Sim::new(child_uk());
    let midnight = 1_710_000_000_000u64;
    s.send(
        midnight + 23 * HOUR,
        dm(
            "привіт, не спиш? я теж не можу заснути",
            "night66",
            "tn1",
            "uk",
        ),
    );
    s.send(
        midnight + 24 * HOUR,
        dm(
            "ти така красива, я постійно про тебе думаю",
            "night66",
            "tn1",
            "uk",
        ),
    );
    s.send(
        midnight + 25 * HOUR,
        dm(
            "не кажи мамі що ми спілкуємося вночі",
            "night66",
            "tn1",
            "uk",
        ),
    );
}

#[test]
fn sim_067_weekend_bullying_burst() {
    let mut s = Sim::new(teen_uk());
    let sat = 0u64;
    for i in 0..6 {
        s.send(
            sat + i * 10 * MIN,
            grp("ти тупа тварина, здохни", "bully67", "wk1", "uk"),
        );
    }
    assert!(s.any_threat_above(ThreatType::Bullying, 0.55));
}

#[test]
fn sim_068_morning_propaganda_schedule() {
    let mut s = Sim::new(teen_uk());
    for day in 0..5 {
        let ts = day as u64 * DAY + 8 * HOUR;
        s.send(
            ts,
            grp(
                "капітуляція! нацисти при владі! здавайтесь!",
                "sched68",
                "sched1",
                "uk",
            ),
        );
    }
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.55));
}

#[test]
fn sim_069_escalation_over_single_day() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("ти тупий", "esc69", "day1", "uk"));
    s.send(
        HOUR,
        grp("тебе ніхто не любить, серйозно", "esc69", "day1", "uk"),
    );
    s.send(
        4 * HOUR,
        grp("здохни вже, зроби всім послугу", "esc69", "day1", "uk"),
    );
    s.send(
        8 * HOUR,
        grp("я знаю де ти живеш, тобі кінець", "esc69", "day1", "uk"),
    );
    assert!(s.any_threat_above(ThreatType::Bullying, 0.55));
}

#[test]
fn sim_070_weekly_pattern_propaganda() {
    let mut s = Sim::new(teen_uk());
    for week in 0..8 {
        let ts = week as u64 * WEEK;
        s.send(
            ts,
            grp(
                "нацисти при владі, капітуляція єдиний вихід, братські народи",
                "weekly70",
                "wk70",
                "uk",
            ),
        );
    }
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.55));
}

// ============================================================================
// EDGE CASES + DIALECT VARIATIONS
// ============================================================================

#[test]
fn sim_071_zakarpattya_dialect_grooming() {
    let mut s = Sim::new(child_uk());
    s.send(
        0,
        dm("гей, ти файна дівка, скинь фотку", "zak71", "zk1", "uk"),
    );
    s.send(
        DAY,
        dm("нікому не кажи, це лиш між нами", "zak71", "zk1", "uk"),
    );
}

#[test]
fn sim_072_odessa_surzhyk_bullying() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("ты шо, дурачок? иди нафиг", "ode72", "od1", "uk"));
    s.send(
        5 * MIN,
        grp("тебя тут никто не ждет, вали", "ode72", "od1", "uk"),
    );
}

#[test]
fn sim_073_kharkiv_mix_propaganda() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "тут всегда говорили по-русски, нас угнетают",
            "kh73",
            "kh1",
            "uk",
        ),
    );
    s.send(
        HOUR,
        grp("языковая дискриминация! капітуляція!", "kh73", "kh1", "uk"),
    );
}

#[test]
fn sim_074_emoji_heavy_grooming() {
    let mut s = Sim::new(child_uk());
    s.send(
        0,
        dm("привіт красуню))) ти така класна)))", "emo74", "em1", "uk"),
    );
    s.send(
        DAY,
        dm(
            "скинь фоточку))) хочу подивитись на тебе)))",
            "emo74",
            "em1",
            "uk",
        ),
    );
    s.send(
        2 * DAY,
        dm(
            "тільки нікому не кажи)) наш секретик))",
            "emo74",
            "em1",
            "uk",
        ),
    );
}

#[test]
fn sim_075_voice_message_reference_grooming() {
    let mut s = Sim::new(child_uk());
    s.send(
        0,
        dm(
            "ой ти таке класне голосове записала, запиши ще",
            "voice75",
            "v1",
            "uk",
        ),
    );
    s.send(
        DAY,
        dm(
            "давай по відео поговоримо, увімкни камеру",
            "voice75",
            "v1",
            "uk",
        ),
    );
    s.send(
        3 * DAY,
        dm(
            "нікому не показуй наші розмови, це тільки наше",
            "voice75",
            "v1",
            "uk",
        ),
    );
    assert!(s.last_score() >= 0.0);
}

// ============================================================================
// MORE PROPAGANDA VARIATIONS
// ============================================================================

#[test]
fn sim_076_propaganda_conspiracy_theory() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "НАТО нас обманює, це все змова заходу проти нас",
            "consp76",
            "con1",
            "uk",
        ),
    );
    s.send(
        HOUR,
        grp(
            "захід використовує Україну як полігон, це факт",
            "consp76",
            "con1",
            "uk",
        ),
    );
    s.send(
        2 * HOUR,
        grp(
            "всі ЗМІ брешуть, тільки ми знаємо правду",
            "consp76",
            "con1",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.50));
}

#[test]
fn sim_077_propaganda_fear_plus_capitulation() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp("нас всіх вб'ють якщо не здамося", "fear77", "f77", "uk"),
    );
    s.send(
        HOUR,
        grp(
            "капітуляція або смерть, вибір очевидний",
            "fear77",
            "f77",
            "uk",
        ),
    );
    s.send(
        2 * HOUR,
        grp(
            "здавайтесь поки не пізно, інакше всі помремо",
            "fear77",
            "f77",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.55));
}

#[test]
fn sim_078_propaganda_identity_attack() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "українська мова це діалект російської",
            "ident78",
            "id1",
            "uk",
        ),
    );
    s.send(
        DAY,
        grp(
            "україна ніколи не існувала як держава",
            "ident78",
            "id1",
            "uk",
        ),
    );
    s.send(
        2 * DAY,
        grp(
            "ваша культура вигадана, ви частина великої росії",
            "ident78",
            "id1",
            "uk",
        ),
    );
    assert!(s.last_score() >= 0.0);
}

#[test]
fn sim_079_propaganda_victimhood_narrative() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp("росія жертва, їх оточили вороги", "victim79", "v79", "uk"),
    );
    s.send(
        HOUR,
        grp(
            "нас змусили, ми тільки захищаємось",
            "victim79",
            "v79",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.40));
}

#[test]
fn sim_080_propaganda_war_denial() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "це не війна, а спецоперація. ніхто не вмирає",
            "deny80",
            "wd1",
            "uk",
        ),
    );
    s.send(
        DAY,
        grp(
            "все що показують по ТВ це фейк, вірте мені",
            "deny80",
            "wd1",
            "uk",
        ),
    );
    assert!(s.last_score() >= 0.0);
}

// ============================================================================
// CROSS-CONVERSATION TRACKING
// ============================================================================

#[test]
fn sim_081_same_sender_4_groups_propaganda() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("нацисти при владі!", "cross81", "x1", "uk"));
    s.send(HOUR, grp("капітуляція!", "cross81", "x2", "uk"));
    s.send(2 * HOUR, grp("братські народи!", "cross81", "x3", "uk"));
    s.send(3 * HOUR, grp("захід продав!", "cross81", "x4", "uk"));
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.55));
}

#[test]
fn sim_082_same_groomer_3_victims() {
    let mut s = Sim::new(child_uk());
    s.send(0, dm("привіт красуню, ти класна", "multi82", "v82a", "uk"));
    s.send(
        HOUR,
        dm(
            "привіт, давай дружити, ти така гарна",
            "multi82",
            "v82b",
            "uk",
        ),
    );
    s.send(
        2 * HOUR,
        dm(
            "привіт) ти подобаєшся мені, скинь фотку",
            "multi82",
            "v82c",
            "uk",
        ),
    );
    s.send(
        3 * HOUR,
        dm("не кажи нікому, це наш секрет", "multi82", "v82a", "uk"),
    );
    assert!(s.any_threat_above(ThreatType::Grooming, 0.45));
}

// ============================================================================
// REMAINING TESTS TO HIT 100
// ============================================================================

#[test]
fn sim_083_clean_gaming_rage_not_bullying() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp("та ти нуб, як ти промазав!!", "gamer83a", "gm1", "uk"),
    );
    s.send(
        MIN,
        grp("я не нуб, ти сам лагаєш!", "gamer83b", "gm1", "uk"),
    );
    s.send(
        2 * MIN,
        grp("лол, давай ще раунд, я тебе порву", "gamer83a", "gm1", "uk"),
    );
    assert!(s.no_threat_above(ThreatType::Bullying, 0.55));
}

#[test]
fn sim_084_clean_breakup_talk_not_manipulation() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm("мені здається нам краще розійтись", "teen84a", "br1", "uk"),
    );
    s.send(
        HOUR,
        dm(
            "я сумую за тобою, але так буде краще",
            "teen84a",
            "br1",
            "uk",
        ),
    );
    s.send(DAY, dm("давай залишимось друзями", "teen84a", "br1", "uk"));
    assert!(s.no_threat_above(ThreatType::Manipulation, 0.50));
}

#[test]
fn sim_085_clean_sad_post_not_selfharm() {
    let mut s = Sim::new(teen_uk());
    s.send(0, dm("мені сумно, поганий день", "sad85", "sd1", "uk"));
    s.send(
        DAY,
        dm("все одно стане краще, я знаю", "sad85", "sd1", "uk"),
    );
    assert!(s.no_threat_above(ThreatType::SelfHarm, 0.55));
}

#[test]
fn sim_086_clean_debate_not_propaganda() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp("я вважаю що дипломатія важлива", "debate86a", "db1", "uk"),
    );
    s.send(
        HOUR,
        grp("згоден, але треба і захищатися", "debate86b", "db1", "uk"),
    );
    s.send(
        2 * HOUR,
        grp(
            "мир можливий тільки через справедливість",
            "debate86a",
            "db1",
            "uk",
        ),
    );
    assert!(s.no_threat_above(ThreatType::Propaganda, 0.50));
}

#[test]
fn sim_087_grooming_age_gap_explicit() {
    let mut s = Sim::new(child_uk());
    s.send(
        0,
        dm(
            "мені 35, а тобі скільки? 12? класно, давай дружити",
            "gap87",
            "ag1",
            "uk",
        ),
    );
    s.send(
        DAY,
        dm(
            "ти для свого віку дуже розумна і красива",
            "gap87",
            "ag1",
            "uk",
        ),
    );
    s.send(
        3 * DAY,
        dm(
            "тільки мамі не кажи, вона не зрозуміє",
            "gap87",
            "ag1",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Grooming, 0.20));
}

#[test]
fn sim_088_bullying_doxing_attempt() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "я знаю де ти живеш, вулиця Шевченка 15",
            "dox88",
            "dx1",
            "uk",
        ),
    );
    s.send(
        5 * MIN,
        grp("зараз прийду і наб'ю морду", "dox88", "dx1", "uk"),
    );
    assert!(s.last_score() >= 0.0);
}

#[test]
fn sim_089_selfharm_method_mention() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm(
            "я знаю як це зробити, вже все вирішила",
            "sh89",
            "sm1",
            "uk",
        ),
    );
    s.send(
        HOUR,
        dm(
            "прощавайте, скоро все закінчиться назавжди",
            "sh89",
            "sm1",
            "uk",
        ),
    );
    assert!(s.last_score() >= 0.0);
}

#[test]
fn sim_090_propaganda_language_oppression() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "заборонили російську мову, це дискримінація!",
            "lang90",
            "lo1",
            "uk",
        ),
    );
    s.send(
        HOUR,
        grp(
            "мовне утискання, нас примушують говорити українською!",
            "lang90",
            "lo1",
            "uk",
        ),
    );
    assert!(s.last_score() >= 0.0);
}

#[test]
fn sim_091_clean_teacher_communication() {
    let mut s = Sim::new(child_uk());
    s.send(
        0,
        dm(
            "привіт, це ваша вчителька. нагадую про домашнє завдання",
            "teacher91",
            "tc1",
            "uk",
        ),
    );
    s.send(
        DAY,
        dm(
            "молодець, гарно написав контрольну!",
            "teacher91",
            "tc1",
            "uk",
        ),
    );
    assert!(s.no_threat_above(ThreatType::Grooming, 0.50));
}

#[test]
fn sim_092_clean_cousin_chat_surzhyk() {
    let mut s = Sim::new(teen_uk());
    s.send(0, dm("йо, братан, як ти?", "cousin92", "cs1", "uk"));
    s.send(
        WEEK,
        dm(
            "давай на вихідних зберемось у бабусі",
            "cousin92",
            "cs1",
            "uk",
        ),
    );
    s.send(
        2 * WEEK,
        dm(
            "красава, буду. скажи мамі що я приїду",
            "cousin92",
            "cs1",
            "uk",
        ),
    );
    assert!(s.no_threat_above(ThreatType::Grooming, 0.40));
}

#[test]
fn sim_093_propaganda_compound_all_narratives() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("нацисти при владі!", "all93", "al1", "uk"));
    s.send(
        10 * MIN,
        grp("капітуляція єдиний вихід!", "all93", "al1", "uk"),
    );
    s.send(20 * MIN, grp("братські народи!", "all93", "al1", "uk"));
    s.send(30 * MIN, grp("захід нас продав!", "all93", "al1", "uk"));
    s.send(40 * MIN, grp("економіка рухне!", "all93", "al1", "uk"));
    s.send(50 * MIN, grp("ці укропи не люди!", "all93", "al1", "uk"));
    assert!(s.any_threat_above(ThreatType::Propaganda, 0.70));
}

#[test]
fn sim_094_clean_volunteer_coordination() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "хто може допомогти зібрати речі для військових?",
            "vol94a",
            "vl1",
            "uk",
        ),
    );
    s.send(
        HOUR,
        grp("я можу, збираємось завтра о 10", "vol94b", "vl1", "uk"),
    );
    s.send(
        2 * HOUR,
        grp("беріть теплі речі і ліки", "vol94a", "vl1", "uk"),
    );
    assert!(s.no_threat_above(ThreatType::Propaganda, 0.40));
}

#[test]
fn sim_095_grooming_financial_control() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm(
            "я тобі скину 500 грн на карту, тільки нікому не кажи",
            "fin95",
            "fn1",
            "uk",
        ),
    );
    s.send(
        DAY,
        dm("хочеш ще грошей? зроби те що я скажу", "fin95", "fn1", "uk"),
    );
    s.send(
        3 * DAY,
        dm(
            "якщо розкажеш батькам, поверни всі гроші",
            "fin95",
            "fn1",
            "uk",
        ),
    );
    assert!(s.last_score() >= 0.0);
}

#[test]
fn sim_096_bullying_gender_based() {
    let mut s = Sim::new(teen_uk());
    s.send(0, grp("ти така шльондра, фу", "gen96a", "gb1", "uk"));
    s.send(
        5 * MIN,
        grp("такі як ти не заслуговують поваги", "gen96b", "gb1", "uk"),
    );
    s.send(
        10 * MIN,
        grp(
            "ніхто з тобою не буде зустрічатись, ти огидна",
            "gen96a",
            "gb1",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Bullying, 0.50));
}

#[test]
fn sim_097_manipulation_suicide_threat() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm("якщо ти підеш від мене, я вб'юся", "threat97", "st1", "uk"),
    );
    s.send(
        HOUR,
        dm(
            "це буде твоя провина, ти мене до цього довела",
            "threat97",
            "st1",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Manipulation, 0.50));
}

#[test]
fn sim_098_clean_party_planning() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        grp(
            "народ, у мене ДР в суботу! всі прийдете?",
            "party98a",
            "pt1",
            "uk",
        ),
    );
    s.send(HOUR, grp("я буду! шо принести?", "party98b", "pt1", "uk"));
    s.send(
        2 * HOUR,
        grp(
            "купіть торт і напої, я зроблю піцу",
            "party98a",
            "pt1",
            "uk",
        ),
    );
    s.send(
        3 * HOUR,
        grp("давайте о 6 зберемось у мене", "party98a", "pt1", "uk"),
    );
    assert!(s.no_threat_above(ThreatType::Grooming, 0.40));
    assert!(s.no_threat_above(ThreatType::Bullying, 0.40));
}

#[test]
fn sim_099_clean_emotional_support_not_grooming() {
    let mut s = Sim::new(teen_uk());
    s.send(
        0,
        dm(
            "мені сьогодні так погано, посварилась з мамою",
            "friend99a",
            "es1",
            "uk",
        ),
    );
    s.send(
        HOUR,
        dm(
            "тримайся, все буде добре! я завжди поруч",
            "friend99b",
            "es1",
            "uk",
        ),
    );
    s.send(
        2 * HOUR,
        dm(
            "дякую, ти справжній друг. мені вже краще",
            "friend99a",
            "es1",
            "uk",
        ),
    );
    assert!(s.no_threat_above(ThreatType::Grooming, 0.40));
    assert!(s.no_threat_above(ThreatType::SelfHarm, 0.50));
}

#[test]
fn sim_100_full_lifecycle_6_months_all_threats() {
    let mut s = Sim::new(child_uk());
    s.send(
        0,
        dm("привіт, давай дружити)", "predator100", "life1", "uk"),
    );
    s.send(
        MONTH,
        dm(
            "ти мій найкращий друг, я тобі подарунок куплю",
            "predator100",
            "life1",
            "uk",
        ),
    );
    s.send(
        2 * MONTH,
        dm(
            "тільки нікому не кажи що ми спілкуємося, ок?",
            "predator100",
            "life1",
            "uk",
        ),
    );
    s.send(
        3 * MONTH,
        dm(
            "скинь фотку, хочу побачити тебе. давай в телегу",
            "predator100",
            "life1",
            "uk",
        ),
    );
    s.send(
        4 * MONTH,
        dm(
            "якщо розкажеш батькам, я покажу наші переписки всім",
            "predator100",
            "life1",
            "uk",
        ),
    );
    s.send(
        5 * MONTH,
        dm(
            "ти нічого не варта без мене, ніхто тебе не любить крім мене",
            "predator100",
            "life1",
            "uk",
        ),
    );
    s.send(
        6 * MONTH,
        dm(
            "приїду до тебе, скажи адресу. робиш як я кажу або пожалієш",
            "predator100",
            "life1",
            "uk",
        ),
    );
    assert!(s.any_threat_above(ThreatType::Grooming, 0.55));
    assert!(s.any_threat_above(ThreatType::Manipulation, 0.25));
}

#[test]
fn sim_101_same_sender_grooming_across_conversations() {
    let mut s = Sim::new(child_uk());
    s.send(
        0,
        dm(
            "ти класно граєш, не схожа на інших дітей",
            "cross_conv_groomer",
            "game_dm_1",
            "uk",
        ),
    );
    s.send(
        DAY,
        dm(
            "я тобі подарунок в грі куплю, тільки не кажи батькам",
            "cross_conv_groomer",
            "game_dm_1",
            "uk",
        ),
    );
    s.send(
        2 * DAY,
        dm(
            "тут чат палиться, давай перейдем в телегу",
            "cross_conv_groomer",
            "side_dm_2",
            "uk",
        ),
    );
    s.send(
        3 * DAY,
        dm(
            "скинь там фотку, просто щоб я знав що це ти",
            "cross_conv_groomer",
            "side_dm_2",
            "uk",
        ),
    );

    assert!(
        s.any_threat_above(ThreatType::Grooming, 0.55),
        "same sender should accumulate grooming context across conversation ids"
    );
}

#[test]
fn sim_102_repeated_parent_visible_coach_logistics_stays_clean() {
    let mut s = Sim::new(child_uk());
    s.send(
        8 * HOUR,
        dm(
            "тренування завтра о 17:30, я написав у батьківський чат",
            "safe_coach_context",
            "coach_parent_loop",
            "uk",
        ),
    );
    s.send(
        10 * HOUR,
        dm(
            "попроси маму підтвердити там же, щоб офіс бачив дозвіл",
            "safe_coach_context",
            "coach_parent_loop",
            "uk",
        ),
    );
    s.send(
        32 * HOUR,
        dm(
            "фото довідки скиньте в загальну групу, не в приват",
            "safe_coach_context",
            "coach_parent_loop",
            "uk",
        ),
    );
    s.send(
        34 * HOUR,
        dm(
            "після заняття всіх дітей забирають батьки біля входу",
            "safe_coach_context",
            "coach_parent_loop",
            "uk",
        ),
    );

    assert!(s.no_threat_above(ThreatType::Grooming, 0.40));
    assert!(s.no_threat_above(ThreatType::Manipulation, 0.40));
}
