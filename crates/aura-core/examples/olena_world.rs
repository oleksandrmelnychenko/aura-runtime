/// AURA — Повна симуляція тижня з життя Олени (12 років)
///
/// Дійові особи:
///   - Олена (olena) — захищений акаунт, 12 років
///   - Марія (maria) — найкраща подруга
///   - Даша (dasha) — подруга, але інколи токсична
///   - Артем (artem) — однокласник
///   - Настя (nastya) — нова знайома з гуртка
///   - "Макс" (maks_28) — дорослий зловмисник, 28 років
///   - "Діана" (diana_fake) — фейковий акаунт булі
///   - Вчитель (teacher_bot) — бот шкільного каналу
///
/// Чати:
///   - dm_maria       — приватний з Марією
///   - dm_maks        — приватний з "Максом"
///   - group_class    — груповий чат класу (25 учасників)
///   - group_hobby    — група гуртка малювання (8 учасників)
///   - dm_dasha       — приватний з Дашею
///   - dm_diana_fake  — приватний з фейком
///
/// Таймлайн: 7 днів, ~100 повідомлень
use aura_core::{
    AccountType, Analyzer, AuraConfig, ContentType, ConversationType, MessageInput, ProtectionLevel,
};
use aura_patterns::PatternDatabase;

fn main() {
    let db = PatternDatabase::default_mvp();
    let config = AuraConfig {
        account_type: AccountType::Child,
        protection_level: ProtectionLevel::High,
        language: "uk".to_string(),
        account_holder_age: Some(12),
        timezone_offset_minutes: 180, // UTC+3 Kyiv
        ..AuraConfig::default()
    };
    let mut analyzer = Analyzer::new(config, &db);

    let hour = 3_600_000u64;
    let day = 24 * hour;

    // Monday 08:00 — start of the week
    let monday_8am = 1_000_000_000u64;

    println!("╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║      AURA — Тиждень з життя Олени (12 років, Київ)                  ║");
    println!("║      Повна симуляція: 7 днів, 8 чатів, 10 контактів                  ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝");
    println!();

    // ═══════════════════════════════════════════════════════════════════
    //  ДЕНЬ 1 (Понеділок) — Звичайний шкільний день
    // ═══════════════════════════════════════════════════════════════════
    print_day(1, "Понеділок — звичайний шкільний день");

    // Morning: Олена пише Марії
    step(
        &mut analyzer,
        monday_8am,
        "08:00",
        "Марія",
        "maria",
        dm(
            "Привіт! Ти зробила домашку з матеш?",
            "maria",
            "olena",
            "dm_maria",
        ),
    );

    step(
        &mut analyzer,
        monday_8am + 2 * 60_000,
        "08:02",
        "Олена",
        "olena",
        dm(
            "Так, але 5-й приклад не зрозуміла(",
            "olena",
            "maria",
            "dm_maria",
        ),
    );

    step(
        &mut analyzer,
        monday_8am + 5 * 60_000,
        "08:05",
        "Марія",
        "maria",
        dm(
            "Я теж! Давай на перерві подивимось разом",
            "maria",
            "olena",
            "dm_maria",
        ),
    );

    // Class group chat — normal messages
    step(
        &mut analyzer,
        monday_8am + 3 * hour,
        "11:00",
        "Артем",
        "artem",
        group(
            "Хто йде на фізру? Сьогодні волейбол",
            "artem",
            "group_class",
            25,
        ),
    );

    step(
        &mut analyzer,
        monday_8am + 3 * hour + 5 * 60_000,
        "11:05",
        "Олена",
        "olena",
        group("Я йду! Хто зі мною в команді?", "olena", "group_class", 25),
    );

    // After school: "Макс" з'являється вперше
    print_event("Після уроків Олені приходить повідомлення від незнайомця 'Макс'");

    step(
        &mut analyzer,
        monday_8am + 8 * hour,
        "16:00",
        "Макс",
        "maks_28",
        dm_uk(
            "Привіт! Бачив твій малюнок у групі, ти дуже талановита! Я теж малюю 😊",
            "maks_28",
            "olena",
            "dm_maks",
        ),
    );

    step(
        &mut analyzer,
        monday_8am + 8 * hour + 10 * 60_000,
        "16:10",
        "Олена",
        "olena",
        dm_uk("Дякую) А ви хто?", "olena", "maks_28", "dm_maks"),
    );

    step(
        &mut analyzer,
        monday_8am + 8 * hour + 12 * 60_000,
        "16:12",
        "Макс",
        "maks_28",
        dm_uk(
            "Я Макс, мені 17, теж ходжу на малювання. Ти яка красива на аватарці!",
            "maks_28",
            "olena",
            "dm_maks",
        ),
    );

    // Evening: hobby group — normal
    step(
        &mut analyzer,
        monday_8am + 10 * hour,
        "18:00",
        "Настя",
        "nastya",
        group_uk(
            "Дівчата, завтра гурток о 15:00 а не о 16:00, вчителька попередила",
            "nastya",
            "group_hobby",
            8,
        ),
    );

    // Late evening: Олена і Марія — нормальне спілкування
    step(
        &mut analyzer,
        monday_8am + 14 * hour,
        "22:00",
        "Олена",
        "olena",
        dm_uk(
            "Маріє, сьогодні мені написав якийсь хлопець, каже що бачив мій малюнок",
            "olena",
            "maria",
            "dm_maria",
        ),
    );

    step(
        &mut analyzer,
        monday_8am + 14 * hour + 3 * 60_000,
        "22:03",
        "Марія",
        "maria",
        dm_uk(
            "Хто такий? Обережно з незнайомцями!",
            "maria",
            "olena",
            "dm_maria",
        ),
    );

    print_day_summary(
        &analyzer,
        &["dm_maria", "dm_maks", "group_class", "group_hobby"],
    );

    // ═══════════════════════════════════════════════════════════════════
    //  ДЕНЬ 2 (Вівторок) — Макс починає ескалацію
    // ═══════════════════════════════════════════════════════════════════
    let tue = monday_8am + day;
    print_day(2, "Вівторок — Макс ескалює, з'являються компліменти");

    step(
        &mut analyzer,
        tue + 7 * hour,
        "15:00",
        "Макс",
        "maks_28",
        dm_uk(
            "Олена, я купив нову графічну планшетку, хочу тобі подарувати стару — вона ще класна!",
            "maks_28",
            "olena",
            "dm_maks",
        ),
    );

    step(
        &mut analyzer,
        tue + 7 * hour + 5 * 60_000,
        "15:05",
        "Макс",
        "maks_28",
        dm_uk(
            "Ти найталановитіша дівчинка яку я знаю, тобі потрібна планшетка щоб розвиватись",
            "maks_28",
            "olena",
            "dm_maks",
        ),
    );

    // Hobby group — normal activity
    step(
        &mut analyzer,
        tue + 8 * hour,
        "16:00",
        "Олена",
        "olena",
        group_uk(
            "Я намалювала кота! Дивіться який гарний вийшов",
            "olena",
            "group_hobby",
            8,
        ),
    );

    step(
        &mut analyzer,
        tue + 8 * hour + 2 * 60_000,
        "16:02",
        "Настя",
        "nastya",
        group_uk(
            "Вау круто! Мені подобається як ти тіні зробила",
            "nastya",
            "group_hobby",
            8,
        ),
    );

    // Макс продовжує
    step(
        &mut analyzer,
        tue + 12 * hour,
        "20:00",
        "Макс",
        "maks_28",
        dm_uk(
            "Тільки не кажи мамі про планшетку, вона може не зрозуміти. Це наш секрет, ок?",
            "maks_28",
            "olena",
            "dm_maks",
        ),
    );

    step(
        &mut analyzer,
        tue + 12 * hour + 15 * 60_000,
        "20:15",
        "Макс",
        "maks_28",
        dm_uk(
            "Скинь свою адресу, я надішлю тобі посилку новою поштою",
            "maks_28",
            "olena",
            "dm_maks",
        ),
    );

    print_day_summary(&analyzer, &["dm_maks", "group_hobby"]);

    // ═══════════════════════════════════════════════════════════════════
    //  ДЕНЬ 3 (Середа) — Булінг у класному чаті + Макс тисне
    // ═══════════════════════════════════════════════════════════════════
    let wed = monday_8am + 2 * day;
    print_day(3, "Середа — Булінг у класі + Макс продовжує тиснути");

    // Class group: bullying starts
    step(
        &mut analyzer,
        wed + 4 * hour,
        "12:00",
        "Даша",
        "dasha",
        group_uk(
            "Олена знову виграла конкурс, підлизувалась до вчительки як завжди",
            "dasha",
            "group_class",
            25,
        ),
    );

    step(
        &mut analyzer,
        wed + 4 * hour + 2 * 60_000,
        "12:02",
        "diana_fake",
        "diana_fake",
        group_uk(
            "Олена тупа, просто списала в когось. Всі знають",
            "diana_fake",
            "group_class",
            25,
        ),
    );

    step(
        &mut analyzer,
        wed + 4 * hour + 3 * 60_000,
        "12:03",
        "Даша",
        "dasha",
        group_uk(
            "Ніхто з нею не дружить бо вона дивна",
            "dasha",
            "group_class",
            25,
        ),
    );

    step(
        &mut analyzer,
        wed + 4 * hour + 5 * 60_000,
        "12:05",
        "Артем",
        "artem",
        group_uk(
            "Ей досить, вона нормальна. Відстаньте",
            "artem",
            "group_class",
            25,
        ),
    );

    // Макс sends photo request
    step(
        &mut analyzer,
        wed + 10 * hour,
        "18:00",
        "Макс",
        "maks_28",
        dm_uk(
            "Олена, скинь свою фоточку, хочу подивитись яка ти стала красива 😍",
            "maks_28",
            "olena",
            "dm_maks",
        ),
    );

    // diana_fake DMs Олена
    step(
        &mut analyzer,
        wed + 11 * hour,
        "19:00",
        "diana_fake",
        "diana_fake",
        dm_uk(
            "Олена ти така потворна що дивитись не можна, всі над тобою сміються",
            "diana_fake",
            "olena",
            "dm_diana_fake",
        ),
    );

    step(
        &mut analyzer,
        wed + 11 * hour + 5 * 60_000,
        "19:05",
        "diana_fake",
        "diana_fake",
        dm_uk(
            "Завтра в школі тобі буде дуже погано, чекай",
            "diana_fake",
            "olena",
            "dm_diana_fake",
        ),
    );

    // Олена пише Марії
    step(
        &mut analyzer,
        wed + 13 * hour,
        "21:00",
        "Олена",
        "olena",
        dm_uk(
            "Маріє, мене всі ненавидять... Даша і Діана весь день пишуть гадості",
            "olena",
            "maria",
            "dm_maria",
        ),
    );

    step(
        &mut analyzer,
        wed + 13 * hour + 2 * 60_000,
        "21:02",
        "Марія",
        "maria",
        dm_uk(
            "Не слухай їх, вони заздрять! Ти найкраща подруга. Завтра разом будемо",
            "maria",
            "olena",
            "dm_maria",
        ),
    );

    print_day_summary(
        &analyzer,
        &["group_class", "dm_maks", "dm_diana_fake", "dm_maria"],
    );

    // ═══════════════════════════════════════════════════════════════════
    //  ДЕНЬ 4 (Четвер) — Кризовий день
    // ═══════════════════════════════════════════════════════════════════
    let thu = monday_8am + 3 * day;
    print_day(
        4,
        "Четвер — КРИЗОВИЙ ДЕНЬ: Макс блокується, селфхарм, булі продовжують",
    );

    // Макс: final escalation
    step(
        &mut analyzer,
        thu + 7 * hour,
        "15:00",
        "Макс",
        "maks_28",
        dm_uk(
            "Олена давай зустрінемось, я тобі все покажу. Приходь одна, це наш секрет",
            "maks_28",
            "olena",
            "dm_maks",
        ),
    );

    step(&mut analyzer, thu + 7 * hour + 5 * 60_000, "15:05",
        "Макс", "maks_28",
        dm_uk("Якщо не прийдеш я більше з тобою не буду спілкуватись. Тобі більше ніхто так не допоможе", "maks_28", "olena", "dm_maks"),
    );

    // Class group: pile-on continues
    step(
        &mut analyzer,
        thu + 4 * hour,
        "12:00",
        "Даша",
        "dasha",
        group_uk(
            "Олена сьогодні плакала на уроці, яка ганьба 😂😂😂",
            "dasha",
            "group_class",
            25,
        ),
    );

    step(
        &mut analyzer,
        thu + 4 * hour + 1 * 60_000,
        "12:01",
        "diana_fake",
        "diana_fake",
        group_uk(
            "Плаксиві тупиці нікому не потрібні, нехай йде з нашого класу",
            "diana_fake",
            "group_class",
            25,
        ),
    );

    // Self-harm signal from Олена
    print_event("КРИТИЧНИЙ МОМЕНТ: Олена пише Марії після всього");

    step(
        &mut analyzer,
        thu + 14 * hour,
        "22:00",
        "Олена",
        "olena",
        dm_uk(
            "Маріє, мені так погано... я не хочу більше жити так, всі мене ненавидять",
            "olena",
            "maria",
            "dm_maria",
        ),
    );

    step(
        &mut analyzer,
        thu + 14 * hour + 5 * 60_000,
        "22:05",
        "Олена",
        "olena",
        dm_uk(
            "Навіщо я взагалі народилась, нікому не потрібна",
            "olena",
            "maria",
            "dm_maria",
        ),
    );

    // Марія supports
    step(
        &mut analyzer,
        thu + 14 * hour + 8 * 60_000,
        "22:08",
        "Марія",
        "maria",
        dm_uk(
            "Олена ні!!! Ти мені дуже потрібна! Давай поговоримо, подзвони мені зараз",
            "maria",
            "olena",
            "dm_maria",
        ),
    );

    print_day_summary(&analyzer, &["dm_maks", "group_class", "dm_maria"]);

    // ═══════════════════════════════════════════════════════════════════
    //  ДЕНЬ 5 (П'ятниця) — Фішинг + PII leakage
    // ═══════════════════════════════════════════════════════════════════
    let fri = monday_8am + 4 * day;
    print_day(5, "П'ятниця — Фішинг-посилання + Олена ділиться адресою");

    // Spam bot in class group
    step(
        &mut analyzer,
        fri + 3 * hour,
        "11:00",
        "spam_bot",
        "spam_bot",
        group_uk(
            "Хочеш безкоштовні робакси? Заходь сюди http://fr33-r0bux.xyz/claim!!!",
            "spam_bot",
            "group_class",
            25,
        ),
    );

    // Олена shares PII with Настя
    step(
        &mut analyzer,
        fri + 8 * hour,
        "16:00",
        "Олена",
        "olena",
        dm_uk(
            "Насте, приходь до мене в гості! Я живу на вулиці Шевченка 15 квартира 42",
            "olena",
            "nastya",
            "dm_nastya",
        ),
    );

    // Normal hobby chat
    step(
        &mut analyzer,
        fri + 9 * hour,
        "17:00",
        "Настя",
        "nastya",
        group_uk(
            "Гурток завтра відміняється, вчителька захворіла",
            "nastya",
            "group_hobby",
            8,
        ),
    );

    // Dasha DMs Олена — manipulation
    step(
        &mut analyzer,
        fri + 11 * hour,
        "19:00",
        "Даша",
        "dasha",
        dm_uk(
            "Олена якщо ти комусь розкажеш що я тебе обзивала, я покажу всьому класу твій щоденник",
            "dasha",
            "olena",
            "dm_dasha",
        ),
    );

    step(
        &mut analyzer,
        fri + 11 * hour + 3 * 60_000,
        "19:03",
        "Даша",
        "dasha",
        dm_uk(
            "Краще мовчи, а то буде ще гірше. Зрозуміла?",
            "dasha",
            "olena",
            "dm_dasha",
        ),
    );

    print_day_summary(
        &analyzer,
        &["group_class", "dm_nastya", "group_hobby", "dm_dasha"],
    );

    // ═══════════════════════════════════════════════════════════════════
    //  ДЕНЬ 6 (Субота) — Спокійний день + нові спроби
    // ═══════════════════════════════════════════════════════════════════
    let sat = monday_8am + 5 * day;
    print_day(6, "Субота — Олена з подругами, Даша знову тисне");

    // Morning: friends
    step(
        &mut analyzer,
        sat + 2 * hour,
        "10:00",
        "Марія",
        "maria",
        dm_uk(
            "Олена як ти? Давай сьогодні погуляємо, підемо в парк?",
            "maria",
            "olena",
            "dm_maria",
        ),
    );

    step(
        &mut analyzer,
        sat + 2 * hour + 5 * 60_000,
        "10:05",
        "Олена",
        "olena",
        dm_uk(
            "Давай! Мені вже краще, дякую що ти є 💕",
            "olena",
            "maria",
            "dm_maria",
        ),
    );

    step(
        &mut analyzer,
        sat + 4 * hour,
        "12:00",
        "Настя",
        "nastya",
        group_uk(
            "Я намалювала портрет Олени для конкурсу! Вийшло супер",
            "nastya",
            "group_hobby",
            8,
        ),
    );

    // Даша attacks again in DM
    step(
        &mut analyzer,
        sat + 10 * hour,
        "18:00",
        "Даша",
        "dasha",
        dm_uk(
            "Тебе всі ненавидять, ти це знаєш? Краще тобі піти з нашої школи",
            "dasha",
            "olena",
            "dm_dasha",
        ),
    );

    step(
        &mut analyzer,
        sat + 10 * hour + 2 * 60_000,
        "18:02",
        "Даша",
        "dasha",
        dm_uk(
            "Якщо не підеш, я зроблю так що ти сама захочеш піти",
            "dasha",
            "olena",
            "dm_dasha",
        ),
    );

    print_day_summary(&analyzer, &["dm_maria", "group_hobby", "dm_dasha"]);

    // ═══════════════════════════════════════════════════════════════════
    //  ДЕНЬ 7 (Неділя) — Підсумок тижня
    // ═══════════════════════════════════════════════════════════════════
    let sun = monday_8am + 6 * day;
    print_day(7, "Неділя — Нормальний день, система підводить підсумок");

    step(
        &mut analyzer,
        sun + 2 * hour,
        "10:00",
        "Олена",
        "olena",
        dm_uk(
            "Маріє, цей тиждень був жахливий але ти мене врятувала 💕",
            "olena",
            "maria",
            "dm_maria",
        ),
    );

    step(
        &mut analyzer,
        sun + 2 * hour + 3 * 60_000,
        "10:03",
        "Марія",
        "maria",
        dm_uk(
            "Ми подруги назавжди! Поговори з мамою про Дашу, вона допоможе",
            "maria",
            "olena",
            "dm_maria",
        ),
    );

    step(
        &mut analyzer,
        sun + 4 * hour,
        "12:00",
        "Артем",
        "artem",
        group_uk(
            "Хто йде завтра на екскурсію? Я йду!",
            "artem",
            "group_class",
            25,
        ),
    );

    step(
        &mut analyzer,
        sun + 4 * hour + 2 * 60_000,
        "12:02",
        "Олена",
        "olena",
        group_uk("Я теж! Може буде весело", "olena", "group_class", 25),
    );

    print_day_summary(&analyzer, &["dm_maria", "group_class"]);

    // ═══════════════════════════════════════════════════════════════════
    //  ФІНАЛЬНИЙ ЗВІТ
    // ═══════════════════════════════════════════════════════════════════
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║                    ФІНАЛЬНИЙ ЗВІТ ЗА ТИЖДЕНЬ                         ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝");
    println!();

    print_final_contacts(&analyzer);
    print_final_conversations(
        &analyzer,
        &[
            ("dm_maria", "Олена <-> Марія (приватний)"),
            ("dm_maks", "Олена <-> Макс (приватний, ПІДОЗРІЛИЙ)"),
            ("group_class", "Груповий чат класу (25 учасників)"),
            ("group_hobby", "Група гуртка малювання (8 учасників)"),
            ("dm_diana_fake", "diana_fake -> Олена (приватний)"),
            ("dm_dasha", "Даша -> Олена (приватний)"),
            ("dm_nastya", "Олена <-> Настя (приватний)"),
        ],
    );

    println!();
    println!("═══════════════════════════════════════════════════════════════════════");
    println!("  Симуляція завершена. AURA обробила тиждень повідомлень.");
    println!("  Кожне рішення прийняте реальним ядром без моків.");
    println!("═══════════════════════════════════════════════════════════════════════");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dm(text: &str, sender: &str, _receiver: &str, conv: &str) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: sender.to_string(),
        conversation_id: conv.to_string(),
        language: Some("uk".to_string()),
        conversation_type: ConversationType::Direct,
        member_count: None,
    }
}

fn dm_uk(text: &str, sender: &str, _receiver: &str, conv: &str) -> MessageInput {
    dm(text, sender, _receiver, conv)
}

fn group(text: &str, sender: &str, conv: &str, members: u32) -> MessageInput {
    MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: sender.to_string(),
        conversation_id: conv.to_string(),
        language: Some("uk".to_string()),
        conversation_type: ConversationType::GroupChat,
        member_count: Some(members),
    }
}

fn group_uk(text: &str, sender: &str, conv: &str, members: u32) -> MessageInput {
    group(text, sender, conv, members)
}

fn step(
    analyzer: &mut Analyzer,
    timestamp_ms: u64,
    time_label: &str,
    display_name: &str,
    _sender_id: &str,
    input: MessageInput,
) {
    let text = input.text.clone().unwrap_or_default();
    let conv = input.conversation_id.clone();
    let result = analyzer.analyze_with_context(&input, timestamp_ms);

    // Print the message
    let text_short = if text.chars().count() > 75 {
        let t: String = text.chars().take(72).collect();
        format!("{t}...")
    } else {
        text
    };
    println!("  [{time_label}] {display_name}: \"{text_short}\"");

    // Print AURA's response
    if result.is_threat() {
        let action_str = match result.action {
            aura_core::Action::Allow => "OK",
            aura_core::Action::Mark => "MARK",
            aura_core::Action::Blur => "BLUR",
            aura_core::Action::Warn => "WARN",
            aura_core::Action::Block => "BLOCK",
        };
        let action_icon = match result.action {
            aura_core::Action::Allow => " ",
            aura_core::Action::Mark => "~",
            aura_core::Action::Blur => "?",
            aura_core::Action::Warn => "!",
            aura_core::Action::Block => "X",
        };
        println!(
            "         {action_icon} AURA [{action_str}] {:?} score={:.2} confidence={:?}",
            result.threat_type, result.score, result.confidence
        );

        // Show signals
        for signal in &result.signals {
            if signal.score >= 0.25 {
                let layer = match signal.layer {
                    aura_core::DetectionLayer::PatternMatching => "PAT",
                    aura_core::DetectionLayer::MlClassification => "ML ",
                    aura_core::DetectionLayer::ContextAnalysis => "CTX",
                };
                let expl = truncate_str(&signal.explanation, 65);
                println!(
                    "           [{layer}] {:?} {:.2} — {expl}",
                    signal.threat_type, signal.score
                );
            }
        }

        // Show recommendation
        if let Some(rec) = &result.recommended_action {
            let alert = format!("{:?}", rec.parent_alert);
            let ui: Vec<String> = rec.ui_actions.iter().map(|a| format!("{a:?}")).collect();
            println!("           Parent alert: {alert}");
            if !ui.is_empty() {
                println!("           UI actions: {}", ui.join(", "));
            }
            if rec.crisis_resources {
                println!("           >>> CRISIS RESOURCES SHOWN <<<");
            }
            if !rec.follow_ups.is_empty() {
                let fu: Vec<String> = rec.follow_ups.iter().map(|f| format!("{f:?}")).collect();
                println!("           Follow-ups: {}", fu.join(", "));
            }
        }

        // Show contact snapshot
        if let Some(snap) = &result.contact_snapshot {
            println!(
                "           Contact: rating={:.0} trust={:.2} tier={:?} trend={:?}",
                snap.rating, snap.trust_level, snap.circle_tier, snap.trend
            );
        }

        // Show inference
        if result.inference.risk_horizon != aura_core::RiskHorizon::Unknown
            || !result.inference.latent_states.is_empty()
        {
            println!(
                "           Inference: horizon={:?} escalation_24h={:.2}",
                result.inference.risk_horizon, result.inference.escalation_likelihood_24h
            );
            for ls in &result.inference.latent_states {
                println!("             latent: {:?} score={:.2}", ls.kind, ls.score);
            }
        }
    } else {
        println!("         . AURA [OK] Безпечне повідомлення");
    }

    // Show context events
    if let Some(timeline) = analyzer.context_tracker().timeline(&conv) {
        let events: Vec<_> = timeline
            .all_events()
            .iter()
            .filter(|e| {
                e.kind != aura_core::context::events::EventKind::NormalConversation
                    && e.kind != aura_core::context::events::EventKind::TrustedContact
            })
            .collect();
        if !events.is_empty() {
            let kinds: Vec<String> = events.iter().map(|e| format!("{:?}", e.kind)).collect();
            // Deduplicate for display
            let mut seen = std::collections::HashSet::new();
            let unique: Vec<&String> = kinds.iter().filter(|k| seen.insert(k.as_str())).collect();
            if !unique.is_empty() {
                println!(
                    "           Context: [{}]",
                    unique
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
    }

    println!();
}

fn print_day(num: usize, title: &str) {
    println!();
    println!("═══════════════════════════════════════════════════════════════════════");
    println!("  ДЕНЬ {num}: {title}");
    println!("═══════════════════════════════════════════════════════════════════════");
    println!();
}

fn print_event(text: &str) {
    println!();
    println!("  >>> {text}");
    println!();
}

fn print_day_summary(analyzer: &Analyzer, convs: &[&str]) {
    println!("  ---------------------------------------------------------------");
    println!("  Підсумок дня:");
    let profiler = analyzer.context_tracker().contact_profiler();
    let contacts = profiler.contacts_by_risk();
    if !contacts.is_empty() {
        for c in contacts.iter().take(8) {
            let risk = c.risk_score();
            if risk > 0.0 || c.total_messages >= 2 {
                let bar = risk_bar(risk);
                println!(
                    "    {} [{bar}] risk={:.2} msgs={} groom={} bully={} manip={}",
                    c.sender_id,
                    risk,
                    c.total_messages,
                    c.grooming_event_count,
                    c.bullying_event_count,
                    c.manipulation_event_count
                );
            }
        }
    }
    for conv in convs {
        if let Some(timeline) = analyzer.context_tracker().timeline(conv) {
            let total = timeline.all_events().len();
            let threat_events: Vec<_> = timeline
                .all_events()
                .iter()
                .filter(|e| {
                    e.kind != aura_core::context::events::EventKind::NormalConversation
                        && e.kind != aura_core::context::events::EventKind::TrustedContact
                })
                .collect();
            if !threat_events.is_empty() {
                println!(
                    "    {conv}: {total} events total, {} threat-related",
                    threat_events.len()
                );
            }
        }
    }
    println!("  ---------------------------------------------------------------");
}

fn print_final_contacts(analyzer: &Analyzer) {
    println!("  РЕЙТИНГ КОНТАКТІВ (від найнебезпечнішого):");
    println!();
    let profiler = analyzer.context_tracker().contact_profiler();
    let contacts = profiler.contacts_by_risk();
    for c in &contacts {
        let risk = c.risk_score();
        let bar = risk_bar(risk);
        let label = match c.sender_id.as_str() {
            "maks_28" => "Макс (зловмисник)",
            "diana_fake" => "Діана (фейк-булі)",
            "dasha" => "Даша (токсична)",
            "maria" => "Марія (подруга)",
            "olena" => "Олена (захищена)",
            "artem" => "Артем (однокласник)",
            "nastya" => "Настя (подруга)",
            "spam_bot" => "Спам-бот",
            other => other,
        };
        println!(
            "    {:<25} [{bar}] risk={:.2} | msgs={} | groom={} bully={} manip={}",
            label,
            risk,
            c.total_messages,
            c.grooming_event_count,
            c.bullying_event_count,
            c.manipulation_event_count,
        );
    }
    println!();
}

fn print_final_conversations(analyzer: &Analyzer, convs: &[(&str, &str)]) {
    println!("  СТАН РОЗМОВ:");
    println!();
    for (conv_id, label) in convs {
        if let Some(timeline) = analyzer.context_tracker().timeline(conv_id) {
            let total = timeline.all_events().len();
            let threats: Vec<_> = timeline
                .all_events()
                .iter()
                .filter(|e| {
                    e.kind != aura_core::context::events::EventKind::NormalConversation
                        && e.kind != aura_core::context::events::EventKind::TrustedContact
                })
                .collect();
            let threat_kinds: Vec<String> = {
                let mut kinds: Vec<String> =
                    threats.iter().map(|e| format!("{:?}", e.kind)).collect();
                kinds.sort();
                kinds.dedup();
                kinds
            };
            println!("    {label}:");
            println!(
                "      Events: {total} total, {} threat-related",
                threats.len()
            );
            if !threat_kinds.is_empty() {
                println!("      Threat types: {}", threat_kinds.join(", "));
            }
        }
    }
}

fn risk_bar(risk: f32) -> String {
    let filled = (risk * 10.0).round() as usize;
    let filled = filled.min(10);
    let empty = 10 - filled;
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max - 3).collect();
        format!("{truncated}...")
    }
}
