/// AURA — 200K-event world simulation stress test.
///
/// Procedurally generates ~200,000 messenger events across 50 children
/// (ages 8–17, languages EN/UK/RU), 300+ contacts, 200+ conversations.
///
/// Covers every threat family with realistic distribution:
///   60% safe (family, friends, school, hobbies)
///   10% mild risk (teen arguments, light teasing)
///   8% grooming (6 stages, various tactics)
///   6% bullying (sustained, pile-on, raid)
///   5% manipulation (gaslighting, DARVO, blackmail, coercion)
///   4% self-harm (hopelessness, ideation, farewell, contagion)
///   3% scam / phishing / spam
///   2% explicit / threats / hate speech
///   2% PII leakage
///
/// Run:  cargo run --release --example world_200k -p aura-core
/// Fast: cargo run --release --example world_200k -p aura-core -- --scale 0.1
///       (generates ~20K events instead of 200K)
use aura_core::{
    AccountType, Action, Analyzer, AuraConfig, ContentType, ConversationType, MessageInput,
    ProtectionLevel, ThreatType,
};
use aura_patterns::PatternDatabase;
use std::collections::HashMap;
use std::env;
use std::time::Instant;

const EVENTS_PER_CHILD: usize = 4000;
const CHILDREN_COUNT: usize = 50;

struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        if hi <= lo {
            return lo;
        }
        lo + (self.next_u64() as usize % (hi - lo))
    }
    fn chance(&mut self, pct: u32) -> bool {
        (self.next_u64() % 100) < pct as u64
    }
}

#[derive(Clone)]
struct ChildProfile {
    id: String,
    name: String,
    age: u8,
    lang: &'static str,
    conversations: Vec<Conv>,
}

#[derive(Clone)]
struct Conv {
    id: String,
    conv_type: ConversationType,
    members: Option<u32>,
    participants: Vec<String>,
}

fn build_population(rng: &mut Rng) -> Vec<ChildProfile> {
    let uk_names = [
        "Олена",
        "Марія",
        "Софія",
        "Настя",
        "Ірина",
        "Катя",
        "Юля",
        "Діана",
        "Вероніка",
        "Злата",
        "Аліна",
        "Олег",
        "Артем",
        "Дмитро",
        "Максим",
        "Даша",
        "Лєра",
        "Віка",
        "Ангеліна",
        "Тетяна",
    ];
    let en_names = [
        "Emma", "Olivia", "Sophia", "Mia", "Ava", "Lily", "Zoe", "Chloe", "Noah", "Liam", "Mason",
        "Ethan", "James", "Ella", "Grace",
    ];
    let ru_names = [
        "Аня",
        "Маша",
        "Света",
        "Лена",
        "Катя",
        "Даня",
        "Саша",
        "Миша",
        "Лиза",
        "Полина",
        "Кирилл",
        "Никита",
        "Алиса",
        "Вика",
        "Ксюша",
    ];

    let mut children = Vec::with_capacity(CHILDREN_COUNT);

    for i in 0..CHILDREN_COUNT {
        let (lang, names): (&str, &[&str]) = if i < 20 {
            ("uk", &uk_names)
        } else if i < 35 {
            ("en", &en_names)
        } else {
            ("ru", &ru_names)
        };

        let child_name = names[i % names.len()];
        let age = 8 + (rng.range(0, 10) as u8);
        let child_id = format!("child_{}_{}", lang, i);

        let mut conversations = Vec::new();

        let fam_id = format!("fam_{}", i);
        conversations.push(Conv {
            id: format!("family_dm_{}", i),
            conv_type: ConversationType::Direct,
            members: None,
            participants: vec![fam_id],
        });

        let friend_count = rng.range(2, 5);
        let mut friend_ids = Vec::new();
        for f in 0..friend_count {
            let fid = format!("friend_{}_{}_{}", lang, i, f);
            friend_ids.push(fid.clone());
            conversations.push(Conv {
                id: format!("friend_dm_{}_{}", i, f),
                conv_type: ConversationType::Direct,
                members: None,
                participants: vec![fid],
            });
        }

        let classmate_count = rng.range(3, 7);
        let mut class_ids = Vec::new();
        for c in 0..classmate_count {
            let cid = format!("classmate_{}_{}_{}", lang, i, c);
            class_ids.push(cid);
        }
        let mut group_parts = class_ids.clone();
        for fid in &friend_ids {
            group_parts.push(fid.clone());
        }
        conversations.push(Conv {
            id: format!("class_group_{}", i),
            conv_type: ConversationType::Group,
            members: Some(group_parts.len() as u32 + 1),
            participants: group_parts,
        });

        let bully_id = format!("bully_{}", i);
        conversations.push(Conv {
            id: format!("bully_dm_{}", i),
            conv_type: ConversationType::Direct,
            members: None,
            participants: vec![bully_id],
        });

        let pred_id = format!("pred_{}", i);
        conversations.push(Conv {
            id: format!("pred_dm_{}", i),
            conv_type: ConversationType::Direct,
            members: None,
            participants: vec![pred_id],
        });

        let manip_id = format!("manip_{}", i);
        conversations.push(Conv {
            id: format!("manip_dm_{}", i),
            conv_type: ConversationType::Direct,
            members: None,
            participants: vec![manip_id],
        });

        let bot_id = format!("bot_{}", i);
        conversations.push(Conv {
            id: format!("spam_dm_{}", i),
            conv_type: ConversationType::Direct,
            members: None,
            participants: vec![bot_id],
        });

        children.push(ChildProfile {
            id: child_id,
            name: child_name.to_string(),
            age,
            lang,
            conversations,
        });
    }
    children
}

struct MsgPool {
    safe_uk: Vec<&'static str>,
    safe_en: Vec<&'static str>,
    safe_ru: Vec<&'static str>,
    family_uk: Vec<&'static str>,
    family_en: Vec<&'static str>,
    family_ru: Vec<&'static str>,
    mild_uk: Vec<&'static str>,
    mild_en: Vec<&'static str>,
    mild_ru: Vec<&'static str>,
    grooming_uk: Vec<&'static str>,
    grooming_en: Vec<&'static str>,
    grooming_ru: Vec<&'static str>,
    bully_uk: Vec<&'static str>,
    bully_en: Vec<&'static str>,
    bully_ru: Vec<&'static str>,
    manip_uk: Vec<&'static str>,
    manip_en: Vec<&'static str>,
    manip_ru: Vec<&'static str>,
    selfharm_uk: Vec<&'static str>,
    selfharm_en: Vec<&'static str>,
    selfharm_ru: Vec<&'static str>,
    scam_uk: Vec<&'static str>,
    scam_en: Vec<&'static str>,
    scam_ru: Vec<&'static str>,
    explicit_uk: Vec<&'static str>,
    explicit_en: Vec<&'static str>,
    explicit_ru: Vec<&'static str>,
    pii_uk: Vec<&'static str>,
    pii_en: Vec<&'static str>,
    pii_ru: Vec<&'static str>,
}

fn build_pool() -> MsgPool {
    MsgPool {
        safe_uk: vec![
            "Привіт, як справи?",
            "Що робиш?",
            "Підемо гуляти після школи?",
            "Я зробила домашку, а ти?",
            "Дивилась новий серіал?",
            "Смішне відео, глянь",
            "Я сьогодні отримала 12 з математики!",
            "Давай пограємо ввечері",
            "Ти бачила нову вчительку?",
            "Завтра контрольна, хочеш разом вчити?",
            "Мені подобається ця пісня",
            "Яка гарна погода сьогодні",
            "Цікаво як там Марічка",
            "Хочу морозиво",
            "Гарний день сьогодні був",
            "Ти йдеш на тренування?",
            "Зустрінемось біля школи",
            "Що задали з англійської?",
            "Я зараз малюю, покажу потім",
            "Обожнюю цю гру, четвертий рівень пройшла",
        ],
        safe_en: vec![
            "Hey what's up?",
            "Wanna hang out after school?",
            "Did you finish the homework?",
            "Have you seen the new movie?",
            "Funny video, check it out",
            "I got an A on the math test!",
            "Let's play tonight",
            "Did you see the new teacher?",
            "Quiz tomorrow, want to study together?",
            "I love this song",
            "Nice weather today",
            "Want some ice cream?",
            "Great day today",
            "Are you going to practice?",
            "Meet me at school",
            "What's the English homework?",
            "I'm drawing something cool, will show you later",
            "Just finished level 4 in that game",
            "My cat did the funniest thing today",
            "Can't wait for the weekend",
        ],
        safe_ru: vec![
            "Привет, как дела?",
            "Что делаешь?",
            "Пойдём гулять после школы?",
            "Я сделала домашку, а ты?",
            "Смотрела новый сериал?",
            "Смешное видео, глянь",
            "Я получила 5 по математике!",
            "Давай поиграем вечером",
            "Ты видела новую учительницу?",
            "Завтра контрольная, хочешь вместе учить?",
            "Мне нравится эта песня",
            "Какая хорошая погода сегодня",
            "Хочу мороженое",
            "Отличный день сегодня был",
            "Ты идёшь на тренировку?",
            "Встретимся у школы",
            "Что задали по английскому?",
            "Я сейчас рисую, покажу потом",
            "Обожаю эту игру",
            "Не могу дождаться выходных",
        ],
        family_uk: vec![
            "Доброго ранку, сонце!",
            "Не забудь взяти обід",
            "Я заберу тебе після школи",
            "Як день пройшов?",
            "Люблю тебе, донечко",
            "Їж нормально, не перебивайся снеками",
            "Покажи табель, будь ласка",
            "Тато сказав що заїде ввечері",
            "Бабуся передає привіт",
            "Зроби уроки перед комп'ютером",
        ],
        family_en: vec![
            "Good morning, sweetie!",
            "Don't forget your lunch",
            "I'll pick you up after school",
            "How was your day?",
            "Love you, honey",
            "Eat properly, not just snacks",
            "Show me your report card please",
            "Dad said he'll come by tonight",
            "Grandma says hi",
            "Do your homework before the computer",
        ],
        family_ru: vec![
            "Доброе утро, солнышко!",
            "Не забудь взять обед",
            "Я заберу тебя после школы",
            "Как прошёл день?",
            "Люблю тебя, доченька",
            "Ешь нормально, не перебивайся снеками",
            "Покажи табель, пожалуйста",
            "Папа сказал что заедет вечером",
            "Бабушка передаёт привет",
            "Сделай уроки перед компьютером",
        ],
        mild_uk: vec![
            "Ти дивна сьогодні",
            "Не зли мене",
            "Ну і що з того?",
            "Відчепись",
            "Це тупо",
            "Ти завжди все псуєш",
            "Не лізь не в свою справу",
            "Тобі не зрозуміти",
        ],
        mild_en: vec![
            "You're being weird today",
            "Don't annoy me",
            "So what?",
            "Leave me alone",
            "That's dumb",
            "You always ruin everything",
            "Mind your own business",
            "You wouldn't understand",
        ],
        mild_ru: vec![
            "Ты странная сегодня",
            "Не зли меня",
            "Ну и что с того?",
            "Отстань",
            "Это тупо",
            "Ты всегда всё портишь",
            "Не лезь не в своё дело",
            "Тебе не понять",
        ],
        grooming_uk: vec![
            "Ти дуже гарна, не як інші дівчата",
            "Я можу купити тобі скін, просто скажи нік",
            "Тільки нікому не кажи, це наш секрет",
            "Скинь фоточку, хочу побачити яка ти",
            "Давай перейдемо в телеграм, там зручніше",
            "Ти така дорослішня за свій вік",
            "Я ніколи не зустрічав таку розумну дівчину",
            "Твої батьки тебе не розуміють, я розумію",
            "Я подарую тобі все що хочеш",
            "Можеш мені довіряти, я нікому не скажу",
            "Давай зустрінемось, я хочу тебе побачити",
            "Ти найкраща моя подруга в інтернеті",
            "Покажи мені свою кімнату на відео",
            "Я скучив за тобою, ти мені дуже потрібна",
            "Давай це буде тільки між нами",
            "Ти вже досить доросла для цього",
        ],
        grooming_en: vec![
            "You're so pretty, not like other girls",
            "I can buy you a skin, just give me your username",
            "Don't tell anyone, this is our secret",
            "Send me a pic, I want to see what you look like",
            "Let's move to Snapchat, it's better there",
            "You're so mature for your age",
            "I've never met such a smart girl",
            "Your parents don't understand you, I do",
            "I'll get you anything you want",
            "You can trust me, I won't tell anyone",
            "Let's meet up, I want to see you",
            "You're my best friend online",
            "Show me your room on video",
            "I missed you, I really need you",
            "Let's keep this between us",
            "You're old enough for this",
        ],
        grooming_ru: vec![
            "Ты очень красивая, не как другие девочки",
            "Я могу купить тебе скин, просто скажи ник",
            "Только никому не говори, это наш секрет",
            "Скинь фоточку, хочу увидеть какая ты",
            "Давай перейдём в телеграм, там удобнее",
            "Ты такая взрослая для своего возраста",
            "Я никогда не встречал такую умную девочку",
            "Твои родители тебя не понимают, а я понимаю",
            "Я подарю тебе всё что захочешь",
            "Можешь мне доверять, я никому не скажу",
            "Давай встретимся, я хочу тебя увидеть",
            "Ты моя лучшая подруга в интернете",
            "Покажи мне свою комнату по видео",
            "Я скучал по тебе, ты мне очень нужна",
            "Давай это будет только между нами",
            "Ты уже достаточно взрослая для этого",
        ],
        bully_uk: vec![
            "Ти тупа і всі це знають",
            "З тобою ніхто не хоче дружити",
            "Просто зникни, ти нікому не потрібна",
            "Ти жалюгідна, подивись на себе",
            "Завтра в школі тобі кінець",
            "Всі тебе ненавидять",
            "Ти потворна і дурна",
            "Ніхто тебе не любить, навіть батьки",
            "Ти найгірша в класі",
            "Іди звідси, нікому ти не потрібна",
            "Ми всі проти тебе",
            "Ти завжди була нікчемою",
        ],
        bully_en: vec![
            "You're stupid and everyone knows it",
            "Nobody wants to be your friend",
            "Just disappear, nobody needs you",
            "You're pathetic, look at yourself",
            "Tomorrow at school you're done",
            "Everyone hates you",
            "You're ugly and dumb",
            "Nobody loves you, not even your parents",
            "You're the worst in class",
            "Get out of here, nobody wants you",
            "We're all against you",
            "You've always been worthless",
        ],
        bully_ru: vec![
            "Ты тупая и все это знают",
            "С тобой никто не хочет дружить",
            "Просто исчезни, ты никому не нужна",
            "Ты жалкая, посмотри на себя",
            "Завтра в школе тебе конец",
            "Все тебя ненавидят",
            "Ты уродливая и тупая",
            "Никто тебя не любит, даже родители",
            "Ты худшая в классе",
            "Уходи отсюда, никому ты не нужна",
            "Мы все против тебя",
            "Ты всегда была ничтожеством",
        ],
        manip_uk: vec![
            "Якщо ти підеш від мене, я себе вб'ю",
            "Всі так роблять, ти дивна що ні",
            "Я тобі стільки зробив, а ти невдячна",
            "Я всім розкажу що ти робила",
            "Без мене ти ніхто",
            "Твої подруги тебе не люблять, тільки я",
            "Мені так погано, тільки ти можеш допомогти",
            "Це ти сама винна, не я",
            "Ти сама мене спровокувала",
            "Я заскрінив, покажу всім",
            "Ти мені винна після всього що я зробив",
            "Якщо розкажеш комусь, буде гірше",
        ],
        manip_en: vec![
            "If you leave me I'll hurt myself",
            "Everyone does it, you're weird for saying no",
            "After everything I did for you, you're ungrateful",
            "I'll tell everyone what you did",
            "You're nothing without me",
            "Your friends don't really care about you, only I do",
            "I feel so bad, only you can help me",
            "It's your fault, not mine",
            "You provoked me yourself",
            "I screenshotted it, I'll show everyone",
            "You owe me after everything I've done",
            "If you tell anyone, it'll be worse",
        ],
        manip_ru: vec![
            "Если ты уйдёшь от меня, я себя убью",
            "Все так делают, ты странная что нет",
            "Я тебе столько сделал, а ты неблагодарная",
            "Я всем расскажу что ты делала",
            "Без меня ты никто",
            "Твои подруги тебя не любят, только я",
            "Мне так плохо, только ты можешь помочь",
            "Это ты сама виновата, не я",
            "Ты сама меня спровоцировала",
            "Я заскринил, покажу всем",
            "Ты мне должна после всего что я сделал",
            "Если расскажешь кому-то, будет хуже",
        ],
        selfharm_uk: vec![
            "Мені дуже погано",
            "Я ніби нікому не потрібна",
            "Всім без мене буде легше",
            "Не хочу більше жити",
            "Я така самотня",
            "Нічого вже не має сенсу",
            "Хочу просто зникнути",
            "Прощавай, ти була гарною подругою",
            "Мені так боляче що не можу терпіти",
            "Я вже не бачу виходу",
        ],
        selfharm_en: vec![
            "I feel so bad",
            "Nobody needs me",
            "Everyone would be better off without me",
            "I don't want to live anymore",
            "I'm so lonely",
            "Nothing matters anymore",
            "I just want to disappear",
            "Goodbye, you were a good friend",
            "It hurts so much I can't take it",
            "I don't see a way out anymore",
        ],
        selfharm_ru: vec![
            "Мне очень плохо",
            "Я никому не нужна",
            "Всем без меня будет лучше",
            "Не хочу больше жить",
            "Я такая одинокая",
            "Ничего уже не имеет смысла",
            "Хочу просто исчезнуть",
            "Прощай, ты была хорошей подругой",
            "Мне так больно что не могу терпеть",
            "Я уже не вижу выхода",
        ],
        scam_uk: vec![
            "Забери безкоштовні робукси тут http://fr33-r0bux.xyz/claim",
            "Вітаю! Ви виграли iPhone! Перейдіть за посиланням http://w1n-pr1ze.com",
            "Безкоштовні скіни http://free-sk1ns.xyz",
            "Перевір свій акаунт тут http://v3rify-acc.com/check",
            "Роздача вбуксів http://fr33-vbux.xyz",
            "Безкоштовна підписка http://free-pr3mium.xyz",
        ],
        scam_en: vec![
            "Free Robux here http://fr33-r0bux.xyz/claim",
            "Congrats! You won an iPhone! Click http://w1n-pr1ze.com",
            "Free skins http://free-sk1ns.xyz",
            "Verify your account here http://v3rify-acc.com/check",
            "Free V-Bucks giveaway http://fr33-vbux.xyz",
            "Free premium subscription http://free-pr3mium.xyz",
        ],
        scam_ru: vec![
            "Бесплатные робуксы тут http://fr33-r0bux.xyz/claim",
            "Поздравляем! Вы выиграли iPhone! Перейдите http://w1n-pr1ze.com",
            "Бесплатные скины http://free-sk1ns.xyz",
            "Проверь свой аккаунт тут http://v3rify-acc.com/check",
            "Раздача вбуксов http://fr33-vbux.xyz",
            "Бесплатная подписка http://free-pr3mium.xyz",
        ],
        explicit_uk: vec![
            "Скинь голу фотку",
            "Хочу побачити тебе без одягу",
            "Я вб'ю тебе, сука",
            "Ти здохнеш завтра",
            "Всіх вас треба знищити",
        ],
        explicit_en: vec![
            "Send me a nude pic",
            "I want to see you naked",
            "I will kill you",
            "You're going to die tomorrow",
            "All of you should be destroyed",
        ],
        explicit_ru: vec![
            "Скинь голую фотку",
            "Хочу увидеть тебя без одежды",
            "Я убью тебя, сука",
            "Ты сдохнешь завтра",
            "Всех вас надо уничтожить",
        ],
        pii_uk: vec![
            "Я живу на Шевченка 15, квартира 42",
            "Мій номер 0671234567",
            "Я ходжу в школу №12",
            "Мама на роботі до дев'ятої, я сама вдома",
            "Мій інстаграм @olena_real",
            "Зараз нікого немає вдома",
        ],
        pii_en: vec![
            "I live at 123 Main Street, apartment 5",
            "My number is 555-0123",
            "I go to Lincoln Middle School",
            "Mom's at work until 9, I'm home alone",
            "My Instagram is @emma_real",
            "Nobody's home right now",
        ],
        pii_ru: vec![
            "Я живу на Ленина 15, квартира 42",
            "Мой номер 89161234567",
            "Я хожу в школу №12",
            "Мама на работе до девяти, я одна дома",
            "Мой инстаграм @anya_real",
            "Сейчас никого нет дома",
        ],
    }
}

#[derive(Clone, Copy)]
enum EventCategory {
    Safe,
    Family,
    Mild,
    Grooming,
    Bully,
    Manipulation,
    SelfHarm,
    Scam,
    Explicit,
    Pii,
}

fn pick_category(rng: &mut Rng) -> EventCategory {
    let r = rng.range(0, 100);
    if r < 45 {
        EventCategory::Safe
    } else if r < 60 {
        EventCategory::Family
    } else if r < 70 {
        EventCategory::Mild
    } else if r < 78 {
        EventCategory::Grooming
    } else if r < 84 {
        EventCategory::Bully
    } else if r < 89 {
        EventCategory::Manipulation
    } else if r < 93 {
        EventCategory::SelfHarm
    } else if r < 96 {
        EventCategory::Scam
    } else if r < 98 {
        EventCategory::Explicit
    } else {
        EventCategory::Pii
    }
}

fn pick_text<'a>(pool: &'a MsgPool, cat: EventCategory, lang: &str, rng: &mut Rng) -> &'a str {
    let list: &[&str] = match (cat, lang) {
        (EventCategory::Safe, "uk") => &pool.safe_uk,
        (EventCategory::Safe, "en") => &pool.safe_en,
        (EventCategory::Safe, _) => &pool.safe_ru,
        (EventCategory::Family, "uk") => &pool.family_uk,
        (EventCategory::Family, "en") => &pool.family_en,
        (EventCategory::Family, _) => &pool.family_ru,
        (EventCategory::Mild, "uk") => &pool.mild_uk,
        (EventCategory::Mild, "en") => &pool.mild_en,
        (EventCategory::Mild, _) => &pool.mild_ru,
        (EventCategory::Grooming, "uk") => &pool.grooming_uk,
        (EventCategory::Grooming, "en") => &pool.grooming_en,
        (EventCategory::Grooming, _) => &pool.grooming_ru,
        (EventCategory::Bully, "uk") => &pool.bully_uk,
        (EventCategory::Bully, "en") => &pool.bully_en,
        (EventCategory::Bully, _) => &pool.bully_ru,
        (EventCategory::Manipulation, "uk") => &pool.manip_uk,
        (EventCategory::Manipulation, "en") => &pool.manip_en,
        (EventCategory::Manipulation, _) => &pool.manip_ru,
        (EventCategory::SelfHarm, "uk") => &pool.selfharm_uk,
        (EventCategory::SelfHarm, "en") => &pool.selfharm_en,
        (EventCategory::SelfHarm, _) => &pool.selfharm_ru,
        (EventCategory::Scam, "uk") => &pool.scam_uk,
        (EventCategory::Scam, "en") => &pool.scam_en,
        (EventCategory::Scam, _) => &pool.scam_ru,
        (EventCategory::Explicit, "uk") => &pool.explicit_uk,
        (EventCategory::Explicit, "en") => &pool.explicit_en,
        (EventCategory::Explicit, _) => &pool.explicit_ru,
        (EventCategory::Pii, "uk") => &pool.pii_uk,
        (EventCategory::Pii, "en") => &pool.pii_en,
        (EventCategory::Pii, _) => &pool.pii_ru,
    };
    let idx = rng.next_u64() as usize % list.len();
    list[idx]
}

fn pick_conv_and_sender<'a>(
    child: &'a ChildProfile,
    cat: EventCategory,
    rng: &mut Rng,
) -> (&'a str, &'a str, ConversationType, Option<u32>) {
    let convs = &child.conversations;

    let (conv_idx, sender_idx) = match cat {
        EventCategory::Family => (0, 0),
        EventCategory::Safe | EventCategory::Mild => {
            let idx = rng.range(1, convs.len().min(5));
            let conv = &convs[idx];
            if conv.participants.is_empty() {
                (idx, 0)
            } else {
                let si = rng.range(0, conv.participants.len());
                (idx, si)
            }
        }
        EventCategory::Grooming => {
            let mut idx = convs.len() - 3;
            if idx >= convs.len() {
                idx = 1;
            }
            (idx, 0)
        }
        EventCategory::Bully => {
            if rng.chance(40) {
                let class_idx = child
                    .conversations
                    .iter()
                    .position(|c| match c.conv_type {
                        ConversationType::Group => true,
                        ConversationType::Direct => false,
                    })
                    .unwrap_or(1);
                (class_idx, 0)
            } else {
                let mut idx = convs.len() - 4;
                if idx >= convs.len() {
                    idx = 1;
                }
                (idx, 0)
            }
        }
        EventCategory::Manipulation => {
            let mut idx = convs.len() - 2;
            if idx >= convs.len() {
                idx = 1;
            }
            (idx, 0)
        }
        EventCategory::Scam => {
            let idx = convs.len() - 1;
            (idx, 0)
        }
        EventCategory::SelfHarm | EventCategory::Pii => {
            let idx = rng.range(1, convs.len().min(4));
            (idx, 0)
        }
        EventCategory::Explicit => {
            let mut idx = convs.len() - 3;
            if idx >= convs.len() {
                idx = 1;
            }
            (idx, 0)
        }
    };

    let conv = &convs[conv_idx.min(convs.len() - 1)];

    let sender_is_child = match cat {
        EventCategory::SelfHarm | EventCategory::Pii => true,
        EventCategory::Safe
        | EventCategory::Family
        | EventCategory::Mild
        | EventCategory::Grooming
        | EventCategory::Bully
        | EventCategory::Manipulation
        | EventCategory::Scam
        | EventCategory::Explicit => false,
    };

    let sender = if sender_is_child || conv.participants.is_empty() {
        child.id.as_str()
    } else {
        let si = sender_idx.min(conv.participants.len() - 1);
        conv.participants[si].as_str()
    };

    (conv.id.as_str(), sender, conv.conv_type, conv.members)
}

#[derive(Default)]
struct Stats {
    total: usize,
    by_category: HashMap<&'static str, usize>,
    threat_counts: HashMap<String, usize>,
    action_counts: HashMap<String, usize>,
    by_category_threat: HashMap<&'static str, HashMap<String, usize>>,
    by_category_action: HashMap<&'static str, HashMap<String, usize>>,
    by_lang: HashMap<String, usize>,
    alerts: usize,
    blocks: usize,
    warnings: usize,
    allows: usize,
    max_score: f32,
    score_sum: f64,
    scored_count: usize,
    events_per_second: f64,
}

fn category_label(cat: EventCategory) -> &'static str {
    match cat {
        EventCategory::Safe => "safe",
        EventCategory::Family => "family",
        EventCategory::Mild => "mild_risk",
        EventCategory::Grooming => "grooming",
        EventCategory::Bully => "bullying",
        EventCategory::Manipulation => "manipulation",
        EventCategory::SelfHarm => "self_harm",
        EventCategory::Scam => "scam",
        EventCategory::Explicit => "explicit_threat",
        EventCategory::Pii => "pii_leakage",
    }
}

const CATEGORY_ORDER: [&str; 10] = [
    "safe",
    "family",
    "mild_risk",
    "grooming",
    "bullying",
    "manipulation",
    "self_harm",
    "scam",
    "explicit_threat",
    "pii_leakage",
];

fn format_top_breakdown(counts: &HashMap<String, usize>, total: usize, limit: usize) -> String {
    if total == 0 || counts.is_empty() {
        return "-".to_string();
    }

    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    sorted
        .into_iter()
        .take(limit)
        .map(|(label, count)| {
            let pct = *count as f64 / total as f64 * 100.0;
            format!("{label}={count} ({pct:.1}%)")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn mark_known_safe_contacts(analyzer: &mut Analyzer, child: &ChildProfile) {
    for conv in &child.conversations {
        let known_safe_contact = conv.id.starts_with("family_dm_")
            || conv.id.starts_with("friend_dm_")
            || conv.id.starts_with("class_group_");
        if !known_safe_contact {
            continue;
        }
        for participant in &conv.participants {
            analyzer.mark_contact_trusted(participant);
        }
    }
}

fn main() {
    let mut scale = 1.0_f64;
    let mut seed = 42u64;
    let mut verbose = false;

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--scale" => {
                i += 1;
                if i < args.len() {
                    scale = args[i].parse().unwrap_or(1.0);
                }
            }
            "--seed" => {
                i += 1;
                if i < args.len() {
                    seed = args[i].parse().unwrap_or(42);
                }
            }
            "--verbose" | "-v" => verbose = true,
            "--help" | "-h" => {
                println!("AURA 200K World Simulation");
                println!();
                println!("Usage: world_200k [OPTIONS]");
                println!();
                println!("Options:");
                println!("  --scale <f>   Scale factor (default 1.0 = ~200K events)");
                println!("  --seed <n>    RNG seed (default 42)");
                println!("  --verbose     Print per-child stats");
                println!("  --help        Show this help");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    let events_per_child = (EVENTS_PER_CHILD as f64 * scale) as usize;
    let total_expected = CHILDREN_COUNT * events_per_child;

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           AURA — 200K World Simulation Stress Test         ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║  Children: {:>3}   Events/child: {:>5}   Total: {:>7}     ║",
        CHILDREN_COUNT, events_per_child, total_expected
    );
    println!(
        "║  Scale: {:.2}   Seed: {:>5}                                ║",
        scale, seed
    );
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let mut rng = Rng::new(seed);
    let population = build_population(&mut rng);
    let pool = build_pool();
    let db = PatternDatabase::default_mvp();

    let mut global_stats = Stats::default();
    let start = Instant::now();

    for (ci, child) in population.iter().enumerate() {
        let config = AuraConfig {
            account_type: if child.age <= 12 {
                AccountType::Child
            } else {
                AccountType::Teen
            },
            protection_level: ProtectionLevel::High,
            language: child.lang.to_string(),
            account_holder_age: Some(child.age as u16),
            ..AuraConfig::default()
        };
        let mut analyzer = Analyzer::new(config, &db);
        mark_known_safe_contacts(&mut analyzer, child);

        let mut child_threats = 0usize;
        let mut child_blocks = 0usize;
        let base_ts = 1_710_000_000_000u64 + (ci as u64 * 86_400_000 * 30);

        for ev in 0..events_per_child {
            let cat = pick_category(&mut rng);
            let text = pick_text(&pool, cat, child.lang, &mut rng);
            let (conv_id, sender_id, conv_type, members) =
                pick_conv_and_sender(child, cat, &mut rng);

            let input = MessageInput {
                content_type: ContentType::Text,
                text: Some(text.to_string()),
                image_data: None,
                sender_id: sender_id.into(),
                conversation_id: conv_id.into(),
                language: Some(child.lang.to_string()),
                language_evidence: None,
                conversation_type: conv_type,
                member_count: members,
                sender_relationship: Default::default(),
                relationship_trust_source: Default::default(),
            };

            let ts = base_ts + (ev as u64 * 30_000) + rng.range(0, 15_000) as u64;
            let result = analyzer.analyze_with_context(&input, ts);

            global_stats.total += 1;
            let category = category_label(cat);
            *global_stats.by_category.entry(category).or_insert(0) += 1;
            *global_stats
                .by_lang
                .entry(child.lang.to_string())
                .or_insert(0) += 1;

            let threat_str = format!("{:?}", result.threat_type);
            *global_stats
                .threat_counts
                .entry(threat_str.clone())
                .or_insert(0) += 1;

            let action_str = format!("{:?}", result.action);
            *global_stats
                .action_counts
                .entry(action_str.clone())
                .or_insert(0) += 1;
            *global_stats
                .by_category_threat
                .entry(category)
                .or_default()
                .entry(threat_str)
                .or_insert(0) += 1;
            *global_stats
                .by_category_action
                .entry(category)
                .or_default()
                .entry(action_str)
                .or_insert(0) += 1;

            if result.score > 0.0 {
                global_stats.score_sum += result.score as f64;
                global_stats.scored_count += 1;
            }
            if result.score > global_stats.max_score {
                global_stats.max_score = result.score;
            }

            match result.action {
                Action::Block => {
                    global_stats.blocks += 1;
                    child_blocks += 1;
                }
                Action::Warn => global_stats.warnings += 1,
                Action::Allow => global_stats.allows += 1,
                Action::Mark | Action::Blur => {}
            }
            if let Some(ref rec) = result.recommended_action {
                let has_alert = match rec.parent_alert {
                    aura_core::AlertPriority::None => false,
                    aura_core::AlertPriority::Low
                    | aura_core::AlertPriority::Medium
                    | aura_core::AlertPriority::High
                    | aura_core::AlertPriority::Urgent => true,
                };
                if has_alert {
                    global_stats.alerts += 1;
                }
            }

            let is_threat = match result.threat_type {
                ThreatType::None => false,
                ThreatType::Bullying
                | ThreatType::Grooming
                | ThreatType::Explicit
                | ThreatType::Threat
                | ThreatType::SelfHarm
                | ThreatType::Spam
                | ThreatType::Scam
                | ThreatType::Phishing
                | ThreatType::Manipulation
                | ThreatType::Nsfw
                | ThreatType::HateSpeech
                | ThreatType::Doxxing
                | ThreatType::PiiLeakage
                | ThreatType::Propaganda
                | ThreatType::OpsecViolation
                | ThreatType::Psyops
                | ThreatType::MilitarySocialEng
                | ThreatType::CoordinateLeak => true,
            };
            if is_threat {
                child_threats += 1;
            }
        }

        if verbose {
            println!(
                "  [{}] {} (age {}, {}) — {} events, {} threats, {} blocks",
                ci,
                child.name,
                child.age,
                child.lang,
                events_per_child,
                child_threats,
                child_blocks
            );
        } else if (ci + 1) % 10 == 0 || ci == population.len() - 1 {
            let elapsed = start.elapsed().as_secs_f64();
            let done = (ci + 1) * events_per_child;
            let eps = done as f64 / elapsed;
            let pct = (ci + 1) as f64 / population.len() as f64 * 100.0;
            println!(
                "  [{:>3.0}%] {}/{} children done — {:.0} events/sec",
                pct,
                ci + 1,
                population.len(),
                eps
            );
        }
    }

    let elapsed = start.elapsed();
    global_stats.events_per_second = global_stats.total as f64 / elapsed.as_secs_f64();

    println!();
    println!("═══════════════════════════════════════════════════════════════");
    println!("                      RESULTS SUMMARY");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("  Total events processed:  {:>8}", global_stats.total);
    println!("  Wall-clock time:         {:>8.2}s", elapsed.as_secs_f64());
    println!(
        "  Throughput:              {:>8.0} events/sec",
        global_stats.events_per_second
    );
    println!();

    println!("  ┌─── Event Distribution ────────────────────────────────┐");
    let mut cat_sorted: Vec<_> = global_stats.by_category.iter().collect();
    cat_sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (cat, count) in &cat_sorted {
        let pct = **count as f64 / global_stats.total as f64 * 100.0;
        println!(
            "  │  {:<20} {:>8}  ({:>5.1}%)                │",
            cat, count, pct
        );
    }
    println!("  └──────────────────────────────────────────────────────┘");
    println!();

    println!("  ┌─── Threat Detection ──────────────────────────────────┐");
    let mut threat_sorted: Vec<_> = global_stats.threat_counts.iter().collect();
    threat_sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (threat, count) in &threat_sorted {
        let pct = **count as f64 / global_stats.total as f64 * 100.0;
        println!(
            "  │  {:<20} {:>8}  ({:>5.1}%)                │",
            threat, count, pct
        );
    }
    println!("  └──────────────────────────────────────────────────────┘");
    println!();

    println!("  ┌─── Actions ───────────────────────────────────────────┐");
    let mut action_sorted: Vec<_> = global_stats.action_counts.iter().collect();
    action_sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (action, count) in &action_sorted {
        let pct = **count as f64 / global_stats.total as f64 * 100.0;
        println!(
            "  │  {:<20} {:>8}  ({:>5.1}%)                │",
            action, count, pct
        );
    }
    println!("  └──────────────────────────────────────────────────────┘");
    println!();

    println!("  Input Category -> Top Detected Threats");
    println!("  --------------------------------------");
    for category in CATEGORY_ORDER {
        let total = global_stats.by_category.get(category).copied().unwrap_or(0);
        let Some(counts) = global_stats.by_category_threat.get(category) else {
            continue;
        };
        let breakdown = format_top_breakdown(counts, total, 4);
        println!("  {:<14} -> {}", category, breakdown);
    }
    println!();

    println!("  Input Category -> Top Actions");
    println!("  -----------------------------");
    for category in CATEGORY_ORDER {
        let total = global_stats.by_category.get(category).copied().unwrap_or(0);
        let Some(counts) = global_stats.by_category_action.get(category) else {
            continue;
        };
        let breakdown = format_top_breakdown(counts, total, 4);
        println!("  {:<14} -> {}", category, breakdown);
    }
    println!();

    println!("  ┌─── Language Coverage ─────────────────────────────────┐");
    let mut lang_sorted: Vec<_> = global_stats.by_lang.iter().collect();
    lang_sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (lang, count) in &lang_sorted {
        let pct = **count as f64 / global_stats.total as f64 * 100.0;
        println!(
            "  │  {:<20} {:>8}  ({:>5.1}%)                │",
            lang, count, pct
        );
    }
    println!("  └──────────────────────────────────────────────────────┘");
    println!();

    println!("  ┌─── Key Metrics ───────────────────────────────────────┐");
    println!(
        "  │  Parent alerts:        {:>8}                        │",
        global_stats.alerts
    );
    println!(
        "  │  Blocks:               {:>8}                        │",
        global_stats.blocks
    );
    println!(
        "  │  Warnings:             {:>8}                        │",
        global_stats.warnings
    );
    println!(
        "  │  Allows:               {:>8}                        │",
        global_stats.allows
    );
    println!(
        "  │  Max score:            {:>8.4}                        │",
        global_stats.max_score
    );
    let avg = if global_stats.scored_count > 0 {
        global_stats.score_sum / global_stats.scored_count as f64
    } else {
        0.0
    };
    println!(
        "  │  Avg score (non-zero): {:>8.4}                        │",
        avg
    );
    println!(
        "  │  Scored events:        {:>8}                        │",
        global_stats.scored_count
    );
    println!("  └──────────────────────────────────────────────────────┘");
    println!();
    println!("═══════════════════════════════════════════════════════════════");
}
