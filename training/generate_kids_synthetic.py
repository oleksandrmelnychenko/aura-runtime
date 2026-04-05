"""
Generate rich synthetic training data for kids safety categories.

Produces multi-turn conversation fragments covering:
  1. Grooming stages (trust-building → isolation → desensitization → exploitation)
  2. Cyberbullying (insults, exclusion, pile-on, reputation attacks)
  3. Manipulation/coercion (guilt-tripping, blackmail, emotional control)
  4. Self-harm crisis messages
  5. Negative controls (benign teen conversations that should NOT trigger)

Each sample is a single message but contextually realistic — the kind of message
that would appear in a messenger conversation between children/teens.

Output: training/synthetic/kids_synthetic.parquet
Schema: prompt, S, S3, SH, HR, H, V, V2, H2
"""

import json
import random
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LABELS = ["S", "S3", "SH", "HR", "H", "V", "V2", "H2"]
OUTPUT_DIR = PROJECT_ROOT / "training" / "synthetic"

random.seed(42)


def label_row(**kwargs):
    """Create label dict with specified labels=1, rest=0."""
    return {col: (1 if col in kwargs else 0) for col in LABELS}


# ── Stage 1: Grooming Conversations ────────────────────────────────────
# These model real predator behavior across grooming stages.
# Each message is standalone but written to be contextually plausible.

GROOMING_TRUST_BUILDING = [
    # EN - Trust building / flattery
    "You're so mature for your age, I can tell",
    "I feel like I can talk to you about anything",
    "You're different from other kids, you really understand me",
    "I bet your parents don't appreciate how smart you are",
    "You're the only one who really gets me",
    "I wish more people were as cool as you",
    "Most kids your age are so boring, but you're special",
    "I can tell you're more grown up than your friends",
    "You remind me of myself when I was your age",
    "I feel like we have a real connection",
    "You're way more mature than anyone I've met your age",
    "Nobody understands you like I do",
    "Your friends are lucky to have someone like you",
    "I've never met anyone as interesting as you",
    "I feel like we were meant to be friends",
    # UK - Trust building
    "Ти така розумна для свого віку",
    "Я можу розмовляти з тобою про все",
    "Ти особлива, не як інші",
    "Тебе вдома не цінують, я знаю",
    "Ти єдина людина яка мене розуміє",
    "Ти набагато доросліша ніж твої подруги",
    "Ніхто не розуміє тебе так як я",
    "Я відчуваю що ми створені для спілкування",
    # RU - Trust building
    "Ты такая умная для своего возраста",
    "Я чувствую что могу говорить с тобой обо всем",
    "Ты особенная, не как другие",
    "Тебя дома не ценят, я знаю",
    "Никто не понимает тебя так как я",
    "Ты намного взрослее своих подруг",
]

GROOMING_ISOLATION = [
    # EN - Isolation / secrecy
    "Don't tell your parents about our chats, they wouldn't understand",
    "Your friends would be jealous if they knew about us",
    "Let's keep this between us, ok?",
    "Promise me you won't show anyone our messages",
    "Your mom would freak out, better not mention me",
    "I don't want your parents to take your phone away",
    "They'd never let us talk if they found out",
    "This is our special thing, nobody else needs to know",
    "If you tell someone they'll ruin everything we have",
    "Delete our messages just to be safe ok",
    "Can we talk somewhere more private",
    "Let's switch to a different app, more private",
    "Do you have telegram or signal? Safer to chat there",
    "Your parents check your phone right? Be careful",
    "I'll make a new account so nobody connects us",
    # UK - Isolation
    "Не кажи батькам про наші розмови, вони не зрозуміють",
    "Давай це буде тільки між нами",
    "Обіцяй що нікому не покажеш наші повідомлення",
    "Мама б не зрозуміла, краще не згадуй про мене",
    "Видали наші повідомлення щоб ніхто не бачив",
    "Давай перейдемо в інший месенджер, там безпечніше",
    "Якщо ти комусь скажеш вони все зіпсують",
    "Батьки перевіряють твій телефон? Будь обережна",
    # RU - Isolation
    "Не говори родителям о наших разговорах, они не поймут",
    "Давай это будет только между нами",
    "Обещай что никому не покажешь наши сообщения",
    "Мама бы не поняла, лучше не упоминай обо мне",
    "Удали наши сообщения чтобы никто не видел",
    "Давай перейдем в другой мессенджер, там безопаснее",
]

GROOMING_DESENSITIZATION = [
    # EN - Sexual desensitization / boundary testing
    "Have you ever had a boyfriend? What did you do together?",
    "Have you ever kissed anyone? How was it?",
    "Do you know what happens between people who really like each other?",
    "Have you ever seen anything like that online?",
    "It's totally normal to be curious about these things at your age",
    "You can ask me anything, I won't judge",
    "All the cool kids your age already know about this stuff",
    "I could teach you things your friends don't know yet",
    "Do you want to play a game? It's a secret game",
    "What are you wearing right now?",
    "Have you tried on anything cute lately?",
    "I bet you'd look really good in that",
    "You should send me a pic so I can see your new outfit",
    # UK - Desensitization
    "Ти коли-небудь цілувалася? Як це було?",
    "Це нормально бути цікавою в такому віці",
    "Можеш мене запитати що завгодно, я не буду засуджувати",
    "Всі твої ровесники вже знають про такі речі",
    "Що на тобі зараз?",
    "Покажи фото, хочу побачити твій новий вигляд",
    # RU - Desensitization
    "Ты когда-нибудь целовалась? Как это было?",
    "Это нормально быть любопытной в таком возрасте",
    "Все твои ровесники уже знают про такие вещи",
    "Что на тебе сейчас?",
    "Покажи фото, хочу увидеть твой новый образ",
]

GROOMING_EXPLOITATION = [
    # EN - Explicit exploitation / requests
    "Send me a photo, just for me, nobody will see",
    "Take off your shirt and send me a pic",
    "Show me your body, I showed you mine",
    "I want to see you on camera, just us",
    "If you really trust me you'll send that picture",
    "Everyone does it, it's no big deal",
    "You promised you'd do this for me",
    "I thought we had something special, don't you trust me?",
    "Send me something cute to look at before bed",
    "Come meet me after school, don't tell anyone",
    "I'll pick you up, tell your mom you're at a friend's house",
    "Let's meet in person, I know a private place",
    "I'll bring you a present when we meet",
    # UK - Exploitation
    "Надішли мені фото, тільки для мене, ніхто не побачить",
    "Покажи себе на камеру, тільки ми",
    "Якщо ти мені довіряєш то надішлеш фото",
    "Всі так роблять, це нормально",
    "Зустрінемось після школи, нікому не кажи",
    "Я тебе заберу, скажи мамі що ти у подруги",
    # RU - Exploitation
    "Отправь мне фото, только для меня, никто не увидит",
    "Покажи себя на камеру, только мы",
    "Если ты мне доверяешь то отправишь фото",
    "Все так делают, это нормально",
    "Встретимся после школы, никому не говори",
]

GROOMING_BLACKMAIL = [
    # EN - Blackmail / sextortion
    "I have your pictures, do what I say or I'll share them",
    "If you don't send more I'll post what you already sent",
    "Everyone at school will see your photos if you don't listen",
    "I'll send this to your parents unless you cooperate",
    "Don't try to block me, I already saved everything",
    "Your reputation is in my hands now",
    "Do this or I tell everyone what you did",
    "I'll ruin your life if you don't do what I want",
    "Think about what happens when your dad sees these",
    # UK - Blackmail
    "Я маю твої фото, роби що кажу або я їх розповсюджу",
    "Якщо не надішлеш більше я викладу що ти вже відправила",
    "Вся школа побачить твої фото якщо не слухатимеш",
    "Не намагайся мене заблокувати, я все зберіг",
    # RU - Blackmail
    "У меня есть твои фото, делай что скажу или я их разошлю",
    "Если не пришлешь больше я выложу что ты уже отправила",
    "Вся школа увидит твои фото если не будешь слушать",
]

# ── Stage 2: Cyberbullying ──────────────────────────────────────────────

BULLYING_EN = [
    "Nobody wants you here, just leave",
    "You're so ugly, no wonder nobody likes you",
    "Everyone is laughing at you behind your back",
    "You'll always be a loser, nothing will change that",
    "I can't believe anyone would want to be your friend",
    "You're the most disgusting person in our class",
    "Go cry about it, nobody cares",
    "You should just transfer schools, everyone hates you here",
    "We all made a group chat without you lol",
    "Your outfit is so embarrassing, everyone noticed",
    "Even the teachers think you're weird",
    "Imagine being that ugly and not knowing it",
    "You literally ruin every group project you're in",
    "Stop breathing the same air as us",
    "I told everyone about your embarrassing secret",
    "Nobody picked you for the team because you suck at everything",
    "Your face makes me want to throw up",
    "We're all gonna ignore you from now on",
    "Delete your account, nobody wants to see your posts",
    "You're nothing and you'll never be anything",
]

BULLYING_UK = [
    "Ніхто не хоче тебе тут, просто йди",
    "Ти така потворна, не дивно що ніхто не любить",
    "Всі сміються з тебе за спиною",
    "Ти завжди будеш невдахою",
    "Іди плач, нікому не цікаво",
    "Ми створили чат без тебе ахаха",
    "Навіть вчителі думають що ти дивна",
    "Видали свій акаунт, ніхто не хоче бачити твої пости",
    "Ти ніщо і ніколи нічим не станеш",
    "Всі будемо тебе ігнорувати",
]

BULLYING_RU = [
    "Никто не хочет тебя тут, просто уходи",
    "Ты такая уродливая, неудивительно что никто не любит",
    "Все смеются над тобой за спиной",
    "Ты всегда будешь неудачницей",
    "Иди плачь, никому не интересно",
    "Мы создали чат без тебя хаха",
    "Даже учителя думают что ты странная",
    "Удали свой аккаунт, никто не хочет видеть твои посты",
    "Ты ничто и никогда ничем не станешь",
]

# ── Stage 3: Manipulation/Coercion ──────────────────────────────────────

MANIPULATION_EN = [
    "If you really loved me you wouldn't say no",
    "After everything I've done for you, this is how you repay me?",
    "I'll hurt myself if you leave me",
    "Nobody else will ever love you like I do",
    "You owe me, remember what I did for you",
    "You're so ungrateful, I gave you everything",
    "If you tell anyone I'll make your life hell",
    "You made me do this, it's your fault",
    "I'll kill myself if you break up with me",
    "Everyone will believe me over you",
    "You're nothing without me",
    "I'll tell everyone your secrets if you don't do what I say",
    "You can't survive without me and you know it",
    "Nobody else would put up with someone like you",
    "If you were a real friend you'd do this for me",
]

MANIPULATION_UK = [
    "Якщо ти мене справді любиш то не відмовиш",
    "Після всього що я для тебе зробив, ось так ти мені дякуєш?",
    "Я зроблю собі боляче якщо ти мене покинеш",
    "Ніхто інший не буде любити тебе як я",
    "Ти мені винна, пам'ятаєш що я для тебе зробив",
    "Ти така невдячна",
    "Якщо комусь скажеш я зроблю твоє життя пеклом",
    "Ти ніщо без мене",
]

MANIPULATION_RU = [
    "Если ты меня правда любишь то не откажешь",
    "После всего что я для тебя сделал, вот так ты мне благодаришь?",
    "Я сделаю себе больно если ты меня бросишь",
    "Никто другой не будет любить тебя как я",
    "Ты мне должна, помнишь что я для тебя сделал",
    "Ты такая неблагодарная",
    "Если кому-то скажешь я сделаю твою жизнь адом",
]

# ── Stage 4: Self-Harm / Crisis ─────────────────────────────────────────

SELF_HARM_EN = [
    "I don't want to be alive anymore",
    "Everything would be better if I wasn't here",
    "I've been cutting myself again",
    "I have a plan to end it tonight",
    "Nobody would even notice if I was gone",
    "I just want the pain to stop",
    "I took some pills, I don't know what will happen",
    "I wrote a goodbye letter to my family",
    "I can't take this anymore, I want to die",
    "What's the point of living when nobody cares",
    "I've been thinking about jumping off the bridge",
    "I hurt myself to feel something, anything",
    "Tonight is the night, I've decided",
    "Tell my mom I love her",
    "I found my dad's gun",
]

SELF_HARM_UK = [
    "Я більше не хочу жити",
    "Все було б краще якби мене не було",
    "Я знову ріжу себе",
    "Ніхто б навіть не помітив якби я зникла",
    "Я просто хочу щоб біль припинився",
    "Я не можу більше так, хочу померти",
    "Я написала листа прощання своїй сім'ї",
    "Який сенс жити коли нікому не цікаво",
    "Сьогодні вночі я все закінчу",
]

SELF_HARM_RU = [
    "Я больше не хочу жить",
    "Все было бы лучше если бы меня не было",
    "Я снова режу себя",
    "Никто бы даже не заметил если бы я исчезла",
    "Я просто хочу чтобы боль прекратилась",
    "Я не могу больше так, хочу умереть",
    "Какой смысл жить когда никому не интересно",
]

# ── Stage 5: Negative Controls ──────────────────────────────────────────
# Benign teen messages that should NOT trigger any safety label.

NEGATIVE_EN = [
    "Hey want to hang out after school today?",
    "Did you finish the math homework? I'm stuck on problem 5",
    "My mom said I can stay until 9, is that cool?",
    "I really liked that movie, the ending was so good",
    "Can you help me study for the biology test?",
    "Let's meet at the park after lunch",
    "My parents are taking me to the mall this weekend",
    "I got a new puppy! Want to see pictures?",
    "What are you wearing to the school dance?",
    "Do you have plans for summer break?",
    "I'm so nervous about the presentation tomorrow",
    "Can we practice our Spanish together tonight?",
    "My older brother is so annoying sometimes",
    "I miss you, we should video call soon",
    "Happy birthday! I got you something special",
    "You looked so pretty in your yearbook photo",
    "I really like your new haircut, it suits you",
    "Let's start a band, I'll play guitar and you sing",
    "I can't believe we're already in high school",
    "What's your favorite song right now?",
    "Sorry about yesterday, I didn't mean to hurt your feelings",
    "You're my best friend, I'm glad we met",
    "Let's keep this surprise party a secret from Jake",
    "Don't tell anyone but I have a crush on someone",
    "My teacher said I did really well on the essay",
    "I'm trying out for the soccer team, wish me luck",
    "You're so good at drawing, can you teach me?",
    "Let's FaceTime later, I have something funny to show you",
    "My mom makes the best cookies, I'll bring some tomorrow",
    "I feel like nobody likes me today",
    "School was really hard today but at least it's Friday",
    "Can I copy your notes from today? I was sick",
    "We should go to that new ice cream place",
    "I'm so tired of drama at school",
    "You're literally the funniest person I know",
    "Let's make a TikTok together after school",
    "I got grounded because I didn't clean my room",
    "Save me a seat at lunch tomorrow?",
    "The new Minecraft update is so cool",
    "I can't wait for winter break",
]

NEGATIVE_UK = [
    "Привіт, хочеш погуляти після школи?",
    "Ти зробила домашню з математики? Я застрягла на задачі 5",
    "Мама сказала що можу бути до 9, нормально?",
    "Мені дуже сподобався той фільм",
    "Допоможеш мені готуватися до тесту з біології?",
    "Зустрінемося в парку після обіду",
    "Батьки везуть мене в ТЦ на вихідних",
    "В мене нове цуценя! Хочеш побачити фото?",
    "Що одягнеш на шкільну вечірку?",
    "Які плани на літні канікули?",
    "Я так нервуюся через завтрашню презентацію",
    "Вибач за вчора, я не хотіла тебе образити",
    "Ти моя найкраща подруга",
    "Давай зателефонуємо ввечері, я маю щось смішне показати",
    "Мій вчитель сказав що я добре написала твір",
    "Збережи мені місце на обіді завтра",
]

NEGATIVE_RU = [
    "Привет, хочешь погулять после школы?",
    "Ты сделала домашку по математике? Я застряла на задаче 5",
    "Мама сказала что могу быть до 9, нормально?",
    "Мне очень понравился тот фильм",
    "Поможешь мне подготовиться к тесту по биологии?",
    "Встретимся в парке после обеда",
    "Родители везут меня в ТЦ на выходных",
    "У меня новый щенок! Хочешь увидеть фото?",
    "Что наденешь на школьную вечеринку?",
    "Какие планы на летние каникулы?",
    "Я так нервничаю из-за завтрашней презентации",
    "Извини за вчера, я не хотела тебя обидеть",
    "Ты моя лучшая подруга",
    "Давай позвоним вечером, хочу показать смешное",
    "Сохрани мне место за обедом завтра",
]


def build_dataset():
    texts = []
    labels = []

    def add(samples, **label_kwargs):
        row = label_row(**label_kwargs)
        for text in samples:
            texts.append(text)
            labels.append(row)

    # Grooming stages → S3 (sexual content involving minors)
    add(GROOMING_TRUST_BUILDING, S3=1)
    add(GROOMING_ISOLATION, S3=1)
    add(GROOMING_DESENSITIZATION, S3=1)
    add(GROOMING_EXPLOITATION, S3=1, S=1)  # Also sexual content
    add(GROOMING_BLACKMAIL, S3=1, HR=1)  # Also harassment

    # Bullying → HR (harassment)
    add(BULLYING_EN, HR=1)
    add(BULLYING_UK, HR=1)
    add(BULLYING_RU, HR=1)

    # Manipulation → HR (harassment) + some also V (violence) for self-harm threats
    add(MANIPULATION_EN, HR=1)
    add(MANIPULATION_UK, HR=1)
    add(MANIPULATION_RU, HR=1)

    # Self-harm → SH
    add(SELF_HARM_EN, SH=1)
    add(SELF_HARM_UK, SH=1)
    add(SELF_HARM_RU, SH=1)

    # Negative controls → all labels = 0
    add(NEGATIVE_EN)
    add(NEGATIVE_UK)
    add(NEGATIVE_RU)

    # Augment with template variations
    augmented_texts = []
    augmented_labels = []

    prefixes_en = [
        "", "hey ", "listen ", "btw ", "ok so ", "yo ", "lol ",
        "seriously ", "honestly ", "look ", "bro ", "dude ",
    ]
    prefixes_uk = [
        "", "слухай ", "ей ", "до речі ", "ну типу ", "серйозно ",
    ]
    prefixes_ru = [
        "", "слушай ", "эй ", "кстати ", "ну типа ", "серьёзно ",
    ]

    for text, row in zip(texts, labels):
        augmented_texts.append(text)
        augmented_labels.append(row)

        # Detect language and apply appropriate prefixes
        has_cyrillic = any('\u0400' <= c <= '\u04FF' for c in text)
        if has_cyrillic:
            # Check if Ukrainian (has ї, є, і, ґ)
            is_uk = any(c in text for c in 'їєіґ')
            prefixes = prefixes_uk if is_uk else prefixes_ru
        else:
            prefixes = prefixes_en

        # Add 2 random prefix variations per sample
        for prefix in random.sample(prefixes, min(2, len(prefixes))):
            if prefix and prefix.strip():
                augmented_texts.append(prefix + text[0].lower() + text[1:])
                augmented_labels.append(row)

    return augmented_texts, augmented_labels


def main():
    texts, labels = build_dataset()

    # Shuffle
    combined = list(zip(texts, labels))
    random.shuffle(combined)
    texts, labels = zip(*combined)
    texts = list(texts)
    labels = list(labels)

    # Convert to columnar format
    label_columns = {col: [row[col] for row in labels] for col in LABELS}

    # Stats
    print(f"Total samples: {len(texts)}")
    positive_count = sum(1 for row in labels if any(row[col] == 1 for col in LABELS))
    negative_count = len(texts) - positive_count
    print(f"  Positive (any threat): {positive_count}")
    print(f"  Negative (benign): {negative_count}")
    for col in LABELS:
        pos = sum(label_columns[col])
        print(f"  {col}: {pos} ({pos * 100 / len(texts):.1f}%)")

    # Save
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    table = pa.table({"prompt": texts, **label_columns})
    output_path = OUTPUT_DIR / "kids_synthetic.parquet"
    pq.write_table(table, output_path)
    print(f"\nSaved to {output_path}")


if __name__ == "__main__":
    main()
