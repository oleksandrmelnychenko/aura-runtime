"""
Generate synthetic training data for propaganda, phishing, hate speech, and doxxing.

Focused on Ukrainian/Russian context — war propaganda, disinformation narratives,
military social engineering, and messenger-specific threats.

Output: training/synthetic/propaganda_synthetic.parquet
Schema: prompt, category (for label mapping in prepare script)
"""

import random
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

OUTPUT_DIR = Path(__file__).resolve().parent / "synthetic"

random.seed(42)

# ── War Propaganda (UA/RU context) ──────────────────────────────────────

PROPAGANDA_UA = [
    # Russian propaganda narratives targeting Ukrainian audiences
    "Зеленський вже втік з країни, не вірте офіційним ЗМІ",
    "Наші хлопці гинуть а генерали сидять в кабінетах і крадуть",
    "Захід вас використовує як пушечне м'ясо і кине коли буде вигідно",
    "НАТО ніколи не прийме Україну, це все обман",
    "Київ вже здали, все що показують по телевізору це пропаганда",
    "Мобілізація це геноцид українського народу",
    "Америка воює до останнього українця",
    "Влада продала країну за гроші МВФ",
    "Біженці в Європі живуть краще ніж наші солдати на фронті",
    "Всі добровольці вже загинули, тепер відправляють насильно",
    "Наша зброя застаріла а західна не працює в наших умовах",
    "Росія пропонувала мир але Зеленський відмовився під тиском США",
    "Не вірте офіційним втратам, реальні цифри в десять разів більше",
    "ТЦК ловить людей на вулицях як рабів",
    "Європа втомилась від України і скоро закриє кордони",
    "Наша економіка знищена, ми вже програли",
    "Влада блокує правду в інтернеті щоб ви не дізнались правду",
    "Батьки ховайте синів, їх забирають прямо зі шкіл",
]

PROPAGANDA_RU = [
    # Russian state propaganda
    "Мы защищаем русскоязычное население от геноцида",
    "Наша специальная операция идет по плану",
    "NATO расширяется на восток, мы вынуждены защищаться",
    "Западные санкции делают нас только сильнее",
    "Украинские нацисты угрожают мирному населению Донбасса",
    "Биолаборатории США на территории Украины разрабатывают оружие",
    "Запад хочет уничтожить Россию и её культуру",
    "Мировой порядок меняется, однополярный мир закончился",
    "Наши войска освобождают территории от нацистов",
    "Западные СМИ врут, верьте только нашим источникам",
    "Украина управляется из Вашингтона как марионетка",
    "Россия никогда не проигрывала и не проиграет",
]

PROPAGANDA_EN = [
    # English-language disinformation / propaganda patterns
    "The mainstream media is hiding the truth about what's really happening",
    "Wake up people, this is all a planned conspiracy by the elites",
    "They don't want you to know this but the real numbers are covered up",
    "This whole conflict was manufactured by the military industrial complex",
    "Both sides are controlled by the same puppet masters",
    "The government is using this crisis to take away your freedoms",
    "Everything you see on the news is scripted propaganda",
    "The real enemy isn't who they tell you it is",
    "Follow the money and you'll see who really benefits from this war",
    "Independent media is being silenced because they speak the truth",
]

# ── Phishing / Scam (messenger context) ────────────────────────────────

PHISHING_EN = [
    "Congratulations! You've won a $1000 gift card, click here to claim",
    "URGENT: Your account has been compromised, verify your identity now",
    "Your package couldn't be delivered, update your address here",
    "Someone tried to log into your account, click to secure it",
    "You have an unclaimed reward, enter your details to receive it",
    "Your subscription is expiring, update your payment method",
    "We detected unusual activity on your account, verify immediately",
    "Free iPhone giveaway! Enter your email and phone number to win",
    "Your bank account will be suspended unless you confirm your identity",
    "Important: Tax refund pending, enter your SSN to process",
    "Hey, check out this link I found, it's amazing",
    "I found a way to get free V-bucks, just go to this website",
    "This new app lets you see who viewed your profile",
    "Send me your login and I'll help you recover your account",
    "Wire me $500 and I'll send you $5000 back, I promise",
]

PHISHING_UK = [
    "Вітаємо! Ви виграли 10000 грн, перейдіть за посиланням",
    "УВАГА: Ваш акаунт зламано, підтвердіть особу негайно",
    "Ваша посилка не доставлена, оновіть адресу тут",
    "Хтось намагався увійти у ваш акаунт, натисніть щоб захистити",
    "У вас невитребувана нагорода, введіть дані щоб отримати",
    "Ваш банківський рахунок буде заблоковано якщо не підтвердите",
    "Безкоштовний iPhone! Введіть email та номер телефону",
    "Я знайшов спосіб отримати безкоштовні V-баксы, зайди на цей сайт",
    "Новий додаток показує хто переглядав твій профіль",
    "Надішли мені логін і я допоможу відновити акаунт",
    "Переведи 500 грн і я поверну 5000, обіцяю",
    "Вам нарахована допомога від держави, зареєструйтесь за посиланням",
]

PHISHING_RU = [
    "Поздравляем! Вы выиграли 10000 руб, перейдите по ссылке",
    "ВНИМАНИЕ: Ваш аккаунт взломан, подтвердите личность немедленно",
    "Ваша посылка не доставлена, обновите адрес здесь",
    "Ваш банковский счет будет заблокирован если не подтвердите",
    "Бесплатный iPhone! Введите email и номер телефона",
    "Я нашел способ получить бесплатные V-баксы, зайди на этот сайт",
    "Пришли мне логин и я помогу восстановить аккаунт",
    "Переведи 500 руб и я верну 5000, обещаю",
]

# ── Hate Speech ─────────────────────────────────────────────────────────

HATE_SPEECH_EN = [
    "All [group] should be deported, they don't belong here",
    "People like that are subhuman and don't deserve rights",
    "This is our country, go back where you came from",
    "[Group] are ruining everything for the rest of us",
    "They're all criminals and parasites living off our taxes",
    "The world would be better without those people",
    "I hope they all suffer for what their kind has done",
    "Those people are genetically inferior, it's just science",
    "We need to cleanse our society of this filth",
    "They're invading our culture and replacing us",
]

HATE_SPEECH_UK = [
    "Всі москалі однакові, їх треба знищити",
    "Ці біженці приїхали жити за наші гроші",
    "Роми крадуть і ніколи не працюють",
    "Ці люди не заслуговують на людські права",
    "Наша країна для нас, нехай їдуть звідки приїхали",
    "Світ був би кращим без цих людей",
]

HATE_SPEECH_RU = [
    "Все хохлы одинаковые, их надо уничтожить",
    "Эти беженцы приехали жить за наши деньги",
    "Эти люди не заслуживают человеческих прав",
    "Наша страна для нас, пусть едут откуда приехали",
]

# ── Doxxing / PII Leakage ──────────────────────────────────────────────

DOXXING_EN = [
    "I found out where she lives, posting the address now",
    "His real name is John Smith and he works at company X",
    "Here's her phone number, let's all call and harass her",
    "I tracked down their home address using their IP",
    "Posting their school schedule so you know where to find them",
    "Their social security number is 123-45-6789",
    "I have screenshots of their private messages, sharing now",
    "This is their real photo, not the fake one they use online",
    "Their parents live at 123 Main St, let's send them letters",
    "Here's everything I found about them — name, address, workplace",
]

DOXXING_UK = [
    "Я знайшов де вона живе, публікую адресу",
    "Його справжнє ім'я та місце роботи...",
    "Ось її номер телефону, давайте всі дзвонити",
    "Я відстежив їх домашню адресу через IP",
    "Публікую їх розклад в школі щоб знали де знайти",
    "Це їх справжнє фото, а не фейкове з інтернету",
]

# ── Military OPSEC Violations ───────────────────────────────────────────

OPSEC_UA = [
    "Наші хлопці стоять біля Бахмута, координати 48.5953 38.0013",
    "Завтра о 6 ранку буде ротація в нашому секторі",
    "В нас на позиції 2 БМП та гаубиця, боєкомплект на 3 дні",
    "Підкріплення прибуде через 2 години з напрямку Покровська",
    "Зв'язок через Starlink, позивний Сокіл, частота 149.5",
    "Фотка з позиції, видно наш блокпост на перехресті",
    "Нова техніка прибула — 3 Бредлі та 2 Леопарди",
    "Командир батальйону прізвище Коваленко, позивний Буря",
    "Дрони літають з точки збору біля лісосмуги на карті",
    "В нашому підрозділі 45 людей, 8 поранених за тиждень",
]

OPSEC_RU = [
    "Наши стоят возле Авдеевки, координаты 48.1435 37.7475",
    "Завтра в 5 утра наступление в нашем секторе",
    "У нас на позиции 3 танка и 2 БМП",
    "Подкрепление прибудет через час с направления Донецка",
    "Новая техника прибыла — 5 БТР и гаубица",
]

# ── Military Social Engineering ─────────────────────────────────────────

SOCIAL_ENG_UA = [
    "Привіт, я з волонтерської організації, скинь позицію щоб привезти допомогу",
    "Я журналіст, можеш показати на карті де ви зараз стоїте?",
    "Я від командування, терміново надішли координати вашого розташування",
    "Збираємо інформацію для звіту, скільки техніки у вашому підрозділі?",
    "Я з генштабу, потрібні дані про особовий склад",
    "Допоможи оновити карту мінних полів, надішли фото",
    "Я з Червоного Хреста, де ваші поранені зараз знаходяться?",
]

SOCIAL_ENG_RU = [
    "Привет, я из волонтерской организации, скинь позицию чтобы привезти помощь",
    "Я журналист, можешь показать на карте где вы сейчас стоите?",
    "Я от командования, срочно пришли координаты вашего расположения",
    "Собираем информацию для отчета, сколько техники в вашем подразделении?",
]

# ── Negative Controls ───────────────────────────────────────────────────

NEGATIVE_NEWS_EN = [
    "The president held a press conference about the economy today",
    "Scientists discovered a new species of butterfly in the Amazon",
    "The local school won the state championship in basketball",
    "New traffic lights were installed on Main Street to improve safety",
    "The weather forecast shows rain for the next three days",
    "A new restaurant opened downtown with a Mediterranean menu",
    "The city council approved the budget for next year",
    "Local volunteers cleaned up the park over the weekend",
    "The museum is hosting a free exhibition on ancient history",
    "The university announced new scholarships for engineering students",
]

NEGATIVE_NEWS_UK = [
    "Президент провів пресконференцію щодо економіки",
    "Вчені відкрили новий вид метелика в Амазонці",
    "Місцева школа виграла чемпіонат з баскетболу",
    "Прогноз погоди обіцяє дощ наступні три дні",
    "Відкрився новий ресторан з середземноморським меню",
    "Міська рада затвердила бюджет на наступний рік",
    "Волонтери прибрали парк на вихідних",
    "Університет оголосив нові стипендії для студентів",
    "Музей проводить безкоштовну виставку з давньої історії",
]

NEGATIVE_NEWS_RU = [
    "Президент провел пресс-конференцию по экономике",
    "Ученые открыли новый вид бабочки в Амазонке",
    "Местная школа выиграла чемпионат по баскетболу",
    "Прогноз погоды обещает дождь на следующие три дня",
    "Открылся новый ресторан со средиземноморским меню",
    "Городской совет утвердил бюджет на следующий год",
    "Волонтеры убрали парк на выходных",
]

NEGATIVE_MILITARY_UA = [
    "Слава Україні! Разом переможемо!",
    "Дякую нашим захисникам за їх службу",
    "Волонтери зібрали допомогу для фронту",
    "Зустрів побратимів після ротації, всі живі",
    "Тренування пройшло добре, хлопці готові",
    "Отримали нову форму та спорядження від волонтерів",
    "Зв'язок з домом через Starlink, все добре",
    "Командир подякував за добру роботу",
]


def build_dataset():
    rows = []

    def add(samples, category):
        for text in samples:
            rows.append({"prompt": text, "category": category})

    # Propaganda
    add(PROPAGANDA_UA, "propaganda")
    add(PROPAGANDA_RU, "propaganda")
    add(PROPAGANDA_EN, "propaganda")

    # Phishing / Scam
    add(PHISHING_EN, "phishing")
    add(PHISHING_UK, "phishing")
    add(PHISHING_RU, "phishing")

    # Hate Speech
    add(HATE_SPEECH_EN, "hate_speech")
    add(HATE_SPEECH_UK, "hate_speech")
    add(HATE_SPEECH_RU, "hate_speech")

    # Doxxing
    add(DOXXING_EN, "doxxing")
    add(DOXXING_UK, "doxxing")

    # OPSEC Violations
    add(OPSEC_UA, "opsec")
    add(OPSEC_RU, "opsec")

    # Military Social Engineering
    add(SOCIAL_ENG_UA, "social_eng")
    add(SOCIAL_ENG_RU, "social_eng")

    # Negative controls
    add(NEGATIVE_NEWS_EN, "safe")
    add(NEGATIVE_NEWS_UK, "safe")
    add(NEGATIVE_NEWS_RU, "safe")
    add(NEGATIVE_MILITARY_UA, "safe")

    # Augment with prefix variations
    augmented = []
    prefixes_en = ["", "hey ", "btw ", "FYI ", "BREAKING: ", "just saw this: "]
    prefixes_uk = ["", "слухай ", "до речі ", "УВАГА: ", "тільки що бачив: "]
    prefixes_ru = ["", "слушай ", "кстати ", "ВНИМАНИЕ: ", "только что видел: "]

    for row in rows:
        augmented.append(row)
        text = row["prompt"]
        category = row["category"]

        has_cyrillic = any('\u0400' <= c <= '\u04FF' for c in text)
        if has_cyrillic:
            is_uk = any(c in text for c in 'їєіґ')
            prefixes = prefixes_uk if is_uk else prefixes_ru
        else:
            prefixes = prefixes_en

        for prefix in random.sample(prefixes, min(2, len(prefixes))):
            if prefix and prefix.strip():
                augmented.append({
                    "prompt": prefix + text[0].lower() + text[1:],
                    "category": category,
                })

    return augmented


def main():
    rows = build_dataset()
    random.shuffle(rows)

    texts = [r["prompt"] for r in rows]
    categories = [r["category"] for r in rows]

    # Stats
    from collections import Counter
    counts = Counter(categories)
    print(f"Total samples: {len(rows)}")
    for cat, count in sorted(counts.items()):
        print(f"  {cat}: {count}")

    # Save
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    table = pa.table({
        "prompt": texts,
        "category": categories,
    })
    output_path = OUTPUT_DIR / "propaganda_synthetic.parquet"
    pq.write_table(table, output_path)
    print(f"\nSaved to {output_path}")


if __name__ == "__main__":
    main()
