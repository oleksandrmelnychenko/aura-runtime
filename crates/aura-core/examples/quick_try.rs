use std::env;
use std::io::{self, Write};

use aura_core::{
    AccountType, Analyzer, AuraConfig, ContentType, ConversationType, MessageInput, ProtectionLevel,
};
use aura_patterns::PatternDatabase;

const STEP_MS: u64 = 60_000;
const DEFAULT_START_MS: u64 = 12 * 60 * 60 * 1000;

fn main() {
    let mut args = Args::default();
    if let Err(err) = args.parse(env::args().skip(1)) {
        eprintln!("error: {err}");
        print_help();
        std::process::exit(2);
    }

    if args.help {
        print_help();
        return;
    }

    let db = PatternDatabase::default_mvp();
    let mut analyzer = Analyzer::new(build_config(&args), &db);
    let mut state = SessionState::from_args(&args);

    if let Some(text) = args.text {
        run_once(&mut analyzer, &mut state, &text);
        return;
    }

    println!("AURA quick_try interactive mode");
    println!("Type a message and press Enter.");
    println!("Commands: /help /reset /sender <id> /conv <id> /lang <code> /direct /group <members> /exit");
    println!(
        "Current session: sender={} conv={} lang={} type={:?}",
        state.sender_id, state.conversation_id, state.language, state.conversation_type
    );
    println!();

    let stdin = io::stdin();
    loop {
        print!("aura> ");
        io::stdout().flush().expect("flush failed");

        let mut line = String::new();
        if stdin.read_line(&mut line).expect("stdin read failed") == 0 {
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line == "/exit" || line == "/quit" {
            break;
        }

        if line == "/help" {
            println!(
                "Normal input: analyze the line as the next message in the current conversation."
            );
            println!("/reset             reset analyzer context");
            println!("/sender <id>       change sender id");
            println!("/conv <id>         change conversation id");
            println!("/lang <code>       change language, e.g. uk, en, ru");
            println!("/direct            use direct conversation mode");
            println!("/group <members>   use group mode with the given member count");
            println!("/exit              leave interactive mode");
            continue;
        }

        if line == "/reset" {
            analyzer = Analyzer::new(build_config(&args), &db);
            state = SessionState::from_args(&args);
            println!("Context reset.");
            continue;
        }

        if let Some(value) = line.strip_prefix("/sender ") {
            state.sender_id = value.trim().to_string();
            println!("sender={}", state.sender_id);
            continue;
        }

        if let Some(value) = line.strip_prefix("/conv ") {
            state.conversation_id = value.trim().to_string();
            println!("conv={}", state.conversation_id);
            continue;
        }

        if let Some(value) = line.strip_prefix("/lang ") {
            state.language = value.trim().to_string();
            println!("lang={}", state.language);
            continue;
        }

        if line == "/direct" {
            state.conversation_type = ConversationType::Direct;
            state.member_count = None;
            println!("conversation_type=Direct");
            continue;
        }

        if let Some(value) = line.strip_prefix("/group ") {
            match value.trim().parse::<u32>() {
                Ok(count) if count >= 2 => {
                    state.conversation_type = ConversationType::Group;
                    state.member_count = Some(count);
                    println!("conversation_type=Group members={count}");
                }
                _ => {
                    println!("expected member count >= 2");
                }
            }
            continue;
        }

        run_once(&mut analyzer, &mut state, line);
    }
}

#[derive(Debug)]
struct SessionState {
    sender_id: String,
    conversation_id: String,
    language: String,
    conversation_type: ConversationType,
    member_count: Option<u32>,
    next_timestamp_ms: u64,
}

impl SessionState {
    fn from_args(args: &Args) -> Self {
        Self {
            sender_id: args.sender_id.clone(),
            conversation_id: args.conversation_id.clone(),
            language: args.language.clone(),
            conversation_type: args.conversation_type,
            member_count: args.member_count,
            next_timestamp_ms: DEFAULT_START_MS,
        }
    }
}

#[derive(Debug)]
struct Args {
    account_type: AccountType,
    protection_level: ProtectionLevel,
    sender_id: String,
    conversation_id: String,
    language: String,
    conversation_type: ConversationType,
    member_count: Option<u32>,
    text: Option<String>,
    help: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            account_type: AccountType::Child,
            protection_level: ProtectionLevel::High,
            sender_id: "sender_1".to_string(),
            conversation_id: "demo_conv".to_string(),
            language: "uk".to_string(),
            conversation_type: ConversationType::Direct,
            member_count: None,
            text: None,
            help: false,
        }
    }
}

impl Args {
    fn parse<I>(&mut self, mut args: I) -> Result<(), String>
    where
        I: Iterator<Item = String>,
    {
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => {
                    self.help = true;
                }
                "--text" => {
                    self.text = Some(next_arg(&mut args, "--text")?);
                }
                "--sender" => {
                    self.sender_id = next_arg(&mut args, "--sender")?;
                }
                "--conv" => {
                    self.conversation_id = next_arg(&mut args, "--conv")?;
                }
                "--lang" => {
                    self.language = next_arg(&mut args, "--lang")?;
                }
                "--account" => {
                    self.account_type = parse_account_type(&next_arg(&mut args, "--account")?)?;
                }
                "--protection" => {
                    self.protection_level =
                        parse_protection_level(&next_arg(&mut args, "--protection")?)?;
                }
                "--conversation" => {
                    let value = next_arg(&mut args, "--conversation")?;
                    self.conversation_type = parse_conversation_type(&value)?;
                    if self.conversation_type == ConversationType::Direct {
                        self.member_count = None;
                    }
                }
                "--members" => {
                    let value = next_arg(&mut args, "--members")?;
                    let count = value
                        .parse::<u32>()
                        .map_err(|_| format!("invalid --members value: {value}"))?;
                    if count < 2 {
                        return Err("--members must be >= 2".to_string());
                    }
                    self.member_count = Some(count);
                    self.conversation_type = ConversationType::Group;
                }
                other => {
                    return Err(format!("unknown argument: {other}"));
                }
            }
        }

        Ok(())
    }
}

fn next_arg<I>(args: &mut I, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_account_type(value: &str) -> Result<AccountType, String> {
    match value {
        "adult" => Ok(AccountType::Adult),
        "teen" => Ok(AccountType::Teen),
        "child" => Ok(AccountType::Child),
        _ => Err(format!("invalid --account value: {value}")),
    }
}

fn parse_protection_level(value: &str) -> Result<ProtectionLevel, String> {
    match value {
        "off" => Ok(ProtectionLevel::Off),
        "low" => Ok(ProtectionLevel::Low),
        "medium" => Ok(ProtectionLevel::Medium),
        "high" => Ok(ProtectionLevel::High),
        _ => Err(format!("invalid --protection value: {value}")),
    }
}

fn parse_conversation_type(value: &str) -> Result<ConversationType, String> {
    match value {
        "direct" => Ok(ConversationType::Direct),
        "group" => Ok(ConversationType::Group),
        _ => Err(format!("invalid --conversation value: {value}")),
    }
}

fn build_config(args: &Args) -> AuraConfig {
    AuraConfig {
        account_type: args.account_type,
        protection_level: args.protection_level,
        language: args.language.clone(),
        ..AuraConfig::default()
    }
}

fn run_once(analyzer: &mut Analyzer, state: &mut SessionState, text: &str) {
    let input = MessageInput {
        content_type: ContentType::Text,
        text: Some(text.to_string()),
        image_data: None,
        sender_id: state.sender_id.as_str().into(),
        conversation_id: state.conversation_id.as_str().into(),
        language: Some(state.language.clone()),
        conversation_type: state.conversation_type,
        member_count: state.member_count,
        server_sender_risk_hint: None,
    };

    let result = analyzer.analyze_with_context(&input, state.next_timestamp_ms);
    state.next_timestamp_ms = state.next_timestamp_ms.saturating_add(STEP_MS);

    println!(
        "threat={:?} action={:?} score={:.2} confidence={:?}",
        result.threat_type, result.action, result.score, result.confidence
    );

    if let Some(recommendation) = &result.recommended_action {
        println!(
            "alert={:?} crisis_resources={} ui_actions={:?} follow_ups={:?}",
            recommendation.parent_alert,
            recommendation.crisis_resources,
            recommendation.ui_actions,
            recommendation.follow_ups
        );
    }

    if !result.reason_codes.is_empty() {
        println!("reason_codes={:?}", result.reason_codes);
    }

    if let Some(snapshot) = &result.contact_snapshot {
        println!(
            "contact: sender={} rating={:.1} trust={:.2} tier={:?} trend={:?} new_contact={}",
            snapshot.sender_id,
            snapshot.rating,
            snapshot.trust_level,
            snapshot.circle_tier,
            snapshot.trend,
            snapshot.is_new_contact
        );
    }

    if result.inference.risk_horizon != aura_core::RiskHorizon::Unknown
        || !result.inference.latent_states.is_empty()
    {
        println!(
            "inference: horizon={:?} escalation_24h={:.2} latent_states={:?}",
            result.inference.risk_horizon,
            result.inference.escalation_likelihood_24h,
            result.inference.latent_states
        );
    }

    let interesting_signals: Vec<_> = result
        .signals
        .iter()
        .filter(|signal| signal.score >= 0.25)
        .collect();
    if !interesting_signals.is_empty() {
        println!("signals:");
        for signal in interesting_signals {
            println!(
                "  - layer={:?} family={:?} threat={:?} score={:.2} code={} explanation={}",
                signal.layer,
                signal.family,
                signal.threat_type,
                signal.score,
                signal.reason_code,
                signal.explanation
            );
        }
    }

    println!();
}

fn print_help() {
    println!("Usage:");
    println!("  cargo run --example quick_try -p aura-core -- [options]");
    println!();
    println!("Options:");
    println!("  --text <message>            analyze a single message and exit");
    println!("  --sender <id>               sender id (default: sender_1)");
    println!("  --conv <id>                 conversation id (default: demo_conv)");
    println!("  --lang <code>               language code (default: uk)");
    println!("  --account <adult|teen|child>");
    println!("  --protection <off|low|medium|high>");
    println!("  --conversation <direct|group>");
    println!("  --members <n>               member count for group mode");
    println!("  --help                      show this message");
    println!();
    println!("Interactive mode starts when --text is omitted.");
}
