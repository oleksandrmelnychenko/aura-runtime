use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DomainInput {
    pub text: Option<String>,
    pub language: Option<String>,
    pub sender_id: Option<String>,
    pub conversation_id: Option<String>,
}
