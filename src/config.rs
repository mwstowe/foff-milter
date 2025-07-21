use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub socket_path: String,
    pub rules: Vec<FilterRule>,
    pub default_action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    pub name: String,
    pub criteria: Criteria,
    pub action: Action,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Criteria {
    MailerPattern { pattern: String },
    SenderPattern { pattern: String },
    RecipientPattern { pattern: String },
    SubjectPattern { pattern: String },
    HeaderPattern { header: String, pattern: String },
    SubjectContainsLanguage { language: String },
    HeaderContainsLanguage { header: String, language: String },
    And { criteria: Vec<Criteria> },
    Or { criteria: Vec<Criteria> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Action {
    Reject {
        message: String,
    },
    TagAsSpam {
        header_name: String,
        header_value: String,
    },
    Accept,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            socket_path: "/var/run/foff-milter.sock".to_string(),
            rules: vec![
                FilterRule {
                    name: "Block suspicious Chinese services".to_string(),
                    criteria: Criteria::MailerPattern {
                        pattern: r"service\..*\.cn".to_string(),
                    },
                    action: Action::Reject {
                        message: "Mail from suspicious service rejected".to_string(),
                    },
                },
                FilterRule {
                    name: "Tag potential spam".to_string(),
                    criteria: Criteria::MailerPattern {
                        pattern: r".*spam.*".to_string(),
                    },
                    action: Action::TagAsSpam {
                        header_name: "X-Spam-Flag".to_string(),
                        header_value: "YES".to_string(),
                    },
                },
            ],
            default_action: Action::Accept,
        }
    }
}

impl Config {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn to_file(&self, path: &str) -> anyhow::Result<()> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
