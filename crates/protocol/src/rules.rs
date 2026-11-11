use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleMatchMode {
    FirstHit,
    FullHits,
}

impl Default for RuleMatchMode {
    fn default() -> Self {
        Self::FullHits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldScope {
    Any,
    FileName,
    HeadTail,
    Body,
    Ocr,
    Table,
    Metadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleExpr {
    Term {
        text: String,
        case_sensitive: bool,
    },
    Phrase {
        text: String,
        case_sensitive: bool,
    },
    Regex {
        pattern: String,
    },
    And(Vec<RuleExpr>),
    Or(Vec<RuleExpr>),
    Not(Box<RuleExpr>),
    AtLeast {
        min: usize,
        exprs: Vec<RuleExpr>,
    },
    Scoped {
        scope: FieldScope,
        inner: Box<RuleExpr>,
    },
    SameLine {
        terms: Vec<String>,
        case_sensitive: bool,
    },
    Near {
        left: String,
        right: String,
        max_distance_chars: usize,
        ordered: bool,
        case_sensitive: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleDefinition {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: String,
    /// Raw expression string e.g. `("内部" | "机密") & (预算 | 招标) & !公开`
    /// or `ATLEAST(2, 绝密, 机密, 秘密)` or `re:/绝密\s*★/`.
    pub expression: String,
    #[serde(default)]
    pub mode: RuleMatchMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSet {
    pub ruleset_id: String,
    pub rules: Vec<RuleDefinition>,
}

impl RuleSet {
    /// Deterministic FNV-1a 64-bit fingerprint for rule-versioned hit caching.
    /// (Full SHA/BLAKE3 can also be computed in engine; this avoids pulling extra deps into protocol.)
    pub fn canonical_fingerprint(&self) -> String {
        let mut h: u64 = 0xcbf29ce484222325;
        let prime: u64 = 0x100000001b3;
        let feed = |state: &mut u64, bytes: &[u8]| {
            for &b in bytes {
                *state ^= b as u64;
                *state = state.wrapping_mul(prime);
            }
            *state ^= 0xff;
            *state = state.wrapping_mul(prime);
        };
        feed(&mut h, self.ruleset_id.as_bytes());
        for r in &self.rules {
            feed(&mut h, r.id.as_bytes());
            feed(&mut h, r.expression.as_bytes());
            let mode_b = match r.mode {
                RuleMatchMode::FirstHit => b"1",
                RuleMatchMode::FullHits => b"F",
            };
            feed(&mut h, mode_b);
        }
        format!("{h:016x}")
    }
}
