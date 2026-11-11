use deepdoc_protocol::{FieldScope, RuleExpr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("empty rule expression")]
    Empty,
    #[error("unexpected token `{token}` at char {pos}")]
    UnexpectedToken { token: String, pos: usize },
    #[error("unterminated delimiter `{delim}` starting at char {pos}")]
    Unterminated { delim: char, pos: usize },
    #[error("expected `{expected}` at char {pos}")]
    Expected { expected: String, pos: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    And,
    Or,
    Not,
    LParen,
    RParen,
    Comma,
    Quoted(String),
    Regex(String),
    Word(String),
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    pos: usize,
}

fn tokenize(input: &str) -> Result<Vec<Token>, ParseError> {
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut i = 0;
    let mut tokens = Vec::new();

    while i < chars.len() {
        let (pos, ch) = chars[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        match ch {
            '(' => {
                tokens.push(Token { kind: TokenKind::LParen, pos });
                i += 1;
            }
            ')' => {
                tokens.push(Token { kind: TokenKind::RParen, pos });
                i += 1;
            }
            ',' => {
                tokens.push(Token { kind: TokenKind::Comma, pos });
                i += 1;
            }
            '&' => {
                if i + 1 < chars.len() && chars[i + 1].1 == '&' {
                    i += 2;
                } else {
                    i += 1;
                }
                tokens.push(Token { kind: TokenKind::And, pos });
            }
            '|' => {
                if i + 1 < chars.len() && chars[i + 1].1 == '|' {
                    i += 2;
                } else {
                    i += 1;
                }
                tokens.push(Token { kind: TokenKind::Or, pos });
            }
            '!' => {
                tokens.push(Token { kind: TokenKind::Not, pos });
                i += 1;
            }
            '"' => {
                i += 1;
                let mut s = String::new();
                let mut closed = false;
                while i < chars.len() {
                    let (_, c) = chars[i];
                    if c == '\\' && i + 1 < chars.len() {
                        i += 1;
                        s.push(chars[i].1);
                        i += 1;
                        continue;
                    }
                    if c == '"' {
                        closed = true;
                        i += 1;
                        break;
                    }
                    s.push(c);
                    i += 1;
                }
                if !closed {
                    return Err(ParseError::Unterminated { delim: '"', pos });
                }
                tokens.push(Token { kind: TokenKind::Quoted(s), pos });
            }
            _ => {
                // Check for `re:/.../` prefix
                if input[pos..].starts_with("re:/") {
                    i += 4;
                    let mut pat = String::new();
                    let mut closed = false;
                    while i < chars.len() {
                        let (_, c) = chars[i];
                        if c == '\\' && i + 1 < chars.len() {
                            pat.push('\\');
                            pat.push(chars[i + 1].1);
                            i += 2;
                            continue;
                        }
                        if c == '/' {
                            closed = true;
                            i += 1;
                            break;
                        }
                        pat.push(c);
                        i += 1;
                    }
                    if !closed {
                        return Err(ParseError::Unterminated { delim: '/', pos });
                    }
                    let mut flags = String::new();
                    while i < chars.len() {
                        let (_, fc) = chars[i];
                        if matches!(fc, 'i' | 'm' | 's' | 'U' | 'x') {
                            if !flags.contains(fc) {
                                flags.push(fc);
                            }
                            i += 1;
                        } else {
                            break;
                        }
                    }
                    let final_pat = if flags.is_empty() {
                        pat
                    } else {
                        format!("(?{flags}:{pat})")
                    };
                    tokens.push(Token { kind: TokenKind::Regex(final_pat), pos });
                    continue;
                }

                // Bare word until whitespace or operator delimiter
                let mut word = String::new();
                while i < chars.len() {
                    let (_, c) = chars[i];
                    if c.is_whitespace() || matches!(c, '(' | ')' | ',' | '&' | '|' | '!' | '"') {
                        break;
                    }
                    word.push(c);
                    i += 1;
                }
                let upper = word.to_ascii_uppercase();
                let kind = match upper.as_str() {
                    "AND" => TokenKind::And,
                    "OR" => TokenKind::Or,
                    "NOT" => TokenKind::Not,
                    _ => TokenKind::Word(word),
                };
                tokens.push(Token { kind, pos });
            }
        }
    }

    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_or(&mut self) -> Result<RuleExpr, ParseError> {
        let mut items = vec![self.parse_and()?];
        while let Some(tok) = self.peek() {
            if tok.kind == TokenKind::Or {
                self.next();
                items.push(self.parse_and()?);
            } else {
                break;
            }
        }
        if items.len() == 1 {
            Ok(items.pop().unwrap())
        } else {
            Ok(RuleExpr::Or(items))
        }
    }

    fn parse_and(&mut self) -> Result<RuleExpr, ParseError> {
        let mut items = vec![self.parse_unary()?];
        while let Some(tok) = self.peek() {
            match tok.kind {
                TokenKind::And => {
                    self.next();
                    items.push(self.parse_unary()?);
                }
                // Implicit AND for adjacent terms / groups, e.g. `预算 内部`
                TokenKind::Not
                | TokenKind::LParen
                | TokenKind::Quoted(_)
                | TokenKind::Regex(_)
                | TokenKind::Word(_) => {
                    items.push(self.parse_unary()?);
                }
                _ => break,
            }
        }
        if items.len() == 1 {
            Ok(items.pop().unwrap())
        } else {
            Ok(RuleExpr::And(items))
        }
    }

    fn parse_unary(&mut self) -> Result<RuleExpr, ParseError> {
        if let Some(tok) = self.peek() {
            if tok.kind == TokenKind::Not {
                self.next();
                let inner = self.parse_unary()?;
                return Ok(RuleExpr::Not(Box::new(inner)));
            }
        }
        self.parse_primary()
    }

    fn expect_rparen(&mut self, open_pos: usize) -> Result<(), ParseError> {
        match self.next() {
            Some(Token { kind: TokenKind::RParen, .. }) => Ok(()),
            _ => Err(ParseError::Unterminated { delim: '(', pos: open_pos }),
        }
    }

    fn parse_primary(&mut self) -> Result<RuleExpr, ParseError> {
        let tok = self.next().ok_or(ParseError::Empty)?;
        match tok.kind {
            TokenKind::LParen => {
                let inner = self.parse_or()?;
                self.expect_rparen(tok.pos)?;
                Ok(inner)
            }
            TokenKind::Quoted(s) => Ok(RuleExpr::Phrase {
                text: s,
                case_sensitive: false,
            }),
            TokenKind::Regex(pat) => Ok(RuleExpr::Regex { pattern: pat }),
            TokenKind::Word(w) => self.parse_word_construct(w, tok.pos),
            other => Err(ParseError::UnexpectedToken {
                token: format!("{other:?}"),
                pos: tok.pos,
            }),
        }
    }

    fn parse_word_construct(&mut self, word: String, pos: usize) -> Result<RuleExpr, ParseError> {
        let upper = word.to_ascii_uppercase();

        // Function forms: ATLEAST(2, a, b, c) or SAMELINE(a, b)
        if upper == "ATLEAST" {
            if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::LParen)) {
                let open = self.next().unwrap();
                let min_tok = self.next().ok_or(ParseError::Expected {
                    expected: "integer minimum".into(),
                    pos: open.pos,
                })?;
                let min: usize = match min_tok.kind {
                    TokenKind::Word(n) => n.parse().map_err(|_| ParseError::Expected {
                        expected: "integer minimum".into(),
                        pos: min_tok.pos,
                    })?,
                    _ => {
                        return Err(ParseError::Expected {
                            expected: "integer minimum".into(),
                            pos: min_tok.pos,
                        })
                    }
                };
                if !matches!(self.next().map(|t| t.kind), Some(TokenKind::Comma)) {
                    return Err(ParseError::Expected {
                        expected: "comma after minimum".into(),
                        pos: open.pos,
                    });
                }
                let mut exprs = Vec::new();
                loop {
                    exprs.push(self.parse_or()?);
                    match self.peek().map(|t| &t.kind) {
                        Some(TokenKind::Comma) => {
                            self.next();
                        }
                        Some(TokenKind::RParen) => {
                            self.next();
                            break;
                        }
                        _ => return Err(ParseError::Unterminated { delim: '(', pos: open.pos }),
                    }
                }
                return Ok(RuleExpr::AtLeast { min, exprs });
            }
        }

        if upper == "SAMELINE" {
            if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::LParen)) {
                let open = self.next().unwrap();
                let mut terms = Vec::new();
                loop {
                    let t = self.next().ok_or(ParseError::Unterminated { delim: '(', pos: open.pos })?;
                    match t.kind {
                        TokenKind::Word(s) | TokenKind::Quoted(s) => terms.push(s),
                        _ => {
                            return Err(ParseError::Expected {
                                expected: "term in SAMELINE".into(),
                                pos: t.pos,
                            })
                        }
                    }
                    match self.peek().map(|tk| &tk.kind) {
                        Some(TokenKind::Comma) => {
                            self.next();
                        }
                        Some(TokenKind::RParen) => {
                            self.next();
                            break;
                        }
                        _ => return Err(ParseError::Unterminated { delim: '(', pos: open.pos }),
                    }
                }
                return Ok(RuleExpr::SameLine {
                    terms,
                    case_sensitive: false,
                });
            }
        }

        if upper == "NEAR" || upper == "ONEAR" {
            if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::LParen)) {
                let open = self.next().unwrap();
                let ordered = upper == "ONEAR";
                let expect_term = |tok: Token| -> Result<String, ParseError> {
                    match tok.kind {
                        TokenKind::Word(s) | TokenKind::Quoted(s) => Ok(s),
                        _ => Err(ParseError::Expected {
                            expected: "term in NEAR/ONEAR".into(),
                            pos: tok.pos,
                        }),
                    }
                };
                let t1 = self.next().ok_or(ParseError::Unterminated { delim: '(', pos: open.pos })?;
                let left = expect_term(t1)?;
                match self.next() {
                    Some(Token { kind: TokenKind::Comma, .. }) => {}
                    Some(other) => {
                        return Err(ParseError::Expected {
                            expected: "',' after first term in NEAR".into(),
                            pos: other.pos,
                        });
                    }
                    None => return Err(ParseError::Unterminated { delim: '(', pos: open.pos }),
                }
                let t2 = self.next().ok_or(ParseError::Unterminated { delim: '(', pos: open.pos })?;
                let right = expect_term(t2)?;
                let mut max_distance_chars = 30usize;
                match self.peek().map(|tk| &tk.kind) {
                    Some(TokenKind::Comma) => {
                        self.next();
                        let dtok = self.next().ok_or(ParseError::Unterminated { delim: '(', pos: open.pos })?;
                        max_distance_chars = match dtok.kind {
                            TokenKind::Word(n) => n.parse::<usize>().map_err(|_| ParseError::Expected {
                                expected: "non-negative integer distance in NEAR".into(),
                                pos: dtok.pos,
                            })?,
                            _ => {
                                return Err(ParseError::Expected {
                                    expected: "non-negative integer distance in NEAR".into(),
                                    pos: dtok.pos,
                                })
                            }
                        };
                        match self.next() {
                            Some(Token { kind: TokenKind::RParen, .. }) => {}
                            Some(other) => {
                                return Err(ParseError::Expected {
                                    expected: "')' closing NEAR".into(),
                                    pos: other.pos,
                                });
                            }
                            None => return Err(ParseError::Unterminated { delim: '(', pos: open.pos }),
                        }
                    }
                    Some(TokenKind::RParen) => {
                        self.next();
                    }
                    _ => return Err(ParseError::Unterminated { delim: '(', pos: open.pos }),
                }
                return Ok(RuleExpr::Near {
                    left,
                    right,
                    max_distance_chars,
                    ordered,
                    case_sensitive: false,
                });
            }
        }

        // Scope prefixes: `scope:filename(...)` or `filename:关键词`
        if let Some((prefix, rest)) = word.split_once(':') {
            let scope_opt = match prefix.to_ascii_lowercase().as_str() {
                "filename" | "name" => Some(FieldScope::FileName),
                "head_tail" | "headtail" => Some(FieldScope::HeadTail),
                "body" => Some(FieldScope::Body),
                "ocr" => Some(FieldScope::Ocr),
                "table" => Some(FieldScope::Table),
                "metadata" | "meta" => Some(FieldScope::Metadata),
                "scope" => match rest.to_ascii_lowercase().as_str() {
                    "filename" | "name" => Some(FieldScope::FileName),
                    "head_tail" | "headtail" => Some(FieldScope::HeadTail),
                    "body" => Some(FieldScope::Body),
                    "ocr" => Some(FieldScope::Ocr),
                    "table" => Some(FieldScope::Table),
                    "metadata" | "meta" => Some(FieldScope::Metadata),
                    _ => None,
                },
                _ => None,
            };

            if let Some(scope) = scope_opt {
                if prefix.eq_ignore_ascii_case("scope") {
                    // Expect `(` expr `)`
                    let open = self.next().ok_or(ParseError::Expected {
                        expected: "(".into(),
                        pos,
                    })?;
                    if open.kind != TokenKind::LParen {
                        return Err(ParseError::Expected {
                            expected: "(".into(),
                            pos: open.pos,
                        });
                    }
                    let inner = self.parse_or()?;
                    self.expect_rparen(open.pos)?;
                    return Ok(RuleExpr::Scoped {
                        scope,
                        inner: Box::new(inner),
                    });
                } else if !rest.is_empty() {
                    let inner = RuleExpr::Term {
                        text: rest.to_string(),
                        case_sensitive: false,
                    };
                    return Ok(RuleExpr::Scoped {
                        scope,
                        inner: Box::new(inner),
                    });
                }
            }
        }

        Ok(RuleExpr::Term {
            text: word,
            case_sensitive: false,
        })
    }
}

pub fn parse_rule_expression(expr: &str) -> Result<RuleExpr, ParseError> {
    let tokens = tokenize(expr)?;
    if tokens.is_empty() {
        return Err(ParseError::Empty);
    }
    let mut parser = Parser { tokens, pos: 0 };
    let ast = parser.parse_or()?;
    if let Some(extra) = parser.peek() {
        return Err(ParseError::UnexpectedToken {
            token: format!("{:?}", extra.kind),
            pos: extra.pos,
        });
    }
    Ok(ast)
}
