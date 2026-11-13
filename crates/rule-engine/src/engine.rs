use crate::parser::{parse_rule_expression, ParseError};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use deepdoc_protocol::{
    ExtractedDocument, FieldScope, HitLocationSnippet, HitRecord, RuleDefinition, RuleExpr,
    RuleMatchMode, RuleSet, SegmentScope, TextSegment,
};
use regex::{Regex, RegexSet};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CompileError {
    #[error("rule `{rule_id}` parse error: {source}")]
    Parse {
        rule_id: String,
        #[source]
        source: ParseError,
    },
    #[error("rule `{rule_id}` invalid regex `{pattern}`: {source}")]
    Regex {
        rule_id: String,
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

#[derive(Debug, Clone, Default)]
pub struct RuleEvalMetrics {
    pub rules_checked: usize,
    pub rules_pruned_stage1: usize,
    pub rules_evaluated_stage2: usize,
}

/// Stage-1 pre-filter condition over Aho-Corasick literal IDs.
#[derive(Debug, Clone)]
enum AnchorCond {
    AlwaysPass,
    Lit(usize),
    And(Vec<AnchorCond>),
    Or(Vec<AnchorCond>),
    AtLeast(usize, Vec<AnchorCond>),
}

impl AnchorCond {
    fn eval(&self, present: &[bool]) -> bool {
        match self {
            AnchorCond::AlwaysPass => true,
            AnchorCond::Lit(id) => present.get(*id).copied().unwrap_or(false),
            AnchorCond::And(items) => items.iter().all(|c| c.eval(present)),
            AnchorCond::Or(items) => items.iter().any(|c| c.eval(present)),
            AnchorCond::AtLeast(min, items) => {
                items.iter().filter(|c| c.eval(present)).count() >= *min
            }
        }
    }
}

#[derive(Debug, Clone)]
enum CompiledNode {
    Literal {
        lit_id: usize,
        text: String,
        case_sensitive: bool,
    },
    Regex {
        regex_id: usize,
        pattern: String,
    },
    And(Vec<CompiledNode>),
    Or(Vec<CompiledNode>),
    Not(Box<CompiledNode>),
    AtLeast {
        min: usize,
        nodes: Vec<CompiledNode>,
    },
    Scoped {
        scope: FieldScope,
        inner: Box<CompiledNode>,
    },
    SameLine {
        terms: Vec<(usize, String)>,
        case_sensitive: bool,
    },
    Near {
        left_id: usize,
        left_orig: String,
        right_id: usize,
        right_orig: String,
        max_distance_chars: usize,
        ordered: bool,
        case_sensitive: bool,
    },
}

#[derive(Debug, Clone)]
struct CompiledRule {
    def: RuleDefinition,
    root: CompiledNode,
    stage1_anchor: AnchorCond,
}

/// Two-stage compiled rule engine:
/// 1. Stage 1: Single Aho-Corasick scan over concatenated normalized text produces a literal bitset
///    and prunes impossible boolean rules immediately.
/// 2. Stage 2: Single combined `RegexSet` scan + precise AST evaluation across scoped `TextSegment`s,
///    extracting match counts and provenance snippets (`scope`, `location_label`, char offsets).
pub struct CompiledRuleSet {
    pub ruleset_id: String,
    pub fingerprint: String,
    literals: Vec<String>, // lowered literals
    all_lits_simple_case: bool,
    ac: Option<AhoCorasick>,
    regexes: Vec<Regex>,
    regex_set: Option<RegexSet>,
    rules: Vec<CompiledRule>,
}

impl CompiledRuleSet {
    pub fn compile(ruleset: &RuleSet) -> Result<Self, CompileError> {
        let mut lit_map: HashMap<String, usize> = HashMap::new();
        let mut literals: Vec<String> = Vec::new();
        let mut regex_patterns: Vec<String> = Vec::new();
        let mut regex_map: HashMap<String, usize> = HashMap::new();
        let mut compiled_rules = Vec::with_capacity(ruleset.rules.len());

        let mut intern_lit = |text: &str| -> usize {
            let key = text.to_lowercase();
            if let Some(&id) = lit_map.get(&key) {
                return id;
            }
            let id = literals.len();
            literals.push(key.clone());
            lit_map.insert(key, id);
            id
        };

        let mut intern_regex = |rule_id: &str, pat: &str| -> Result<usize, CompileError> {
            if let Some(&id) = regex_map.get(pat) {
                return Ok(id);
            }
            // Validate upfront so errors point to the exact rule_id
            Regex::new(pat).map_err(|e| CompileError::Regex {
                rule_id: rule_id.to_string(),
                pattern: pat.to_string(),
                source: e,
            })?;
            let id = regex_patterns.len();
            regex_patterns.push(pat.to_string());
            regex_map.insert(pat.to_string(), id);
            Ok(id)
        };

        for def in &ruleset.rules {
            let ast = parse_rule_expression(&def.expression).map_err(|e| CompileError::Parse {
                rule_id: def.id.clone(),
                source: e,
            })?;
            let (root, stage1_anchor) =
                compile_expr(&def.id, &ast, &mut intern_lit, &mut intern_regex)?;
            compiled_rules.push(CompiledRule {
                def: def.clone(),
                root,
                stage1_anchor,
            });
        }

        let all_lits_simple_case = literals.iter().all(|lit| {
            lit.chars()
                .all(|c| c.is_ascii() || c.to_lowercase().eq(c.to_uppercase()))
        });

        let ac = if literals.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(all_lits_simple_case)
                    .match_kind(MatchKind::Standard)
                    .build(&literals)
                    .expect("valid aho-corasick patterns"),
            )
        };

        let mut regexes = Vec::with_capacity(regex_patterns.len());
        for pat in &regex_patterns {
            regexes.push(Regex::new(pat).expect("validated regex"));
        }
        let regex_set = if regex_patterns.is_empty() {
            None
        } else {
            Some(RegexSet::new(&regex_patterns).expect("validated regex set"))
        };

        Ok(Self {
            ruleset_id: ruleset.ruleset_id.clone(),
            fingerprint: ruleset.canonical_fingerprint(),
            literals,
            all_lits_simple_case,
            ac,
            regexes,
            regex_set,
            rules: compiled_rules,
        })
    }

    /// Returns `true` if any rule in this set explicitly scopes on `FieldScope::FileName`.
    pub fn has_filename_scope(&self) -> bool {
        self.rules
            .iter()
            .any(|r| node_uses_scope(&r.root, FieldScope::FileName))
    }

    /// If every rule in this set requires matching specific trailing `.ext` filename suffixes
    /// (such as `scope:filename(re:/\.dwg$/i)`), returns those normalized lowercase extensions
    /// so SQLite can pre-filter rows without decompressing unrelated documents.
    pub fn prefilter_file_extensions(&self) -> Option<Vec<String>> {
        if self.rules.is_empty() {
            return None;
        }
        let mut union = Vec::new();
        for rule in &self.rules {
            let exts = extract_required_exts(&rule.root, FieldScope::Any)?;
            for e in exts {
                if !union.contains(&e) {
                    union.push(e);
                }
            }
        }
        (!union.is_empty()).then_some(union)
    }

    pub fn evaluate_document(
        &self,
        doc_id: u64,
        doc: &ExtractedDocument,
        max_snippets_per_rule: usize,
    ) -> (Vec<HitRecord>, RuleEvalMetrics) {
        let mut metrics = RuleEvalMetrics {
            rules_checked: self.rules.len(),
            ..Default::default()
        };
        if self.rules.is_empty() {
            return (Vec::new(), metrics);
        }

        // Stage 1: stream filename + segments through Aho-Corasick without concatenating a huge buffer.
        let mut present_lits = vec![false; self.literals.len()];
        if let Some(ac) = &self.ac {
            let all_found = |present: &[bool]| present.iter().all(|&b| b);
            let fields = std::iter::once(doc.file_name.as_str())
                .chain(doc.segments.iter().map(|s| s.text.as_str()));
            if self.all_lits_simple_case {
                for field in fields {
                    for mat in ac.find_overlapping_iter(field) {
                        present_lits[mat.pattern().as_usize()] = true;
                    }
                    if all_found(&present_lits) {
                        break;
                    }
                }
            } else {
                for field in fields {
                    let lower = field.to_lowercase();
                    for mat in ac.find_overlapping_iter(&lower) {
                        present_lits[mat.pattern().as_usize()] = true;
                    }
                    if all_found(&present_lits) {
                        break;
                    }
                }
            }
        }

        // Stage 1: prune impossible rules
        let mut candidates = Vec::new();
        for rule in &self.rules {
            if rule.stage1_anchor.eval(&present_lits) {
                candidates.push(rule);
            } else {
                metrics.rules_pruned_stage1 += 1;
            }
        }

        if candidates.is_empty() {
            return (Vec::new(), metrics);
        }

        // Stage 2: evaluate RegexSet per field/segment so `^` and `$` anchors match exact field boundaries
        let mut present_regexes = vec![false; self.regexes.len()];
        if let Some(rset) = &self.regex_set {
            for idx in rset.matches(&doc.file_name).into_iter() {
                present_regexes[idx] = true;
            }
            for seg in &doc.segments {
                if present_regexes.iter().all(|&b| b) {
                    break;
                }
                for idx in rset.matches(&seg.text).into_iter() {
                    present_regexes[idx] = true;
                }
            }
        }

        // Prepare searchable virtual segment slice (filename + doc segments)
        let fname_seg = TextSegment {
            scope: SegmentScope::FileName,
            location_label: "文件名".to_string(),
            text: doc.file_name.clone(),
        };

        let mut hits = Vec::new();
        for rule in candidates {
            metrics.rules_evaluated_stage2 += 1;
            let ctx = EvalContext {
                doc,
                fname_seg: &fname_seg,
                literals: &self.literals,
                regexes: &self.regexes,
                present_lits: &present_lits,
                present_regexes: &present_regexes,
                mode: rule.def.mode,
                max_snippets: max_snippets_per_rule.max(1),
            };
            let mut collector = MatchCollector::default();
            if eval_node(&ctx, &rule.root, FieldScope::Any, &mut collector) {
                collector.snippets.truncate(max_snippets_per_rule.max(1));
                hits.push(HitRecord {
                    doc_id,
                    virtual_path: doc.virtual_path.clone(),
                    file_name: doc.file_name.clone(),
                    detected_format: doc.detected_format.clone(),
                    blake3_hex: doc.blake3_hex.clone(),
                    byte_size: doc.byte_size,
                    modified_unix_ms: 0,
                    rule_id: rule.def.id.clone(),
                    rule_name: rule.def.name.clone(),
                    severity: rule.def.severity.clone(),
                    total_matches: collector.total_matches.max(1),
                    snippets: collector.snippets,
                });
            }
        }

        (hits, metrics)
    }
}

fn compile_expr(
    rule_id: &str,
    expr: &RuleExpr,
    intern_lit: &mut impl FnMut(&str) -> usize,
    intern_regex: &mut impl FnMut(&str, &str) -> Result<usize, CompileError>,
) -> Result<(CompiledNode, AnchorCond), CompileError> {
    match expr {
        RuleExpr::Term { text, case_sensitive } | RuleExpr::Phrase { text, case_sensitive } => {
            let lit_id = intern_lit(text);
            Ok((
                CompiledNode::Literal {
                    lit_id,
                    text: text.clone(),
                    case_sensitive: *case_sensitive,
                },
                AnchorCond::Lit(lit_id),
            ))
        }
        RuleExpr::Regex { pattern } => {
            let regex_id = intern_regex(rule_id, pattern)?;
            Ok((
                CompiledNode::Regex {
                    regex_id,
                    pattern: pattern.clone(),
                },
                AnchorCond::AlwaysPass,
            ))
        }
        RuleExpr::And(items) => {
            let mut nodes = Vec::with_capacity(items.len());
            let mut anchors = Vec::with_capacity(items.len());
            for it in items {
                let (n, a) = compile_expr(rule_id, it, intern_lit, intern_regex)?;
                nodes.push(n);
                anchors.push(a);
            }
            Ok((CompiledNode::And(nodes), AnchorCond::And(anchors)))
        }
        RuleExpr::Or(items) => {
            let mut nodes = Vec::with_capacity(items.len());
            let mut anchors = Vec::with_capacity(items.len());
            for it in items {
                let (n, a) = compile_expr(rule_id, it, intern_lit, intern_regex)?;
                nodes.push(n);
                anchors.push(a);
            }
            Ok((CompiledNode::Or(nodes), AnchorCond::Or(anchors)))
        }
        RuleExpr::Not(inner) => {
            let (n, _) = compile_expr(rule_id, inner, intern_lit, intern_regex)?;
            // Never prune based on NOT in Stage 1
            Ok((CompiledNode::Not(Box::new(n)), AnchorCond::AlwaysPass))
        }
        RuleExpr::AtLeast { min, exprs } => {
            let mut nodes = Vec::with_capacity(exprs.len());
            let mut anchors = Vec::with_capacity(exprs.len());
            for it in exprs {
                let (n, a) = compile_expr(rule_id, it, intern_lit, intern_regex)?;
                nodes.push(n);
                anchors.push(a);
            }
            Ok((
                CompiledNode::AtLeast { min: *min, nodes },
                AnchorCond::AtLeast(*min, anchors),
            ))
        }
        RuleExpr::Scoped { scope, inner } => {
            let (n, a) = compile_expr(rule_id, inner, intern_lit, intern_regex)?;
            Ok((
                CompiledNode::Scoped {
                    scope: *scope,
                    inner: Box::new(n),
                },
                a,
            ))
        }
        RuleExpr::SameLine { terms, case_sensitive } => {
            let mut pairs = Vec::with_capacity(terms.len());
            let mut anchors = Vec::with_capacity(terms.len());
            for t in terms {
                let lit_id = intern_lit(t);
                pairs.push((lit_id, t.clone()));
                anchors.push(AnchorCond::Lit(lit_id));
            }
            Ok((
                CompiledNode::SameLine {
                    terms: pairs,
                    case_sensitive: *case_sensitive,
                },
                AnchorCond::And(anchors),
            ))
        }
        RuleExpr::Near {
            left,
            right,
            max_distance_chars,
            ordered,
            case_sensitive,
        } => {
            let left_id = intern_lit(left);
            let right_id = intern_lit(right);
            Ok((
                CompiledNode::Near {
                    left_id,
                    left_orig: left.clone(),
                    right_id,
                    right_orig: right.clone(),
                    max_distance_chars: *max_distance_chars,
                    ordered: *ordered,
                    case_sensitive: *case_sensitive,
                },
                AnchorCond::And(vec![
                    AnchorCond::Lit(left_id),
                    AnchorCond::Lit(right_id),
                ]),
            ))
        }
    }
}

struct EvalContext<'a> {
    doc: &'a ExtractedDocument,
    fname_seg: &'a TextSegment,
    literals: &'a [String],
    regexes: &'a [Regex],
    present_lits: &'a [bool],
    present_regexes: &'a [bool],
    mode: RuleMatchMode,
    max_snippets: usize,
}

#[derive(Default)]
struct MatchCollector {
    total_matches: usize,
    snippets: Vec<HitLocationSnippet>,
}

fn node_uses_scope(node: &CompiledNode, target: FieldScope) -> bool {
    match node {
        CompiledNode::Scoped { scope, inner } => *scope == target || node_uses_scope(inner, target),
        CompiledNode::And(items) | CompiledNode::Or(items) | CompiledNode::AtLeast { nodes: items, .. } => {
            items.iter().any(|n| node_uses_scope(n, target))
        }
        CompiledNode::Not(inner) => node_uses_scope(inner, target),
        _ => false,
    }
}

fn extract_required_exts(node: &CompiledNode, scope: FieldScope) -> Option<Vec<String>> {
    match node {
        CompiledNode::Scoped { scope: s, inner } => extract_required_exts(inner, *s),
        CompiledNode::And(items) => {
            for it in items {
                if let Some(exts) = extract_required_exts(it, scope) {
                    return Some(exts);
                }
            }
            None
        }
        CompiledNode::Or(items) => {
            let mut union = Vec::new();
            for it in items {
                let exts = extract_required_exts(it, scope)?;
                for e in exts {
                    if !union.contains(&e) {
                        union.push(e);
                    }
                }
            }
            (!union.is_empty()).then_some(union)
        }
        CompiledNode::Regex { pattern, .. } if scope == FieldScope::FileName => {
            parse_trailing_ext_regex(pattern)
        }
        _ => None,
    }
}

fn parse_trailing_ext_regex(pattern: &str) -> Option<Vec<String>> {
    let inner = pattern
        .strip_prefix("(?i:")
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(pattern);
    let rest = inner.strip_prefix(r"\.")?.strip_suffix('$')?;
    let alts = rest
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(rest);
    let mut exts = Vec::new();
    for part in alts.split('|') {
        let p = part.trim().to_ascii_lowercase();
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return None;
        }
        exts.push(p);
    }
    (!exts.is_empty()).then_some(exts)
}

fn scope_matches(filter: FieldScope, seg_scope: SegmentScope) -> bool {
    match filter {
        FieldScope::Any => true,
        FieldScope::FileName => seg_scope == SegmentScope::FileName,
        FieldScope::HeadTail => seg_scope == SegmentScope::HeadTail,
        FieldScope::Body => matches!(seg_scope, SegmentScope::Body | SegmentScope::Comment),
        FieldScope::Ocr => seg_scope == SegmentScope::Ocr,
        FieldScope::Table => seg_scope == SegmentScope::Table,
        FieldScope::Metadata => seg_scope == SegmentScope::Metadata,
    }
}

fn iter_matching_segments<'a>(
    ctx: &'a EvalContext<'a>,
    scope: FieldScope,
) -> impl Iterator<Item = &'a TextSegment> {
    std::iter::once(ctx.fname_seg)
        .chain(ctx.doc.segments.iter())
        .filter(move |seg| scope_matches(scope, seg.scope))
}

fn make_snippet(
    seg: &TextSegment,
    matched_term: &str,
    byte_start: usize,
    byte_end: usize,
) -> HitLocationSnippet {
    let text = &seg.text;
    let prefix_char_idx = text[..byte_start].chars().count();
    let match_len_char = text[byte_start..byte_end].chars().count();

    let all_chars: Vec<(usize, char)> = text.char_indices().collect();
    let ctx_before = 35usize;
    let ctx_after = 55usize;
    let win_start_ci = prefix_char_idx.saturating_sub(ctx_before);
    let win_end_ci = (prefix_char_idx + match_len_char + ctx_after).min(all_chars.len());

    let byte_win_start = all_chars.get(win_start_ci).map(|&(b, _)| b).unwrap_or(0);
    let byte_win_end = if win_end_ci >= all_chars.len() {
        text.len()
    } else {
        all_chars[win_end_ci].0
    };

    let mut snippet = String::new();
    let mut lead_chars = 0usize;
    if win_start_ci > 0 {
        snippet.push_str("...");
        lead_chars = 3;
    }
    let slice_clean: String = text[byte_win_start..byte_win_end]
        .chars()
        .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
        .collect();
    snippet.push_str(&slice_clean);
    if win_end_ci < all_chars.len() {
        snippet.push_str("...");
    }

    let match_start_char = lead_chars + (prefix_char_idx - win_start_ci);

    HitLocationSnippet {
        scope: seg.scope,
        location_label: seg.location_label.clone(),
        matched_term: matched_term.to_string(),
        snippet,
        match_start_char,
        match_len_char,
    }
}

/// Safe case-insensitive literal find when lowercased char boundaries may shift only in exotic Unicode;
/// falls back to lowercase string match and maps back gracefully.
fn find_literal_occurrences(
    haystack: &str,
    needle_orig: &str,
    needle_lower: &str,
    case_sensitive: bool,
    limit: usize,
) -> Vec<(usize, usize)> {
    let mut hits = Vec::new();
    if needle_orig.is_empty() {
        return hits;
    }
    if case_sensitive {
        let mut start = 0;
        while let Some(pos) = haystack[start..].find(needle_orig) {
            let abs = start + pos;
            hits.push((abs, abs + needle_orig.len()));
            if hits.len() >= limit {
                break;
            }
            start = abs + needle_orig.len().max(1);
        }
    } else {
        // Check ASCII fast-path first; for Unicode strings, search lowercased buffer
        let hay_lower = haystack.to_lowercase();
        if hay_lower.len() == haystack.len() {
            let mut start = 0;
            while let Some(pos) = hay_lower[start..].find(needle_lower) {
                let abs = start + pos;
                let end = (abs + needle_lower.len()).min(haystack.len());
                if haystack.is_char_boundary(abs) && haystack.is_char_boundary(end) {
                    hits.push((abs, end));
                }
                if hits.len() >= limit {
                    break;
                }
                start = abs + needle_lower.len().max(1);
            }
        } else {
            // Map char positions safely
            let mut start = 0;
            while let Some(pos) = hay_lower[start..].find(needle_lower) {
                let abs_l = start + pos;
                let char_start = hay_lower[..abs_l].chars().count();
                let char_len = needle_lower.chars().count();
                let byte_start = haystack
                    .char_indices()
                    .nth(char_start)
                    .map(|(b, _)| b)
                    .unwrap_or(0);
                let byte_end = haystack
                    .char_indices()
                    .nth(char_start + char_len)
                    .map(|(b, _)| b)
                    .unwrap_or(haystack.len());
                hits.push((byte_start, byte_end));
                if hits.len() >= limit {
                    break;
                }
                start = abs_l + needle_lower.len().max(1);
            }
        }
    }
    hits
}

fn eval_node(
    ctx: &EvalContext<'_>,
    node: &CompiledNode,
    scope: FieldScope,
    out: &mut MatchCollector,
) -> bool {
    match node {
        CompiledNode::Literal {
            lit_id,
            text,
            case_sensitive,
        } => {
            if !ctx.present_lits[*lit_id] {
                return false;
            }
            let needle_lower = &ctx.literals[*lit_id];
            let mut matched = false;
            let per_seg_limit = if ctx.mode == RuleMatchMode::FirstHit {
                1
            } else {
                32
            };
            for seg in iter_matching_segments(ctx, scope) {
                let occs = find_literal_occurrences(
                    &seg.text,
                    text,
                    needle_lower,
                    *case_sensitive,
                    per_seg_limit,
                );
                if !occs.is_empty() {
                    matched = true;
                    out.total_matches += occs.len();
                    for (bs, be) in occs {
                        if out.snippets.len() < ctx.max_snippets {
                            out.snippets.push(make_snippet(seg, text, bs, be));
                        }
                    }
                    if ctx.mode == RuleMatchMode::FirstHit {
                        return true;
                    }
                }
            }
            matched
        }
        CompiledNode::Regex { regex_id, pattern } => {
            if !ctx.present_regexes[*regex_id] {
                return false;
            }
            let re = &ctx.regexes[*regex_id];
            let mut matched = false;
            for seg in iter_matching_segments(ctx, scope) {
                for m in re.find_iter(&seg.text) {
                    matched = true;
                    out.total_matches += 1;
                    if out.snippets.len() < ctx.max_snippets {
                        out.snippets
                            .push(make_snippet(seg, pattern, m.start(), m.end()));
                    }
                    if ctx.mode == RuleMatchMode::FirstHit {
                        return true;
                    }
                }
            }
            matched
        }
        CompiledNode::And(children) => {
            let mut sub = MatchCollector::default();
            for ch in children {
                if !eval_node(ctx, ch, scope, &mut sub) {
                    return false;
                }
            }
            out.total_matches += sub.total_matches;
            for s in sub.snippets {
                if out.snippets.len() < ctx.max_snippets {
                    out.snippets.push(s);
                }
            }
            true
        }
        CompiledNode::Or(children) => {
            let mut any = false;
            for ch in children {
                if eval_node(ctx, ch, scope, out) {
                    any = true;
                    if ctx.mode == RuleMatchMode::FirstHit {
                        return true;
                    }
                }
            }
            any
        }
        CompiledNode::Not(inner) => {
            let mut throwaway = MatchCollector::default();
            let hit = eval_node(ctx, inner, scope, &mut throwaway);
            !hit
        }
        CompiledNode::AtLeast { min, nodes } => {
            let mut count = 0usize;
            let mut sub = MatchCollector::default();
            for n in nodes {
                let mut tmp = MatchCollector::default();
                if eval_node(ctx, n, scope, &mut tmp) {
                    count += 1;
                    sub.total_matches += tmp.total_matches;
                    sub.snippets.extend(tmp.snippets);
                    if count >= *min && ctx.mode == RuleMatchMode::FirstHit {
                        out.total_matches += sub.total_matches;
                        for s in sub.snippets {
                            if out.snippets.len() < ctx.max_snippets {
                                out.snippets.push(s);
                            }
                        }
                        return true;
                    }
                }
            }
            if count >= *min {
                out.total_matches += sub.total_matches;
                for s in sub.snippets {
                    if out.snippets.len() < ctx.max_snippets {
                        out.snippets.push(s);
                    }
                }
                true
            } else {
                false
            }
        }
        CompiledNode::Scoped { scope: inner_scope, inner } => {
            let effective = if scope == FieldScope::Any {
                *inner_scope
            } else if scope == *inner_scope {
                scope
            } else {
                // Conflicting nested scopes cannot both match
                return false;
            };
            eval_node(ctx, inner, effective, out)
        }
        CompiledNode::SameLine {
            terms,
            case_sensitive,
        } => {
            for (lit_id, _) in terms {
                if !ctx.present_lits[*lit_id] {
                    return false;
                }
            }
            let mut matched = false;
            for seg in iter_matching_segments(ctx, scope) {
                let mut offset_base = 0usize;
                for line in seg.text.split('\n') {
                    let all_in_line = terms.iter().all(|(lid, orig)| {
                        !find_literal_occurrences(
                            line,
                            orig,
                            &ctx.literals[*lid],
                            *case_sensitive,
                            1,
                        )
                        .is_empty()
                    });
                    if all_in_line {
                        matched = true;
                        out.total_matches += 1;
                        if out.snippets.len() < ctx.max_snippets {
                            let first = &terms[0];
                            if let Some((bs, be)) = find_literal_occurrences(
                                line,
                                &first.1,
                                &ctx.literals[first.0],
                                *case_sensitive,
                                1,
                            )
                            .into_iter()
                            .next()
                            {
                                let abs_bs = offset_base + bs;
                                let abs_be = offset_base + be;
                                out.snippets.push(make_snippet(
                                    seg,
                                    &terms
                                        .iter()
                                        .map(|(_, t)| t.as_str())
                                        .collect::<Vec<_>>()
                                        .join(" + "),
                                    abs_bs,
                                    abs_be,
                                ));
                            }
                        }
                        if ctx.mode == RuleMatchMode::FirstHit {
                            return true;
                        }
                    }
                    offset_base += line.len() + 1;
                }
            }
            matched
        }
        CompiledNode::Near {
            left_id,
            left_orig,
            right_id,
            right_orig,
            max_distance_chars,
            ordered,
            case_sensitive,
        } => {
            if !ctx.present_lits[*left_id] || !ctx.present_lits[*right_id] {
                return false;
            }
            let left_lower = &ctx.literals[*left_id];
            let right_lower = &ctx.literals[*right_id];
            let mut matched = false;
            for seg in iter_matching_segments(ctx, scope) {
                let left_occs =
                    find_literal_occurrences(&seg.text, left_orig, left_lower, *case_sensitive, 64);
                if left_occs.is_empty() {
                    continue;
                }
                let right_occs = find_literal_occurrences(
                    &seg.text,
                    right_orig,
                    right_lower,
                    *case_sensitive,
                    64,
                );
                if right_occs.is_empty() {
                    continue;
                }
                let left_spans = map_byte_spans_to_chars(&seg.text, &left_occs);
                let right_spans = map_byte_spans_to_chars(&seg.text, &right_occs);
                let label = format!("{left_orig} ~ {right_orig}");
                for &(lbs, lbe, lcs, lce) in &left_spans {
                    for &(rbs, rbe, rcs, rce) in &right_spans {
                        let within = if *ordered {
                            rcs >= lce && rcs - lce <= *max_distance_chars
                        } else if rcs >= lce {
                            rcs - lce <= *max_distance_chars
                        } else if lcs >= rce {
                            lcs - rce <= *max_distance_chars
                        } else {
                            // Overlapping occurrences
                            true
                        };
                        if within {
                            matched = true;
                            out.total_matches += 1;
                            if out.snippets.len() < ctx.max_snippets {
                                let span_bs = lbs.min(rbs);
                                let span_be = lbe.max(rbe);
                                out.snippets.push(make_snippet(
                                    seg,
                                    &label,
                                    span_bs,
                                    span_be,
                                ));
                            }
                            if ctx.mode == RuleMatchMode::FirstHit {
                                return true;
                            }
                        }
                    }
                }
            }
            matched
        }
    }
}

fn map_byte_spans_to_chars(
    text: &str,
    spans: &[(usize, usize)],
) -> Vec<(usize, usize, usize, usize)> {
    // Build byte-offset -> char-index lookup once per segment evaluation.
    let mut byte_to_ci = Vec::with_capacity(spans.len() * 2);
    for &(bs, be) in spans {
        byte_to_ci.push((bs, 0usize));
        byte_to_ci.push((be, 0usize));
    }
    let mut ci_map = std::collections::HashMap::with_capacity(byte_to_ci.len());
    for (ci, (b, _)) in text.char_indices().enumerate() {
        ci_map.insert(b, ci);
    }
    let total_chars = text.chars().count();
    ci_map.insert(text.len(), total_chars);
    spans
        .iter()
        .map(|&(bs, be)| {
            let cs = ci_map
                .get(&bs)
                .copied()
                .unwrap_or_else(|| text[..bs].chars().count());
            let ce = ci_map
                .get(&be)
                .copied()
                .unwrap_or_else(|| text[..be].chars().count());
            (bs, be, cs, ce)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc() -> ExtractedDocument {
        ExtractedDocument {
            virtual_path: r"D:\archive.zip!\内部预算.xlsx".into(),
            file_name: "内部预算.xlsx".into(),
            detected_format: "xlsx".into(),
            blake3_hex: "abc".into(),
            byte_size: 1024,
            encrypted: false,
            segments: vec![
                TextSegment {
                    scope: SegmentScope::HeadTail,
                    location_label: "文档首部".into(),
                    text: "绝密 ★ 10年\n关于年度采购方案的请示".into(),
                },
                TextSegment {
                    scope: SegmentScope::Table,
                    location_label: "Sheet[预算表] 行18".into(),
                    text: "安全专项 | 预算金额 500万元 | 非公开".into(),
                },
                TextSegment {
                    scope: SegmentScope::Ocr,
                    location_label: "word/media/image1.png (OCR)".into(),
                    text: "盖章确认：研发核心参数".into(),
                },
            ],
            metadata: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn boolean_and_regex_and_scope_eval() {
        let rs = RuleSet {
            ruleset_id: "r1".into(),
            rules: vec![
                RuleDefinition {
                    id: "rule-bool".into(),
                    name: "敏感预算".into(),
                    category: "涉密".into(),
                    severity: "High".into(),
                    expression: r#"("预算金额" | "招标") & scope:ocr("研发核心") & !公开测试"#.into(),
                    mode: RuleMatchMode::FullHits,
                },
                RuleDefinition {
                    id: "rule-re".into(),
                    name: "红头密级".into(),
                    category: "公文".into(),
                    severity: "Critical".into(),
                    expression: r#"scope:head_tail(re:/绝密\s*★/)"#.into(),
                    mode: RuleMatchMode::FirstHit,
                },
                RuleDefinition {
                    id: "rule-pruned".into(),
                    name: "会被Stage1剪枝".into(),
                    category: "常规".into(),
                    severity: "Low".into(),
                    expression: r#""绝对不存在的关键词" & 预算"#.into(),
                    mode: RuleMatchMode::FirstHit,
                },
                RuleDefinition {
                    id: "rule-atleast".into(),
                    name: "至少命中两词".into(),
                    category: "组合".into(),
                    severity: "Medium".into(),
                    expression: r#"ATLEAST(2, 绝密, 研发核心, 不存在词)"#.into(),
                    mode: RuleMatchMode::FullHits,
                },
                RuleDefinition {
                    id: "rule-sameline".into(),
                    name: "同行共现".into(),
                    category: "表格".into(),
                    severity: "High".into(),
                    expression: r#"SAMELINE(安全专项, 500万元)"#.into(),
                    mode: RuleMatchMode::FirstHit,
                },
                RuleDefinition {
                    id: "rule-near-hit".into(),
                    name: "邻近匹配".into(),
                    category: "邻近".into(),
                    severity: "High".into(),
                    expression: r#"NEAR(非公开, 安全专项, 20)"#.into(),
                    mode: RuleMatchMode::FirstHit,
                },
                RuleDefinition {
                    id: "rule-onear-miss".into(),
                    name: "有序邻近未命中".into(),
                    category: "邻近".into(),
                    severity: "High".into(),
                    expression: r#"ONEAR(非公开, 安全专项, 20)"#.into(),
                    mode: RuleMatchMode::FirstHit,
                },
                RuleDefinition {
                    id: "rule-onear-hit".into(),
                    name: "有序邻近命中".into(),
                    category: "邻近".into(),
                    severity: "High".into(),
                    expression: r#"ONEAR(安全专项, 500万元, 10)"#.into(),
                    mode: RuleMatchMode::FirstHit,
                },
                RuleDefinition {
                    id: "rule-filename-regex-i".into(),
                    name: "文件名正则标志".into(),
                    category: "文件名".into(),
                    severity: "Hit".into(),
                    expression: r#"scope:filename(re:/\.XLSX$/i) & scope:table(re:/[\u4e00-\u9fff]{2,}/)"#.into(),
                    mode: RuleMatchMode::FirstHit,
                },
            ],
        };
        let compiled = CompiledRuleSet::compile(&rs).unwrap();
        let doc = sample_doc();
        let (hits, metrics) = compiled.evaluate_document(42, &doc, 5);
        assert_eq!(metrics.rules_checked, 9);
        assert_eq!(metrics.rules_pruned_stage1, 1);
        assert_eq!(hits.len(), 7);
        assert!(hits.iter().any(|h| h.rule_id == "rule-bool"));
        assert!(hits.iter().any(|h| h.rule_id == "rule-re"));
        assert!(hits.iter().any(|h| h.rule_id == "rule-atleast"));
        assert!(hits.iter().any(|h| h.rule_id == "rule-sameline"));
        assert!(hits.iter().any(|h| h.rule_id == "rule-near-hit"));
        assert!(hits.iter().any(|h| h.rule_id == "rule-onear-hit"));
        assert!(hits.iter().any(|h| h.rule_id == "rule-filename-regex-i"));
        assert!(!hits.iter().any(|h| h.rule_id == "rule-onear-miss"));
        assert!(compiled.has_filename_scope());

        let single_ext_rs = RuleSet {
            ruleset_id: "ext".into(),
            rules: vec![RuleDefinition {
                id: "dwg".into(),
                name: "dwg".into(),
                category: "c".into(),
                severity: "s".into(),
                expression: r#"scope:filename(re:/\.(DWG|DXF)$/i) & "给水""#.into(),
                mode: RuleMatchMode::FirstHit,
            }],
        };
        let single_ext = CompiledRuleSet::compile(&single_ext_rs).unwrap();
        assert_eq!(
            single_ext.prefilter_file_extensions(),
            Some(vec!["dwg".to_string(), "dxf".to_string()])
        );
    }
}
