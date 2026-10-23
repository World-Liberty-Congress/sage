//! Model-facing views over Admin Config reads.
//!
//! The Python control plane returns complete Admin Config data to Sage. These
//! views turn that data into scoped, paged Tool results that fit the
//! per-result Tool budget, so a question about one User Type, Document, or
//! setting never depends on a whole-area dump the model cannot receive.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{json, Map, Value};

use crate::sage_agent::ToolArgs;

/// Upper bound for one Admin Config read result, envelope included. It sits
/// below the 4,000-character per-result ceiling so up to four reads can share
/// one Tool batch (12,000 characters) without truncation.
pub(crate) const READ_RESULT_BUDGET_CHARS: usize = 3_000;

/// Long text in list rows is shortened to this many characters. Naming the
/// setting in `keys`, or the User Type in `user_type`, returns full text.
const PREVIEW_CHARS: usize = 160;
const MAX_PAGE_ROWS: usize = 50;
const MAX_LISTED_NAMES: usize = 20;
const MAX_LISTED_OPTIONS: usize = 25;
const MAX_KEYS: usize = 20;
const MAX_KEY_CHARS: usize = 64;
/// A scoped User Type description is shown in full up to this length.
const MAX_DESCRIPTION_CHARS: usize = 1_000;
const MAX_OFFSET: u64 = 100_000;
const MAX_TEXT_ARG_CHARS: usize = 200;
/// Allowance for the page object growing between the size estimate and the
/// final render (for example `null` replacing a short number).
const PAGE_SLACK_CHARS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadViewError {
    /// The model supplied unusable arguments; the message explains the fix.
    InvalidArguments(String),
    /// The control plane returned data in an unexpected shape.
    MalformedData,
}

impl ReadViewError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidArguments(_) => "invalid_arguments",
            Self::MalformedData => "execution_failed",
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::InvalidArguments(message) => message.clone(),
            Self::MalformedData => "Admin Config returned data in an unexpected shape.".to_string(),
        }
    }
}

type ViewResult = Result<Value, ReadViewError>;

fn invalid(message: impl Into<String>) -> ReadViewError {
    ReadViewError::InvalidArguments(message.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccessFilter {
    Available,
    Unavailable,
    DefaultActive,
}

impl AccessFilter {
    fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::DefaultActive => "default_active",
        }
    }

    fn matches(self, document: &Value) -> bool {
        match self {
            Self::Available => is_effectively_available(document),
            Self::Unavailable => !is_effectively_available(document),
            Self::DefaultActive => is_effectively_default_active(document),
        }
    }
}

/// Matches the control plane: only completed Documents count as available.
fn is_ready(document: &Value) -> bool {
    matches!(
        document.get("status").and_then(Value::as_str),
        Some("completed" | "completed_with_errors")
    )
}

fn is_effectively_available(document: &Value) -> bool {
    bool_at(document, "is_available") && is_ready(document)
}

fn is_effectively_default_active(document: &Value) -> bool {
    is_effectively_available(document) && bool_at(document, "is_default_active")
}

/// How the model named a User Type. JSON numbers are ids; text matches a
/// name first and then a numeric id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UserTypeRef {
    Id(i64),
    Text(String),
}

impl UserTypeRef {
    fn label(&self) -> String {
        match self {
            Self::Id(id) => id.to_string(),
            Self::Text(text) => text.clone(),
        }
    }
}

/// Parsed, validated arguments for one Admin Config read.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct ReadArgs {
    pub(crate) user_type: Option<UserTypeRef>,
    pub(crate) document: Option<String>,
    pub(crate) access: Option<AccessFilter>,
    pub(crate) category: Option<String>,
    pub(crate) keys: Option<Vec<String>>,
    pub(crate) offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadArg {
    UserType,
    Document,
    Access,
    Category,
    Keys,
    Offset,
}

impl ReadArg {
    fn name(self) -> &'static str {
        match self {
            Self::UserType => "user_type",
            Self::Document => "document",
            Self::Access => "access",
            Self::Category => "category",
            Self::Keys => "keys",
            Self::Offset => "offset",
        }
    }

    fn schema(self) -> Value {
        match self {
            Self::UserType => json!({
                "type": "string",
                "description": "User Type name or numeric id. Omit for global values and all User Types."
            }),
            Self::Document => json!({
                "type": "string",
                "description": "Only Documents whose job_id equals this or whose filename contains this text (case-insensitive)."
            }),
            Self::Access => json!({
                "type": "string",
                "enum": ["available", "unavailable", "default_active"],
                "description": "Only Documents with this effective access. Only completed Documents count as available; default_active means available and on by default."
            }),
            Self::Category => json!({
                "type": "string",
                "description": "Only settings in this category, as listed in summary.categories."
            }),
            Self::Keys => json!({
                "type": "array",
                "items": {"type": "string"},
                "description": "Only these setting keys, returned with full untruncated values."
            }),
            Self::Offset => json!({
                "type": "integer",
                "minimum": 0,
                "description": "Continue a paged result from the previous page.next_offset."
            }),
        }
    }
}

/// One model-callable Admin Config read and the arguments it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadView {
    InstanceSettings,
    DeploymentSettings,
    DeploymentReadiness,
    AgentSettings,
    UserTypes,
    DocumentAccess,
    OnboardingStatus,
}

impl ReadView {
    fn arguments(self) -> &'static [ReadArg] {
        match self {
            Self::InstanceSettings => &[ReadArg::Keys, ReadArg::Offset],
            Self::DeploymentSettings => &[ReadArg::Category, ReadArg::Keys, ReadArg::Offset],
            Self::DeploymentReadiness | Self::OnboardingStatus => &[],
            Self::AgentSettings => &[ReadArg::UserType, ReadArg::Keys, ReadArg::Offset],
            Self::UserTypes => &[ReadArg::UserType, ReadArg::Offset],
            Self::DocumentAccess => &[
                ReadArg::UserType,
                ReadArg::Document,
                ReadArg::Access,
                ReadArg::Offset,
            ],
        }
    }

    pub(crate) fn native_parameters(self) -> Value {
        let properties = self
            .arguments()
            .iter()
            .map(|arg| (arg.name().to_string(), arg.schema()))
            .collect::<Map<_, _>>();
        json!({
            "type": "object",
            "properties": properties,
            "additionalProperties": false,
        })
    }

    pub(crate) fn parse_args(self, args: &ToolArgs) -> Result<ReadArgs, ReadViewError> {
        let allowed = self.arguments();
        let mut names = args.keys().collect::<Vec<_>>();
        names.sort();
        let mut parsed = ReadArgs::default();
        for name in names {
            let value = &args[name];
            if value.is_null() {
                continue;
            }
            let Some(arg) = allowed.iter().copied().find(|arg| arg.name() == name) else {
                return Err(invalid(format!(
                    "Unsupported argument `{}`. {}",
                    name,
                    supported_arguments_sentence(allowed)
                )));
            };
            match arg {
                ReadArg::UserType => parsed.user_type = user_type_arg(value)?,
                ReadArg::Document => parsed.document = text_arg(arg, value)?,
                ReadArg::Category => parsed.category = text_arg(arg, value)?,
                ReadArg::Access => parsed.access = access_arg(value)?,
                ReadArg::Keys => parsed.keys = keys_arg(value)?,
                ReadArg::Offset => parsed.offset = offset_arg(value)?,
            }
        }
        Ok(parsed)
    }

    /// Shapes complete control-plane `data` for the model within `budget`
    /// characters.
    pub(crate) fn apply(self, data: &Value, args: &ReadArgs, budget: usize) -> ViewResult {
        match self {
            Self::InstanceSettings => instance_settings_view(data, args, budget),
            Self::DeploymentSettings => deployment_settings_view(data, args, budget),
            Self::DeploymentReadiness => deployment_readiness_view(data),
            Self::AgentSettings => agent_settings_view(
                &AgentSettingsSnapshot::from_control_plane(data)?,
                args,
                budget,
            ),
            Self::UserTypes => user_types_view(data, args, budget),
            Self::DocumentAccess => document_access_view(data, args, budget),
            Self::OnboardingStatus => onboarding_status_view(data),
        }
    }
}

fn supported_arguments_sentence(allowed: &[ReadArg]) -> String {
    if allowed.is_empty() {
        "This Tool takes no arguments.".to_string()
    } else {
        format!(
            "Supported arguments: {}.",
            allowed
                .iter()
                .map(|arg| arg.name())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn user_type_arg(value: &Value) -> Result<Option<UserTypeRef>, ReadViewError> {
    match value {
        Value::String(text) if text.chars().count() <= MAX_TEXT_ARG_CHARS => {
            Ok(non_empty(text).map(UserTypeRef::Text))
        }
        Value::Number(number) => number
            .as_i64()
            .filter(|id| *id >= 0)
            .map(|id| Some(UserTypeRef::Id(id)))
            .ok_or_else(|| invalid("user_type must be a User Type name or numeric id.")),
        _ => Err(invalid("user_type must be a User Type name or numeric id.")),
    }
}

fn text_arg(arg: ReadArg, value: &Value) -> Result<Option<String>, ReadViewError> {
    let Value::String(text) = value else {
        return Err(invalid(format!("{} must be a string.", arg.name())));
    };
    if text.chars().count() > MAX_TEXT_ARG_CHARS {
        return Err(invalid(format!(
            "{} must be at most {} characters.",
            arg.name(),
            MAX_TEXT_ARG_CHARS
        )));
    }
    Ok(non_empty(text))
}

fn access_arg(value: &Value) -> Result<Option<AccessFilter>, ReadViewError> {
    match value.as_str().map(str::trim) {
        Some("") => Ok(None),
        Some("available") => Ok(Some(AccessFilter::Available)),
        Some("unavailable") => Ok(Some(AccessFilter::Unavailable)),
        Some("default_active") => Ok(Some(AccessFilter::DefaultActive)),
        _ => Err(invalid(
            "access must be one of: available, unavailable, default_active.",
        )),
    }
}

fn keys_arg(value: &Value) -> Result<Option<Vec<String>>, ReadViewError> {
    let values = match value {
        Value::String(text) => vec![Value::String(text.clone())],
        Value::Array(values) => values.clone(),
        _ => return Err(invalid("keys must be an array of setting keys.")),
    };
    let mut keys = Vec::new();
    for value in values {
        let Value::String(text) = value else {
            return Err(invalid("keys must be an array of setting keys."));
        };
        if text.chars().count() > MAX_KEY_CHARS {
            return Err(invalid(format!(
                "Each key must be at most {} characters.",
                MAX_KEY_CHARS
            )));
        }
        if let Some(key) = non_empty(&text) {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
    }
    if keys.len() > MAX_KEYS {
        return Err(invalid(format!("keys accepts at most {} keys.", MAX_KEYS)));
    }
    Ok((!keys.is_empty()).then_some(keys))
}

fn offset_arg(value: &Value) -> Result<usize, ReadViewError> {
    let offset = match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    };
    match offset {
        Some(offset) if offset <= MAX_OFFSET => Ok(offset as usize),
        _ => Err(invalid(
            "offset must be a non-negative integer taken from page.next_offset.",
        )),
    }
}

fn non_empty(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// Serialized size as the Tool loop measures it.
pub(crate) fn char_len(value: &Value) -> usize {
    value.to_string().chars().count()
}

/// Adds `rows[offset..]` under `list_key` until the object would exceed
/// `budget` characters. At least one row is always included so paging makes
/// progress; `page.next_offset` continues the list.
fn paged(
    mut fixed: Map<String, Value>,
    list_key: &str,
    rows: Vec<Value>,
    offset: usize,
    budget: usize,
) -> Value {
    let total = rows.len();
    let start = offset.min(total);
    let page = |returned: usize| {
        let next = start + returned;
        let has_more = next < total;
        json!({
            "offset": start,
            "returned": returned,
            "total_count": total,
            "has_more": has_more,
            "next_offset": if has_more { Value::from(next) } else { Value::Null },
        })
    };

    fixed.insert(list_key.to_string(), Value::Array(Vec::new()));
    fixed.insert("page".to_string(), page(0));
    let mut used = char_len(&Value::Object(fixed.clone())) + PAGE_SLACK_CHARS;
    let mut taken = Vec::new();
    for row in rows.into_iter().skip(start) {
        let cost = char_len(&row) + usize::from(!taken.is_empty());
        if !taken.is_empty() && (taken.len() >= MAX_PAGE_ROWS || used + cost > budget) {
            break;
        }
        used += cost;
        taken.push(row);
    }
    let returned = taken.len();
    fixed.insert(list_key.to_string(), Value::Array(taken));
    fixed.insert("page".to_string(), page(returned));
    Value::Object(fixed)
}

/// Shortens long string fields and records which ones were shortened.
fn shorten(row: &mut Map<String, Value>, fields: &[&str]) {
    shorten_to(row, fields, PREVIEW_CHARS);
}

fn shorten_to(row: &mut Map<String, Value>, fields: &[&str], limit: usize) {
    let mut truncated = Vec::new();
    for field in fields {
        if let Some(Value::String(text)) = row.get_mut(*field) {
            if text.chars().count() > limit {
                let mut short = text.chars().take(limit - 1).collect::<String>();
                short.push('…');
                *text = short;
                truncated.push(Value::from(*field));
            }
        }
    }
    if !truncated.is_empty() {
        row.insert("truncated".to_string(), Value::Array(truncated));
    }
}

fn copy_fields(source: &Value, fields: &[&str]) -> Map<String, Value> {
    fields
        .iter()
        .filter_map(|field| {
            source
                .get(*field)
                .map(|value| (field.to_string(), value.clone()))
        })
        .collect()
}

fn bool_at(value: &Value, field: &str) -> bool {
    value.get(field).and_then(Value::as_bool).unwrap_or(false)
}

fn listed_names(names: &[String]) -> Value {
    Value::from(
        names
            .iter()
            .take(MAX_LISTED_NAMES)
            .cloned()
            .collect::<Vec<_>>(),
    )
}

fn names_sentence(label: &str, names: &[String]) -> String {
    if names.is_empty() {
        return format!("No {} are configured.", label);
    }
    let mut sentence = format!(
        "Known {}: {}",
        label,
        names
            .iter()
            .take(MAX_LISTED_NAMES * 3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );
    if names.len() > MAX_LISTED_NAMES * 3 {
        sentence.push_str(&format!(
            ", and {} more",
            names.len() - MAX_LISTED_NAMES * 3
        ));
    }
    sentence.push('.');
    sentence
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NamedUserType {
    id: i64,
    name: String,
}

impl NamedUserType {
    fn to_json(&self) -> Value {
        json!({"id": self.id, "name": self.name})
    }
}

fn resolve_user_type<'a>(
    user_types: &'a [NamedUserType],
    reference: &UserTypeRef,
) -> Result<&'a NamedUserType, ReadViewError> {
    let by_id = |id: i64| user_types.iter().find(|user_type| user_type.id == id);
    match reference {
        UserTypeRef::Id(id) => by_id(*id),
        UserTypeRef::Text(text) => {
            let wanted = text.trim().to_lowercase();
            user_types
                .iter()
                .find(|user_type| user_type.name.trim().to_lowercase() == wanted)
                .or_else(|| wanted.parse::<i64>().ok().and_then(by_id))
        }
    }
    .ok_or_else(|| {
        let names = user_types
            .iter()
            .map(|user_type| format!("{} (id {})", user_type.name, user_type.id))
            .collect::<Vec<_>>();
        invalid(format!(
            "Unknown User Type \"{}\". {}",
            reference.label().trim(),
            names_sentence("User Types", &names)
        ))
    })
}

/// Returns the requested keys that do not exist. A request where no key
/// exists is rejected with the valid keys so the model can correct it; a
/// partial match still answers for the keys that do exist.
fn unknown_keys(
    keys: Option<&Vec<String>>,
    known: &[String],
    label: &str,
) -> Result<Vec<String>, ReadViewError> {
    let Some(keys) = keys else {
        return Ok(Vec::new());
    };
    let unknown = keys
        .iter()
        .filter(|key| !known.contains(key))
        .cloned()
        .collect::<Vec<_>>();
    if unknown.len() < keys.len() {
        return Ok(unknown);
    }
    Err(invalid(format!(
        "Unknown {} key(s): {}. {}",
        label,
        unknown.join(", "),
        names_sentence("keys", known)
    )))
}

fn with_unknown_keys(mut scope: Value, unknown: Vec<String>) -> Value {
    if let (Value::Object(object), false) = (&mut scope, unknown.is_empty()) {
        object.insert("unknown_keys".to_string(), Value::from(unknown));
    }
    scope
}

fn scope(user_type: Option<&NamedUserType>, args: &ReadArgs) -> Value {
    let mut scope = Map::new();
    if let Some(user_type) = user_type {
        scope.insert("user_type".to_string(), user_type.to_json());
    }
    if let Some(document) = &args.document {
        scope.insert("document".to_string(), Value::from(document.clone()));
    }
    if let Some(access) = args.access {
        scope.insert("access".to_string(), Value::from(access.as_str()));
    }
    if let Some(category) = &args.category {
        scope.insert("category".to_string(), Value::from(category.clone()));
    }
    Value::Object(scope)
}

fn fixed(scope: Value, summary: Map<String, Value>) -> Map<String, Value> {
    Map::from_iter([
        ("scope".to_string(), scope),
        ("summary".to_string(), Value::Object(summary)),
    ])
}

fn instance_settings_view(data: &Value, args: &ReadArgs, budget: usize) -> ViewResult {
    let fields = data
        .get("fields")
        .and_then(Value::as_array)
        .ok_or(ReadViewError::MalformedData)?;
    let known = fields
        .iter()
        .filter_map(|field| field.get("key").and_then(Value::as_str).map(str::to_string))
        .collect::<Vec<_>>();
    let unknown = unknown_keys(args.keys.as_ref(), &known, "Instance Setting")?;

    let summary = Map::from_iter([
        ("settings".to_string(), Value::from(fields.len())),
        (
            "operator_set".to_string(),
            Value::from(
                fields
                    .iter()
                    .filter(|field| field.get("source").and_then(Value::as_str) == Some("operator"))
                    .count(),
            ),
        ),
    ]);
    let rows = fields
        .iter()
        .filter(|field| match &args.keys {
            Some(keys) => field
                .get("key")
                .and_then(Value::as_str)
                .is_some_and(|key| keys.iter().any(|wanted| wanted == key)),
            None => true,
        })
        .map(|field| {
            if args.keys.is_some() {
                return field.clone();
            }
            let mut row = copy_fields(field, &["key", "value", "source"]);
            shorten(&mut row, &["value"]);
            Value::Object(row)
        })
        .collect();
    Ok(paged(
        fixed(with_unknown_keys(scope(None, args), unknown), summary),
        "settings",
        rows,
        args.offset,
        budget,
    ))
}

fn deployment_settings_view(data: &Value, args: &ReadArgs, budget: usize) -> ViewResult {
    let settings = data
        .get("settings")
        .and_then(Value::as_object)
        .ok_or(ReadViewError::MalformedData)?;
    let category_of = |setting: &Value| {
        setting
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("general")
            .to_string()
    };

    let mut categories = BTreeMap::<String, usize>::new();
    for setting in settings.values() {
        *categories.entry(category_of(setting)).or_default() += 1;
    }
    let category = match &args.category {
        Some(wanted) => Some(
            categories
                .keys()
                .find(|name| name.eq_ignore_ascii_case(wanted))
                .cloned()
                .ok_or_else(|| {
                    invalid(format!(
                        "Unknown Deployment Setting category \"{}\". {}",
                        wanted,
                        names_sentence(
                            "categories",
                            &categories.keys().cloned().collect::<Vec<_>>()
                        )
                    ))
                })?,
        ),
        None => None,
    };
    let unknown = unknown_keys(
        args.keys.as_ref(),
        &settings.keys().cloned().collect::<Vec<_>>(),
        "Deployment Setting",
    )?;

    let count = |predicate: fn(&Value) -> bool| settings.values().filter(|s| predicate(s)).count();
    let summary = Map::from_iter([
        ("settings".to_string(), Value::from(settings.len())),
        (
            "configured".to_string(),
            Value::from(count(|s| bool_at(s, "configured"))),
        ),
        (
            "secrets_configured".to_string(),
            Value::from(count(|s| bool_at(s, "secret") && bool_at(s, "configured"))),
        ),
        (
            "requires_restart".to_string(),
            Value::from(count(|s| bool_at(s, "requires_restart"))),
        ),
        ("categories".to_string(), json!(categories)),
    ]);

    let mut ordered = settings.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|(key, setting)| (category_of(setting), (*key).clone()));
    let rows = ordered
        .into_iter()
        .filter(|(key, setting)| {
            category
                .as_ref()
                .is_none_or(|category| &category_of(setting) == category)
                && args
                    .keys
                    .as_ref()
                    .is_none_or(|keys| keys.iter().any(|wanted| wanted == *key))
        })
        .map(|(key, setting)| {
            let mut row = Map::from_iter([("key".to_string(), Value::from(key.clone()))]);
            if args.keys.is_some() {
                row.extend(copy_fields(
                    setting,
                    &[
                        "category",
                        "value",
                        "configured",
                        "secret",
                        "requires_restart",
                        "source",
                        "description",
                        "updated_at",
                    ],
                ));
                return Value::Object(row);
            }
            row.extend(copy_fields(setting, &["category", "value", "configured"]));
            for flag in ["secret", "requires_restart"] {
                if bool_at(setting, flag) {
                    row.insert(flag.to_string(), Value::Bool(true));
                }
            }
            shorten(&mut row, &["value"]);
            Value::Object(row)
        })
        .collect();
    Ok(paged(
        fixed(with_unknown_keys(scope(None, args), unknown), summary),
        "settings",
        rows,
        args.offset,
        budget,
    ))
}

fn document_access_view(data: &Value, args: &ReadArgs, budget: usize) -> ViewResult {
    let per_user_type = data
        .get("per_user_type")
        .and_then(Value::as_array)
        .ok_or(ReadViewError::MalformedData)?;
    let user_types = per_user_type
        .iter()
        .filter_map(|entry| {
            Some(NamedUserType {
                id: entry.get("user_type_id")?.as_i64()?,
                name: entry
                    .get("user_type_name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .collect::<Vec<_>>();
    let scoped = args
        .user_type
        .as_ref()
        .map(|reference| resolve_user_type(&user_types, reference))
        .transpose()?;
    let user_type_documents = |id: i64| {
        per_user_type
            .iter()
            .find(|entry| entry.get("user_type_id").and_then(Value::as_i64) == Some(id))
            .and_then(|entry| entry.get("documents"))
            .and_then(Value::as_array)
    };
    let documents = match scoped {
        Some(user_type) => user_type_documents(user_type.id),
        None => data
            .pointer("/global/documents")
            .or_else(|| data.get("documents"))
            .and_then(Value::as_array),
    }
    .ok_or(ReadViewError::MalformedData)?;

    let is_override = |document: &&Value| bool_at(document, "is_override");
    let mut summary = Map::from_iter([
        ("documents".to_string(), Value::from(documents.len())),
        (
            "available".to_string(),
            Value::from(
                documents
                    .iter()
                    .filter(|document| is_effectively_available(document))
                    .count(),
            ),
        ),
        (
            "default_active".to_string(),
            Value::from(
                documents
                    .iter()
                    .filter(|document| is_effectively_default_active(document))
                    .count(),
            ),
        ),
    ]);
    let not_ready = documents
        .iter()
        .filter(|document| !is_ready(document))
        .count();
    if not_ready > 0 {
        summary.insert("not_ready".to_string(), Value::from(not_ready));
    }

    let mut overrides_by_job = HashMap::<String, Vec<Value>>::new();
    if scoped.is_some() {
        summary.insert(
            "overrides".to_string(),
            Value::from(documents.iter().filter(is_override).count()),
        );
    } else {
        let global_jobs = documents
            .iter()
            .filter_map(|document| document.get("job_id").and_then(Value::as_str))
            .collect::<HashSet<_>>();
        let mut with_overrides = Vec::new();
        for user_type in &user_types {
            let overrides = user_type_documents(user_type.id)
                .map(|documents| documents.iter().filter(is_override).collect::<Vec<_>>())
                .unwrap_or_default();
            if overrides.is_empty() {
                continue;
            }
            let mut entry = json!({
                "id": user_type.id,
                "name": user_type.name,
                "overrides": overrides.len(),
            });
            // Overrides for Documents without a global row only appear when
            // reading that User Type.
            let user_type_only = overrides
                .iter()
                .filter(|document| {
                    document
                        .get("job_id")
                        .and_then(Value::as_str)
                        .is_some_and(|job_id| !global_jobs.contains(job_id))
                })
                .count();
            if user_type_only > 0 {
                entry["user_type_only_documents"] = Value::from(user_type_only);
            }
            with_overrides.push(entry);
            for document in overrides {
                if let Some(job_id) = document.get("job_id").and_then(Value::as_str) {
                    overrides_by_job
                        .entry(job_id.to_string())
                        .or_default()
                        .push(json!({
                            "user_type_id": user_type.id,
                            "is_available": bool_at(document, "is_available"),
                            "is_default_active": bool_at(document, "is_default_active"),
                        }));
                }
            }
        }
        if with_overrides.len() > MAX_LISTED_NAMES {
            summary.insert(
                "user_types_with_overrides_total".to_string(),
                Value::from(with_overrides.len()),
            );
            with_overrides.truncate(MAX_LISTED_NAMES);
        }
        summary.insert(
            "user_types_with_overrides".to_string(),
            Value::Array(with_overrides),
        );
    }

    let document_filter = args.document.as_ref().map(|text| text.to_lowercase());
    let rows = documents
        .iter()
        .filter(|document| {
            let job_id = document
                .get("job_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let filename = document
                .get("filename")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_lowercase();
            document_filter.as_ref().is_none_or(|wanted| {
                job_id.eq_ignore_ascii_case(wanted) || filename.contains(wanted.as_str())
            }) && args.access.is_none_or(|access| access.matches(document))
        })
        .map(|document| {
            let mut row = copy_fields(document, &["job_id", "filename", "status"]);
            row.insert(
                "is_available".to_string(),
                Value::Bool(bool_at(document, "is_available")),
            );
            row.insert(
                "is_default_active".to_string(),
                Value::Bool(bool_at(document, "is_default_active")),
            );
            let scoped_override = scoped.is_some() && is_override(&document);
            if args.document.is_some() {
                let updated_at = if scoped_override {
                    document.get("override_updated_at")
                } else {
                    document.get("updated_at")
                };
                if let Some(updated_at) = updated_at.filter(|value| !value.is_null()) {
                    row.insert("updated_at".to_string(), updated_at.clone());
                }
            }
            if scoped.is_some() {
                row.insert(
                    "source".to_string(),
                    Value::from(if scoped_override {
                        "user_type_override"
                    } else {
                        "global"
                    }),
                );
            } else if let Some(overrides) = document
                .get("job_id")
                .and_then(Value::as_str)
                .and_then(|job_id| overrides_by_job.get(job_id))
            {
                row.insert(
                    "user_type_overrides".to_string(),
                    Value::Array(overrides.clone()),
                );
            }
            shorten(&mut row, &["filename"]);
            Value::Object(row)
        })
        .collect();
    Ok(paged(
        fixed(scope(scoped, args), summary),
        "documents",
        rows,
        args.offset,
        budget,
    ))
}

fn onboarding_fields(user_type: &Value) -> &[Value] {
    user_type
        .get("onboarding_fields")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn is_global_question(field: &Value) -> bool {
    field.get("user_type_id").is_none_or(Value::is_null)
}

fn question_row(field: &Value) -> Value {
    let mut row = copy_fields(field, &["id"]);
    row.insert(
        "scope".to_string(),
        Value::from(if is_global_question(field) {
            "global"
        } else {
            "user_type"
        }),
    );
    row.extend(copy_fields(
        field,
        &[
            "name",
            "label",
            "field_type",
            "required",
            "display_order",
            "encryption_enabled",
            "include_in_chat",
        ],
    ));
    if let Some(placeholder) = field
        .get("placeholder")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        row.insert("placeholder".to_string(), Value::from(placeholder));
    }
    if let Some(options) = field.get("options").and_then(Value::as_array) {
        row.insert(
            "options".to_string(),
            Value::from(
                options
                    .iter()
                    .take(MAX_LISTED_OPTIONS)
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
        );
        if options.len() > MAX_LISTED_OPTIONS {
            row.insert("options_total".to_string(), Value::from(options.len()));
        }
    }
    shorten(&mut row, &["label", "placeholder"]);
    Value::Object(row)
}

fn user_types_view(data: &Value, args: &ReadArgs, budget: usize) -> ViewResult {
    let user_types = data
        .get("user_types")
        .and_then(Value::as_array)
        .ok_or(ReadViewError::MalformedData)?;
    let named = user_types
        .iter()
        .filter_map(|user_type| {
            Some(NamedUserType {
                id: user_type.get("id")?.as_i64()?,
                name: user_type
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .collect::<Vec<_>>();

    let Some(reference) = args.user_type.as_ref() else {
        let mut question_ids = HashSet::new();
        let mut global_names = Vec::new();
        for field in user_types.iter().flat_map(onboarding_fields) {
            let id = field.get("id").map(Value::to_string).unwrap_or_default();
            if question_ids.insert(id) && is_global_question(field) {
                global_names.push(
                    field
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                );
            }
        }
        let mut summary = Map::from_iter([
            ("user_types".to_string(), Value::from(user_types.len())),
            (
                "onboarding_questions".to_string(),
                Value::from(question_ids.len()),
            ),
            ("global_questions".to_string(), listed_names(&global_names)),
        ]);
        if global_names.len() > MAX_LISTED_NAMES {
            summary.insert(
                "global_questions_total".to_string(),
                Value::from(global_names.len()),
            );
        }
        let rows = user_types
            .iter()
            .map(|user_type| {
                let mut row = copy_fields(
                    user_type,
                    &["id", "name", "description", "icon", "display_order"],
                );
                row.insert(
                    "type_specific_questions".to_string(),
                    Value::from(
                        onboarding_fields(user_type)
                            .iter()
                            .filter(|field| !is_global_question(field))
                            .count(),
                    ),
                );
                shorten(&mut row, &["description"]);
                Value::Object(row)
            })
            .collect();
        return Ok(paged(
            fixed(scope(None, args), summary),
            "user_types",
            rows,
            args.offset,
            budget,
        ));
    };

    let target = resolve_user_type(&named, reference)?;
    let record = user_types
        .iter()
        .find(|user_type| user_type.get("id").and_then(Value::as_i64) == Some(target.id))
        .ok_or(ReadViewError::MalformedData)?;
    let fields = onboarding_fields(record);
    let global = fields
        .iter()
        .filter(|field| is_global_question(field))
        .count();
    let summary = Map::from_iter([
        ("questions".to_string(), Value::from(fields.len())),
        ("global".to_string(), Value::from(global)),
        (
            "type_specific".to_string(),
            Value::from(fields.len() - global),
        ),
    ]);
    let mut fixed = fixed(scope(Some(target), args), summary);
    let mut user_type = copy_fields(
        record,
        &[
            "id",
            "name",
            "description",
            "icon",
            "display_order",
            "created_at",
        ],
    );
    shorten_to(&mut user_type, &["description"], MAX_DESCRIPTION_CHARS);
    fixed.insert("user_type".to_string(), Value::Object(user_type));
    Ok(paged(
        fixed,
        "questions",
        fields.iter().map(question_row).collect(),
        args.offset,
        budget,
    ))
}

/// Keeps readiness items' meaning and drops the UI translation keys and
/// interpolation values that roughly double their size.
fn deployment_readiness_view(data: &Value) -> ViewResult {
    let object = data.as_object().ok_or(ReadViewError::MalformedData)?;
    let mut view = Map::new();
    for key in ["status", "summary"] {
        if let Some(value) = object.get(key) {
            view.insert(key.to_string(), value.clone());
        }
    }
    let items = object
        .get("items")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    Value::Object(copy_fields(
                        item,
                        &[
                            "key",
                            "label",
                            "source",
                            "severity",
                            "status",
                            "summary",
                            "next_action",
                            "conversation_blocking",
                        ],
                    ))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    view.insert("items".to_string(), Value::Array(items));
    Ok(Value::Object(view))
}

fn onboarding_status_view(data: &Value) -> ViewResult {
    let object = data.as_object().ok_or(ReadViewError::MalformedData)?;
    let mut view = Map::new();
    for key in ["instance", "guided_bootstrap"] {
        if let Some(value) = object.get(key) {
            view.insert(key.to_string(), value.clone());
        }
    }
    if let Some(Value::Object(setup)) = object.get("user_types_setup") {
        let mut setup = setup.clone();
        if let Some(Value::Array(names)) = setup.get_mut("names") {
            names.truncate(MAX_LISTED_NAMES);
        }
        view.insert("user_types_setup".to_string(), Value::Object(setup));
    }
    let question_count = object
        .get("onboarding_questions")
        .and_then(Value::as_array)
        .map(|questions| {
            questions
                .iter()
                .filter_map(|question| question.get("id").map(Value::to_string))
                .collect::<HashSet<_>>()
                .len()
        })
        .unwrap_or(0);
    view.insert(
        "onboarding_questions_setup".to_string(),
        json!({ "count": question_count }),
    );
    Ok(Value::Object(view))
}

/// One global Agent Setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentSetting {
    pub(crate) key: String,
    pub(crate) value: String,
    pub(crate) value_type: String,
    pub(crate) category: String,
    pub(crate) description: Option<String>,
    pub(crate) updated_at: Option<String>,
}

/// One User Type's value for an Agent Setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentSettingOverride {
    pub(crate) value: String,
    pub(crate) updated_at: Option<String>,
}

/// The Agent Setting values one User Type overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserTypeAgentOverrides {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) overrides: BTreeMap<String, AgentSettingOverride>,
}

/// Global Agent Settings plus every User Type's overrides.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AgentSettingsSnapshot {
    pub(crate) global: Vec<AgentSetting>,
    pub(crate) user_types: Vec<UserTypeAgentOverrides>,
}

impl AgentSettingsSnapshot {
    /// Reads the control-plane Agent Settings shape: `global` grouped by
    /// category and keyed by setting, plus `per_user_type[].overrides`.
    pub(crate) fn from_control_plane(data: &Value) -> Result<Self, ReadViewError> {
        let global_groups = data
            .get("global")
            .and_then(Value::as_object)
            .ok_or(ReadViewError::MalformedData)?;
        let mut global = Vec::new();
        for group in ["prompt_sections", "parameters", "defaults"] {
            let Some(items) = global_groups.get(group).and_then(Value::as_object) else {
                continue;
            };
            for (key, item) in items {
                global.push(AgentSetting {
                    key: key.clone(),
                    value: setting_text(item.get("value")),
                    value_type: setting_text(item.get("value_type")),
                    category: setting_text(item.get("category")),
                    description: item
                        .get("description")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    updated_at: optional_text(item.get("updated_at")),
                });
            }
        }
        let user_types = data
            .get("per_user_type")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| {
                        Some(UserTypeAgentOverrides {
                            id: entry.get("user_type_id")?.as_i64()?,
                            name: setting_text(entry.get("user_type_name")),
                            overrides: entry
                                .get("overrides")
                                .and_then(Value::as_object)
                                .map(|overrides| {
                                    overrides
                                        .iter()
                                        .map(|(key, item)| {
                                            (
                                                key.clone(),
                                                AgentSettingOverride {
                                                    value: setting_text(item.get("value")),
                                                    updated_at: optional_text(
                                                        item.get("updated_at"),
                                                    ),
                                                },
                                            )
                                        })
                                        .collect()
                                })
                                .unwrap_or_default(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self { global, user_types })
    }
}

fn optional_text(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::Null) | None => None,
        other => Some(setting_text(other)),
    }
}

fn setting_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

pub(crate) fn agent_settings_view(
    snapshot: &AgentSettingsSnapshot,
    args: &ReadArgs,
    budget: usize,
) -> ViewResult {
    let known = snapshot
        .global
        .iter()
        .map(|setting| setting.key.clone())
        .collect::<Vec<_>>();
    // Override rows have no foreign key to settings; ignore keys Sage no
    // longer reads, as effective-value resolution does.
    let user_types = snapshot
        .user_types
        .iter()
        .map(|user_type| UserTypeAgentOverrides {
            id: user_type.id,
            name: user_type.name.clone(),
            overrides: user_type
                .overrides
                .iter()
                .filter(|(key, _)| known.contains(key))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        })
        .collect::<Vec<_>>();
    let named = user_types
        .iter()
        .map(|user_type| NamedUserType {
            id: user_type.id,
            name: user_type.name.clone(),
        })
        .collect::<Vec<_>>();
    let target = args
        .user_type
        .as_ref()
        .map(|reference| resolve_user_type(&named, reference))
        .transpose()?;
    let overrides = target.and_then(|target| {
        user_types
            .iter()
            .find(|user_type| user_type.id == target.id)
    });
    let unknown = unknown_keys(args.keys.as_ref(), &known, "Agent Setting")?;

    let mut summary =
        Map::from_iter([("settings".to_string(), Value::from(snapshot.global.len()))]);
    match overrides {
        Some(user_type) => {
            summary.insert(
                "overrides".to_string(),
                Value::from(user_type.overrides.len()),
            );
        }
        None => {
            let mut with_overrides = user_types
                .iter()
                .filter(|user_type| !user_type.overrides.is_empty())
                .map(|user_type| {
                    json!({
                        "id": user_type.id,
                        "name": user_type.name,
                        "overrides": user_type.overrides.len(),
                    })
                })
                .collect::<Vec<_>>();
            if with_overrides.len() > MAX_LISTED_NAMES {
                summary.insert(
                    "user_types_with_overrides_total".to_string(),
                    Value::from(with_overrides.len()),
                );
                with_overrides.truncate(MAX_LISTED_NAMES);
            }
            summary.insert(
                "user_types_with_overrides".to_string(),
                Value::Array(with_overrides),
            );
        }
    }

    let full_values = args.keys.is_some();
    let rows = snapshot
        .global
        .iter()
        .filter(|setting| {
            args.keys
                .as_ref()
                .is_none_or(|keys| keys.contains(&setting.key))
        })
        .map(|setting| {
            let mut row = Map::from_iter([
                ("key".to_string(), Value::from(setting.key.clone())),
                (
                    "category".to_string(),
                    Value::from(setting.category.clone()),
                ),
                (
                    "value_type".to_string(),
                    Value::from(setting.value_type.clone()),
                ),
                ("value".to_string(), Value::from(setting.value.clone())),
            ]);
            let mut updated_at = setting.updated_at.clone();
            match overrides {
                Some(user_type) => match user_type.overrides.get(&setting.key) {
                    Some(value) => {
                        row.insert("value".to_string(), Value::from(value.value.clone()));
                        row.insert("source".to_string(), Value::from("user_type_override"));
                        row.insert(
                            "global_value".to_string(),
                            Value::from(setting.value.clone()),
                        );
                        updated_at = value.updated_at.clone();
                    }
                    None => {
                        row.insert("source".to_string(), Value::from("global"));
                    }
                },
                None => {
                    let overridden_by = user_types
                        .iter()
                        .filter(|user_type| user_type.overrides.contains_key(&setting.key))
                        .map(|user_type| user_type.id)
                        .collect::<Vec<_>>();
                    if !overridden_by.is_empty() {
                        row.insert("overridden_by".to_string(), Value::from(overridden_by));
                    }
                }
            }
            if let Some(description) = &setting.description {
                row.insert("description".to_string(), Value::from(description.clone()));
            }
            if full_values {
                if let Some(updated_at) = updated_at {
                    row.insert("updated_at".to_string(), Value::from(updated_at));
                }
            } else {
                shorten(&mut row, &["value", "global_value", "description"]);
            }
            Value::Object(row)
        })
        .collect();
    Ok(paged(
        fixed(with_unknown_keys(scope(target, args), unknown), summary),
        "settings",
        rows,
        args.offset,
        budget,
    ))
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Admin Config data shaped like the control plane returns it, at a
    //! deliberately larger scale than any current deployment.

    use serde_json::{json, Map, Value};

    fn document(job: usize, available: bool, default_active: bool, is_override: bool) -> Value {
        json!({
            "job_id": format!("job-{:03}-0000-0000-0000-000000000000", job),
            "filename": format!("Field Guide {:03} — regional handbook.pdf", job),
            "status": "completed",
            "total_chunks": 12,
            "is_available": available,
            "is_default_active": default_active,
            "display_order": job,
            "updated_at": "2026-10-22 20:06:31",
            "is_override": is_override,
            "override_user_type_id": null,
            "override_updated_at": null,
        })
    }

    /// Production-shaped Document Access at a deliberately larger scale than
    /// any current deployment: 200 Documents and 12 User Types.
    pub(crate) fn document_access_fixture() -> Value {
        let global = (0..200)
            .map(|job| document(job, job % 10 != 0, job % 4 == 0, false))
            .collect::<Vec<_>>();
        let per_user_type = (0..12)
            .map(|index| {
                let id = index + 2;
                let documents = (0..200)
                    .map(|job| {
                        if index % 3 == 0 && job % 50 == 7 {
                            document(job, true, true, true)
                        } else {
                            document(job, job % 10 != 0, job % 4 == 0, false)
                        }
                    })
                    .collect::<Vec<_>>();
                json!({
                    "user_type_id": id,
                    "user_type_name": format!("Group {}", index),
                    "available_document_ids": [],
                    "default_document_ids": [],
                    "documents": documents,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "global": {"available_document_ids": [], "default_document_ids": [], "documents": global},
            "documents": global,
            "per_user_type": per_user_type,
            "limits": {"documents_returned": 200, "user_types_returned": 12},
        })
    }

    fn question(id: i64, user_type_id: Option<i64>, options: usize) -> Value {
        json!({
            "id": id,
            "user_type_id": user_type_id,
            "name": format!("question_{}", id),
            "label": format!("Question {}", id),
            "field_type": if options > 0 { "select" } else { "text" },
            "required": id % 2 == 0,
            "display_order": id,
            "placeholder": if options > 0 { Value::Null } else { Value::from("Type your answer") },
            "options": if options > 0 {
                Value::from((0..options).map(|n| format!("Option {}", n)).collect::<Vec<_>>())
            } else {
                Value::Null
            },
            "encryption_enabled": true,
            "include_in_chat": false,
            "created_at": "2026-10-22 20:06:31",
        })
    }

    /// Ten User Types with long descriptions, 25 global questions repeated
    /// into every User Type (as the control plane does), and 15 type-specific
    /// questions each, one with 100 options.
    pub(crate) fn user_types_fixture() -> Value {
        let user_types = (0..10)
            .map(|index| {
                let id = index + 2;
                let mut fields = (1..=25).map(|q| question(q, None, 0)).collect::<Vec<_>>();
                fields.extend(
                    (0..15).map(|q| question(100 * id + q, Some(id), if q == 0 { 100 } else { 0 })),
                );
                json!({
                    "id": id,
                    "name": format!("Group {}", index),
                    "description": "Long description. ".repeat(40),
                    "icon": "Users",
                    "display_order": index,
                    "created_at": "2026-10-22 20:06:31",
                    "onboarding_fields": fields,
                })
            })
            .collect::<Vec<_>>();
        let flattened = user_types
            .iter()
            .flat_map(|user_type| user_type["onboarding_fields"].as_array().unwrap().clone())
            .collect::<Vec<_>>();
        json!({
            "user_types": user_types,
            "onboarding_questions": flattened,
            "limits": {"user_types_returned": 10, "onboarding_questions_returned": flattened.len()},
        })
    }

    pub(crate) fn instance_settings_fixture() -> Value {
        let mut fields = (0..32)
            .map(|index| {
                json!({
                    "key": format!("setting_{:02}", index),
                    "label": format!("Setting {}", index),
                    "value": if index == 3 { "Long text. ".repeat(80) } else { format!("value {}", index) },
                    "source": if index < 5 { "operator" } else { "default" },
                    "editable": true,
                })
            })
            .collect::<Vec<_>>();
        fields[1]["supported_values"] = json!(["en", "es", "pt", "fr", "de", "it", "nl"]);
        let settings = fields
            .iter()
            .map(|field| {
                (
                    field["key"].as_str().unwrap().to_string(),
                    field["value"].clone(),
                )
            })
            .collect::<Map<_, _>>();
        json!({"settings": settings, "explicitly_set_keys": [], "fields": fields})
    }

    pub(crate) fn deployment_settings_fixture() -> Value {
        let mut settings = Map::new();
        for (index, category) in ["domains", "email", "llm", "security"].iter().enumerate() {
            for n in 0..13 {
                let secret = n == 0;
                settings.insert(
                    format!("{}_SETTING_{:02}", category.to_uppercase(), n),
                    json!({
                        "value": if secret { "********".to_string() } else { format!("https://{}.example.test/{}", category, n) },
                        "configured": n % 3 != 0 || secret,
                        "secret": secret,
                        "requires_restart": index % 2 == 0,
                        "source": "deployment_config",
                        "category": category,
                        "description": "Deployment setting description text",
                        "updated_at": "2026-10-22 20:06:31",
                    }),
                );
            }
        }
        json!({"settings": settings, "categories": {}})
    }

    /// Deployment readiness as the control plane builds it, including the UI
    /// translation keys and interpolation values on every item.
    pub(crate) fn deployment_readiness_fixture() -> Value {
        let item = |key: &str, severity: &str, status: &str| {
            json!({
                "key": key,
                "label": format!("{} check", key.replace('_', " ")),
                "label_key": format!("adminDeployment.readiness.{}.label", key),
                "source": "deployment_readiness",
                "severity": severity,
                "status": status,
                "summary": format!("The {} check reported {} after reviewing the current deployment configuration and recorded evidence.", key, status),
                "summary_key": format!("adminDeployment.readiness.{}.status.{}.summary", key, status),
                "summary_values": {"count": 15, "items": "CORS_ORIGINS, FRONTEND_URL, SMTP_HOST", "last_checked_at": "2026-10-22T20:06:31Z"},
                "next_action": format!("Review the {} evidence and record the outcome before opening the instance.", key),
                "next_action_key": format!("adminDeployment.readiness.{}.status.{}.next_action", key, status),
                "next_action_values": {"count": 15, "target": "Deployment Settings"},
                "conversation_blocking": false,
            })
        };
        json!({
            "status": "warnings",
            "summary": {"blockers": 0, "warnings": 4, "ready": 2, "total": 6},
            "items": [
                item("deployment_settings_validation", "warning", "advisory"),
                item("inference", "ready", "configured"),
                item("data_lifecycle", "warning", "review_required"),
                item("backup_restore_drill", "warning", "not_recorded"),
                item("restart_required", "warning", "pending"),
                item("sage_runtime_config", "ready", "matched"),
            ],
        })
    }

    /// The onboarding-status shape, which embeds every User Type and question.
    pub(crate) fn onboarding_status_fixture() -> Value {
        let user_types = user_types_fixture();
        json!({
            "instance": {"admin_exists": true, "admin_initialized": true, "setup_complete": false, "ready_for_users": false, "admin_count": 1},
            "guided_bootstrap": {"required_keys": ["instance_name", "default_language"], "configured_keys": ["instance_name"], "missing_required_keys": ["default_language"], "complete": false, "required_count": 2, "configured_required_count": 1},
            "user_types_setup": {"required_minimum": 1, "count": 10, "names": ["Group 0"], "complete": true},
            "user_types": user_types["user_types"],
            "onboarding_questions": user_types["onboarding_questions"],
            "limits": user_types["limits"],
        })
    }

    /// The control-plane Agent Settings shape with a long rule list and three
    /// User Types that each repeat every effective value.
    pub(crate) fn agent_settings_fixture() -> Value {
        let rules = serde_json::to_string(&vec!["Follow the operator's long rule text."; 120])
            .expect("rules serialize");
        let item = |key: &str, value: &str, value_type: &str, category: &str| json!({"key": key, "value": value, "value_type": value_type, "category": category, "description": format!("{} description", key), "updated_at": "2026-10-22T20:06:31Z"});
        let global = json!({
            "prompt_sections": {
                "prompt_rules": item("prompt_rules", &rules, "json", "prompt_section"),
                "prompt_tone": item("prompt_tone", "Be helpful, concise, and professional.", "string", "prompt_section"),
            },
            "parameters": {
                "temperature": item("temperature", "0.1", "number", "parameter"),
                "top_k": item("top_k", "8", "number", "parameter"),
            },
            "defaults": {
                "web_search_default": item("web_search_default", "false", "boolean", "default"),
            },
        });
        let per_user_type = (0..3)
            .map(|index| {
                json!({
                    "user_type_id": index + 2,
                    "user_type_name": format!("Group {}", index),
                    "overrides": if index == 1 {
                        json!({"temperature": item("temperature", "0.3", "number", "parameter")})
                    } else {
                        json!({})
                    },
                    "effective_values": global,
                })
            })
            .collect::<Vec<_>>();
        json!({"global": global, "per_user_type": per_user_type, "limits": {"user_types_returned": 3}})
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    const BUDGET: usize = 2_800;

    fn args(entries: Value) -> ToolArgs {
        ToolArgs::from_json_object(&entries).expect("test args should be an object")
    }

    fn read(view: ReadView, data: &Value, entries: Value) -> Value {
        let parsed = view.parse_args(&args(entries)).expect("args should parse");
        view.apply(data, &parsed, BUDGET)
            .expect("view should apply")
    }

    fn read_error(view: ReadView, data: &Value, entries: Value) -> String {
        let parsed = match view.parse_args(&args(entries)) {
            Ok(parsed) => parsed,
            Err(error) => return error.message(),
        };
        view.apply(data, &parsed, BUDGET)
            .expect_err("view should reject the arguments")
            .message()
    }

    /// Walks every page and returns all rows, asserting each page fits.
    fn walk(view: ReadView, data: &Value, mut entries: Value, list_key: &str) -> Vec<Value> {
        let mut rows = Vec::new();
        for _ in 0..1_000 {
            let result = read(view, data, entries.clone());
            assert!(
                char_len(&result) <= BUDGET,
                "{:?} page was {} chars",
                view,
                char_len(&result)
            );
            rows.extend(result[list_key].as_array().expect("rows").iter().cloned());
            match result["page"]["next_offset"].as_u64() {
                Some(next) => entries["offset"] = Value::from(next),
                None => return rows,
            }
        }
        panic!("paging did not terminate");
    }

    #[test]
    fn document_access_overview_fits_budget_and_reports_overrides() {
        let data = document_access_fixture();
        assert!(
            char_len(&data) > 100_000,
            "fixture should be far over budget"
        );

        let result = read(ReadView::DocumentAccess, &data, json!({}));

        assert!(char_len(&result) <= BUDGET);
        assert_eq!(result["summary"]["documents"], 200);
        assert_eq!(result["summary"]["available"], 180);
        assert_eq!(result["summary"]["default_active"], 40);
        let with_overrides = result["summary"]["user_types_with_overrides"]
            .as_array()
            .expect("override list");
        assert_eq!(with_overrides.len(), 4);
        assert_eq!(
            with_overrides[0],
            json!({"id": 2, "name": "Group 0", "overrides": 4})
        );
        assert_eq!(result["page"]["offset"], 0);
        assert_eq!(result["page"]["total_count"], 200);
        assert_eq!(result["page"]["has_more"], true);

        let rows = walk(ReadView::DocumentAccess, &data, json!({}), "documents");
        assert_eq!(rows.len(), 200);
        let job_seven = rows
            .iter()
            .find(|row| row["job_id"].as_str().unwrap().starts_with("job-007"))
            .expect("job 7");
        assert_eq!(
            job_seven["user_type_overrides"].as_array().unwrap().len(),
            4
        );
        assert!(rows[1].get("user_type_overrides").is_none());
    }

    #[test]
    fn document_access_answers_one_document_for_one_user_type() {
        let data = document_access_fixture();

        let result = read(
            ReadView::DocumentAccess,
            &data,
            json!({"user_type": "group 3", "document": "guide 057"}),
        );

        assert_eq!(
            result["scope"]["user_type"],
            json!({"id": 5, "name": "Group 3"})
        );
        assert_eq!(result["page"]["total_count"], 1);
        let row = &result["documents"][0];
        assert!(row["filename"]
            .as_str()
            .unwrap()
            .starts_with("Field Guide 057"));
        assert_eq!(row["is_available"], true);
        assert_eq!(row["is_default_active"], true);
        assert_eq!(row["source"], "user_type_override");
        assert_eq!(result["summary"]["overrides"], 4);
    }

    #[test]
    fn document_access_filters_by_numeric_id_and_access() {
        let data = document_access_fixture();

        let result = read(
            ReadView::DocumentAccess,
            &data,
            json!({"user_type": 3, "access": "default_active"}),
        );

        assert_eq!(result["scope"]["user_type"]["name"], "Group 1");
        assert_eq!(result["page"]["total_count"], 40);
        assert!(result["documents"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["is_available"] == true
                && row["is_default_active"] == true
                && row["source"] == "global"));
    }

    #[test]
    fn unknown_user_type_lists_known_user_types() {
        let message = read_error(
            ReadView::DocumentAccess,
            &document_access_fixture(),
            json!({"user_type": "Teachers"}),
        );

        assert!(message.starts_with("Unknown User Type \"Teachers\"."));
        assert!(message.contains("Group 0 (id 2)"));
    }

    #[test]
    fn user_types_overview_lists_types_and_global_questions_once() {
        let data = user_types_fixture();
        assert!(char_len(&data) > 50_000);

        let result = read(ReadView::UserTypes, &data, json!({}));

        assert!(char_len(&result) <= BUDGET);
        assert_eq!(result["summary"]["user_types"], 10);
        assert_eq!(result["summary"]["onboarding_questions"], 25 + 10 * 15);
        assert_eq!(
            result["summary"]["global_questions"]
                .as_array()
                .unwrap()
                .len(),
            MAX_LISTED_NAMES
        );
        assert_eq!(result["summary"]["global_questions_total"], 25);
        let first = &result["user_types"][0];
        assert_eq!(first["type_specific_questions"], 15);
        assert_eq!(first["truncated"], json!(["description"]));
        assert_eq!(
            walk(ReadView::UserTypes, &data, json!({}), "user_types").len(),
            10
        );
    }

    #[test]
    fn user_type_detail_returns_full_record_and_every_question_it_sees() {
        let data = user_types_fixture();

        let result = read(ReadView::UserTypes, &data, json!({"user_type": "Group 4"}));

        assert_eq!(result["user_type"]["id"], 6);
        assert_eq!(
            result["user_type"]["description"].as_str().unwrap().len(),
            "Long description. ".len() * 40
        );
        assert_eq!(
            result["summary"],
            json!({"questions": 40, "global": 25, "type_specific": 15})
        );
        let questions = walk(
            ReadView::UserTypes,
            &data,
            json!({"user_type": "Group 4"}),
            "questions",
        );
        assert_eq!(questions.len(), 40);
        assert_eq!(questions[0]["scope"], "global");
        let select = questions
            .iter()
            .find(|question| question["id"] == 600)
            .expect("type-specific select question");
        assert_eq!(select["scope"], "user_type");
        assert_eq!(
            select["options"].as_array().unwrap().len(),
            MAX_LISTED_OPTIONS
        );
        assert_eq!(select["options_total"], 100);
    }

    #[test]
    fn onboarding_status_drops_embedded_user_type_detail() {
        let mut data = json!({
            "instance": {"admin_exists": true, "setup_complete": false},
            "guided_bootstrap": {"complete": false, "missing_required_keys": ["default_language"]},
            "user_types_setup": {"required_minimum": 1, "count": 10, "names": ["A"], "complete": true},
            "limits": {"user_types_returned": 10},
        });
        let fixture = user_types_fixture();
        data["user_types"] = fixture["user_types"].clone();
        data["onboarding_questions"] = fixture["onboarding_questions"].clone();

        let result = read(ReadView::OnboardingStatus, &data, json!({}));

        assert!(char_len(&result) <= 1_000);
        assert_eq!(result["onboarding_questions_setup"]["count"], 175);
        assert_eq!(result["user_types_setup"]["count"], 10);
        assert!(result.get("user_types").is_none());
        assert!(result.get("limits").is_none());
        assert_eq!(
            read_error(ReadView::OnboardingStatus, &data, json!({"user_type": "A"})),
            "Unsupported argument `user_type`. This Tool takes no arguments."
        );
    }

    #[test]
    fn instance_settings_overview_shortens_values_and_keys_return_full_fields() {
        let data = instance_settings_fixture();

        let overview = read(ReadView::InstanceSettings, &data, json!({}));
        assert!(char_len(&overview) <= BUDGET);
        assert_eq!(
            overview["summary"],
            json!({"settings": 32, "operator_set": 5})
        );
        assert_eq!(
            walk(ReadView::InstanceSettings, &data, json!({}), "settings").len(),
            32
        );
        let long = &overview["settings"][3];
        assert_eq!(long["truncated"], json!(["value"]));
        assert!(long.get("label").is_none());

        let detail = read(
            ReadView::InstanceSettings,
            &data,
            json!({"keys": ["setting_01", "setting_03"]}),
        );
        assert_eq!(detail["settings"][0]["supported_values"][0], "en");
        assert_eq!(
            detail["settings"][1]["value"].as_str().unwrap().len(),
            "Long text. ".len() * 80
        );
        assert!(
            read_error(ReadView::InstanceSettings, &data, json!({"keys": ["nope"]}))
                .starts_with("Unknown Instance Setting key(s): nope.")
        );

        // A mix of stored and unstored keys answers what exists and names the rest.
        let partial = read(
            ReadView::InstanceSettings,
            &data,
            json!({"keys": ["setting_02", "default_language"]}),
        );
        assert_eq!(partial["page"]["total_count"], 1);
        assert_eq!(partial["settings"][0]["key"], "setting_02");
        assert_eq!(
            partial["scope"]["unknown_keys"],
            json!(["default_language"])
        );
    }

    #[test]
    fn deployment_settings_page_filter_and_detail() {
        let data = deployment_settings_fixture();

        let overview = read(ReadView::DeploymentSettings, &data, json!({}));
        assert!(char_len(&overview) <= BUDGET);
        assert_eq!(overview["summary"]["settings"], 52);
        assert_eq!(overview["summary"]["secrets_configured"], 4);
        assert_eq!(overview["summary"]["categories"]["email"], 13);
        assert_eq!(
            walk(ReadView::DeploymentSettings, &data, json!({}), "settings").len(),
            52
        );

        let email = walk(
            ReadView::DeploymentSettings,
            &data,
            json!({"category": "EMAIL"}),
            "settings",
        );
        assert_eq!(email.len(), 13);
        assert_eq!(email[0]["key"], "EMAIL_SETTING_00");
        assert_eq!(email[0]["value"], "********");
        assert_eq!(email[0]["secret"], true);
        assert!(email[1].get("secret").is_none());
        assert!(email[1].get("description").is_none());

        let detail = read(
            ReadView::DeploymentSettings,
            &data,
            json!({"keys": ["LLM_SETTING_01"]}),
        );
        assert_eq!(
            detail["settings"][0]["description"],
            "Deployment setting description text"
        );
        assert_eq!(detail["settings"][0]["secret"], false);
        assert!(read_error(
            ReadView::DeploymentSettings,
            &data,
            json!({"category": "storage"})
        )
        .contains("Known categories: domains, email, llm, security."));
    }

    fn agent_settings_snapshot() -> AgentSettingsSnapshot {
        let setting = |key: &str, value: String, value_type: &str, category: &str| AgentSetting {
            key: key.to_string(),
            value,
            value_type: value_type.to_string(),
            category: category.to_string(),
            description: Some(format!("{} description", key)),
            updated_at: Some("2026-10-01T00:00:00Z".to_string()),
        };
        AgentSettingsSnapshot {
            global: vec![
                setting(
                    "prompt_rules",
                    serde_json::to_string(&vec!["Follow the operator's long rule text."; 120])
                        .unwrap(),
                    "json",
                    "prompt_section",
                ),
                setting(
                    "prompt_tone",
                    "Be helpful.".to_string(),
                    "string",
                    "prompt_section",
                ),
                setting("temperature", "0.1".to_string(), "number", "parameter"),
                setting("top_k", "8".to_string(), "number", "parameter"),
                setting(
                    "web_search_default",
                    "false".to_string(),
                    "boolean",
                    "default",
                ),
            ],
            user_types: vec![
                UserTypeAgentOverrides {
                    id: 2,
                    name: "Teachers".to_string(),
                    overrides: BTreeMap::from([
                        (
                            "temperature".to_string(),
                            AgentSettingOverride {
                                value: "0.3".to_string(),
                                updated_at: Some("2026-10-20T00:00:00Z".to_string()),
                            },
                        ),
                        (
                            "admin_trace_visibility".to_string(),
                            AgentSettingOverride {
                                value: "legacy".to_string(),
                                updated_at: None,
                            },
                        ),
                    ]),
                },
                UserTypeAgentOverrides {
                    id: 3,
                    name: "Students".to_string(),
                    overrides: BTreeMap::new(),
                },
            ],
        }
    }

    fn agent_view(entries: Value) -> Result<Value, ReadViewError> {
        let parsed = ReadView::AgentSettings.parse_args(&args(entries))?;
        agent_settings_view(&agent_settings_snapshot(), &parsed, BUDGET)
    }

    #[test]
    fn agent_settings_overview_shortens_prompts_and_names_overrides() {
        let result = agent_view(json!({})).unwrap();

        assert!(char_len(&result) <= BUDGET);
        assert_eq!(result["page"]["total_count"], 5);
        assert_eq!(result["page"]["has_more"], false);
        assert_eq!(result["settings"][0]["key"], "prompt_rules");
        assert_eq!(result["settings"][0]["truncated"], json!(["value"]));
        assert_eq!(
            result["summary"]["user_types_with_overrides"],
            json!([{"id": 2, "name": "Teachers", "overrides": 1}])
        );
    }

    #[test]
    fn agent_settings_for_user_type_reports_effective_value_and_source() {
        let result =
            agent_view(json!({"user_type": "teachers", "keys": ["temperature", "top_k"]})).unwrap();

        assert_eq!(
            result["scope"]["user_type"],
            json!({"id": 2, "name": "Teachers"})
        );
        assert_eq!(result["summary"]["overrides"], 1);
        let rows = result["settings"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["key"], "temperature");
        assert_eq!(rows[0]["value"], "0.3");
        assert_eq!(rows[0]["source"], "user_type_override");
        assert_eq!(rows[0]["global_value"], "0.1");
        assert_eq!(rows[1]["source"], "global");
    }

    #[test]
    fn agent_settings_keys_return_full_values() {
        let full = agent_view(json!({"keys": ["prompt_rules"]})).unwrap();
        assert!(full["settings"][0].get("truncated").is_none());
        assert!(full["settings"][0]["value"].as_str().unwrap().len() > 4_000);

        let partial = agent_view(json!({"keys": ["temperature", "max_tokens"]})).unwrap();
        assert_eq!(partial["settings"].as_array().unwrap().len(), 1);
        assert_eq!(partial["scope"]["unknown_keys"], json!(["max_tokens"]));

        let message = agent_view(json!({"keys": ["max_tokens"]}))
            .unwrap_err()
            .message();
        assert!(message.starts_with("Unknown Agent Setting key(s): max_tokens."));
        assert!(message.contains("temperature"));
    }

    #[test]
    fn agent_settings_snapshot_reads_control_plane_shape() {
        let data = json!({
            "global": {
                "prompt_sections": {"prompt_tone": {"value": "Be kind.", "value_type": "string", "category": "prompt_section", "description": "Voice"}},
                "parameters": {"temperature": {"value": "0.4", "value_type": "number", "category": "parameter", "description": null}},
                "defaults": {}
            },
            "per_user_type": [{
                "user_type_id": 7,
                "user_type_name": "Advocates",
                "overrides": {"temperature": {"value": "0.2"}},
                "effective_values": {}
            }],
            "limits": {"user_types_returned": 1}
        });

        let result = read(
            ReadView::AgentSettings,
            &data,
            json!({"user_type": "Advocates", "keys": ["temperature"]}),
        );

        assert_eq!(result["settings"][0]["value"], "0.2");
        assert_eq!(result["settings"][0]["global_value"], "0.4");
    }

    #[test]
    fn arguments_are_validated_against_each_view() {
        let parsed = ReadView::DocumentAccess
            .parse_args(&args(json!({
                "user_type": 4,
                "document": "  Guide  ",
                "access": "available",
                "offset": "20",
                "keys": ["temperature"],
            })))
            .expect_err("keys is not a Document Access argument");
        assert_eq!(
            parsed.message(),
            "Unsupported argument `keys`. Supported arguments: user_type, document, access, offset."
        );

        let parsed = ReadView::DocumentAccess
            .parse_args(&args(json!({
                "user_type": 4,
                "document": "  Guide  ",
                "access": "available",
                "offset": "20",
            })))
            .expect("arguments should parse");
        assert_eq!(parsed.user_type, Some(UserTypeRef::Id(4)));
        assert_eq!(parsed.document.as_deref(), Some("Guide"));
        assert_eq!(parsed.access, Some(AccessFilter::Available));
        assert_eq!(parsed.offset, 20);

        for bad in [
            json!({"offset": -1}),
            json!({"access": "everyone"}),
            json!({"user_type": true}),
        ] {
            assert_eq!(
                ReadView::DocumentAccess
                    .parse_args(&args(bad))
                    .unwrap_err()
                    .code(),
                "invalid_arguments"
            );
        }
    }

    #[test]
    fn every_view_declares_its_arguments() {
        assert_eq!(
            ReadView::DocumentAccess.native_parameters()["properties"]
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            vec!["user_type", "document", "access", "offset"]
        );
        assert_eq!(
            ReadView::OnboardingStatus.native_parameters()["properties"],
            json!({})
        );
        assert_eq!(
            ReadView::AgentSettings.native_parameters()["properties"]["keys"]["type"],
            "array"
        );
    }

    #[test]
    fn deployment_readiness_drops_translation_keys_and_fits_the_budget() {
        let data = deployment_readiness_fixture();
        assert!(char_len(&data) > 3_000, "fixture should exceed the budget");

        let result = read(ReadView::DeploymentReadiness, &data, json!({}));

        assert!(char_len(&result) <= BUDGET, "{}", char_len(&result));
        assert_eq!(result["status"], "warnings");
        assert_eq!(result["summary"]["total"], 6);
        let item = &result["items"][3];
        assert_eq!(item["key"], "backup_restore_drill");
        assert!(item["next_action"].as_str().unwrap().starts_with("Review"));
        assert!(item.get("summary_key").is_none());
        assert!(item.get("summary_values").is_none());
    }

    #[test]
    fn agent_settings_overview_counts_overrides_and_names_overriding_types() {
        let mut snapshot = agent_settings_snapshot();
        let keys = snapshot
            .global
            .iter()
            .map(|setting| setting.key.clone())
            .collect::<Vec<_>>();
        snapshot.user_types = (0..25)
            .map(|index| UserTypeAgentOverrides {
                id: 10 + index,
                name: format!("A User Type With A Fairly Long Name {}", index),
                overrides: keys
                    .iter()
                    .map(|key| {
                        (
                            key.clone(),
                            AgentSettingOverride {
                                value: "override value text".repeat(20),
                                updated_at: None,
                            },
                        )
                    })
                    .collect(),
            })
            .collect();

        let parsed = ReadView::AgentSettings
            .parse_args(&args(json!({})))
            .unwrap();
        let result = agent_settings_view(&snapshot, &parsed, BUDGET).unwrap();

        assert!(char_len(&result) <= BUDGET, "{}", char_len(&result));
        assert_eq!(result["summary"]["user_types_with_overrides_total"], 25);
        assert_eq!(
            result["summary"]["user_types_with_overrides"][0]["overrides"],
            5
        );
        assert_eq!(
            result["settings"][0]["overridden_by"]
                .as_array()
                .unwrap()
                .len(),
            25
        );
    }

    #[test]
    fn agent_settings_ignore_overrides_for_settings_sage_no_longer_reads() {
        let overview = agent_view(json!({})).unwrap();
        assert_eq!(
            overview["summary"]["user_types_with_overrides"],
            json!([{"id": 2, "name": "Teachers", "overrides": 1}])
        );
        let temperature = overview["settings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["key"] == "temperature")
            .unwrap();
        assert_eq!(temperature["overridden_by"], json!([2]));
        assert!(temperature.get("updated_at").is_none());

        let scoped = agent_view(json!({"user_type": "Teachers", "keys": ["temperature"]})).unwrap();
        assert_eq!(scoped["summary"]["overrides"], 1);
        assert_eq!(scoped["settings"][0]["updated_at"], "2026-10-20T00:00:00Z");
        let global = agent_view(json!({"keys": ["top_k"]})).unwrap();
        assert_eq!(global["settings"][0]["updated_at"], "2026-10-01T00:00:00Z");
    }

    #[test]
    fn user_type_detail_shortens_a_very_long_description() {
        let mut data = user_types_fixture();
        data["user_types"][0]["description"] = Value::from("x".repeat(3_500));

        let result = read(ReadView::UserTypes, &data, json!({"user_type": "Group 0"}));

        assert!(char_len(&result) <= BUDGET, "{}", char_len(&result));
        assert_eq!(result["user_type"]["truncated"], json!(["description"]));
        assert_eq!(
            result["user_type"]["description"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            MAX_DESCRIPTION_CHARS
        );
    }

    #[test]
    fn numeric_user_type_matches_ids_and_text_matches_names_first() {
        let data = json!({"user_types": [
            {"id": 5, "name": "2", "onboarding_fields": []},
            {"id": 2, "name": "Teachers", "onboarding_fields": []},
        ]});

        let by_number = read(ReadView::UserTypes, &data, json!({"user_type": 2}));
        assert_eq!(by_number["user_type"]["name"], "Teachers");
        let by_text = read(ReadView::UserTypes, &data, json!({"user_type": "2"}));
        assert_eq!(by_text["user_type"]["id"], 5);
        let by_id_text = read(ReadView::UserTypes, &data, json!({"user_type": "5"}));
        assert_eq!(by_id_text["user_type"]["id"], 5);
        assert!(
            read_error(ReadView::UserTypes, &data, json!({"user_type": 9}))
                .starts_with("Unknown User Type \"9\".")
        );
    }

    #[test]
    fn keys_are_bounded_and_not_echoed() {
        let long_key = "k".repeat(MAX_KEY_CHARS + 1);
        assert_eq!(
            ReadView::InstanceSettings
                .parse_args(&args(json!({"keys": [long_key]})))
                .unwrap_err()
                .message(),
            format!("Each key must be at most {} characters.", MAX_KEY_CHARS)
        );
        let result = read(
            ReadView::InstanceSettings,
            &instance_settings_fixture(),
            json!({"keys": ["setting_01"]}),
        );
        assert_eq!(result["scope"], json!({}));
    }

    #[test]
    fn document_access_counts_only_completed_documents_as_available() {
        let mut data = document_access_fixture();
        // Job 4 is available and on by default globally but still processing.
        data["global"]["documents"][4]["status"] = Value::from("processing");

        let result = read(ReadView::DocumentAccess, &data, json!({}));
        assert_eq!(result["summary"]["available"], 179);
        assert_eq!(result["summary"]["default_active"], 39);
        assert_eq!(result["summary"]["not_ready"], 1);

        let available = walk(
            ReadView::DocumentAccess,
            &data,
            json!({"access": "available"}),
            "documents",
        );
        assert_eq!(available.len(), 179);
        assert!(available.iter().all(|row| row["status"] == "completed"));
    }

    #[test]
    fn document_access_reports_overrides_without_a_global_row() {
        let mut data = document_access_fixture();
        let orphan = json!({
            "job_id": "job-orphan", "filename": "Only For Group 0.pdf", "status": "completed",
            "is_available": true, "is_default_active": true, "is_override": true,
            "updated_at": "2026-10-21 10:00:00", "override_updated_at": "2026-10-21 10:00:00"
        });
        data["per_user_type"][0]["documents"]
            .as_array_mut()
            .unwrap()
            .push(orphan);

        let overview = read(ReadView::DocumentAccess, &data, json!({}));
        assert_eq!(
            overview["summary"]["user_types_with_overrides"][0],
            json!({"id": 2, "name": "Group 0", "overrides": 5, "user_type_only_documents": 1})
        );

        let detail = read(
            ReadView::DocumentAccess,
            &data,
            json!({"user_type": "Group 0", "document": "Only For"}),
        );
        assert_eq!(detail["documents"][0]["source"], "user_type_override");
        assert_eq!(detail["documents"][0]["updated_at"], "2026-10-21 10:00:00");
    }

    #[test]
    fn a_page_always_makes_progress_even_when_one_row_exceeds_the_budget() {
        let rows = vec![json!({"text": "x".repeat(5_000)}), json!({"text": "y"})];

        let first = paged(Map::new(), "rows", rows.clone(), 0, 100);
        assert_eq!(first["page"]["returned"], 1);
        assert_eq!(first["page"]["next_offset"], 1);

        let second = paged(Map::new(), "rows", rows.clone(), 1, 100);
        assert_eq!(second["rows"][0]["text"], "y");
        assert_eq!(second["page"]["next_offset"], Value::Null);

        let past_end = paged(Map::new(), "rows", rows, 9, 100);
        assert_eq!(past_end["page"]["returned"], 0);
        assert_eq!(past_end["page"]["offset"], 2);
    }
}
