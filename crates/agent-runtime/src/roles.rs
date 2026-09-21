use std::collections::{BTreeMap, BTreeSet};

use edsa_core::{
    EvidenceAssessment, EvidenceRef, Hypothesis, HypothesisId, PatchAttemptId, RepositorySnapshot,
    Signal, SignalId,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Mapper,
    HypothesisPlanner,
    ExperimentDesigner,
    EvidenceCritic,
    PatchAgent,
    VariantHunter,
    Reviewer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCapability {
    ReadRepositoryFile,
    SearchRepository,
    /// Reserved protocol capability. Model-supplied commands are never admitted.
    RunSandboxExperiment,
    ReadEvidenceArtifact,
    /// Reserved until the verified patch workflow is installed.
    ProposePatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "tool", content = "input", rename_all = "snake_case")]
pub enum ToolRequest {
    ReadRepositoryFile {
        relative_path: String,
        start_byte: u64,
        maximum_bytes: u64,
    },
    SearchRepository {
        query: String,
        path_prefix: Option<String>,
        maximum_matches: u32,
    },
    RunSandboxExperiment {
        image: String,
        command: Vec<String>,
        timeout_seconds: u64,
    },
    ReadEvidenceArtifact {
        sha256: String,
        maximum_bytes: u64,
    },
    ProposePatch {
        hypothesis_id: HypothesisId,
        unified_diff: String,
    },
}

impl ToolRequest {
    #[must_use]
    pub const fn capability(&self) -> ToolCapability {
        match self {
            Self::ReadRepositoryFile { .. } => ToolCapability::ReadRepositoryFile,
            Self::SearchRepository { .. } => ToolCapability::SearchRepository,
            Self::RunSandboxExperiment { .. } => ToolCapability::RunSandboxExperiment,
            Self::ReadEvidenceArtifact { .. } => ToolCapability::ReadEvidenceArtifact,
            Self::ProposePatch { .. } => ToolCapability::ProposePatch,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "tool", content = "output", rename_all = "snake_case")]
pub enum ToolResult {
    RepositoryFile {
        relative_path: String,
        content: String,
        truncated: bool,
    },
    SearchMatches {
        matches: Vec<SearchMatch>,
        truncated: bool,
    },
    SandboxExperiment {
        exit_code: Option<i32>,
        stdout_sha256: String,
        stderr_sha256: String,
        output_truncated: bool,
    },
    EvidenceArtifact {
        sha256: String,
        media_type: String,
        content: Vec<u8>,
        truncated: bool,
    },
    PatchProposal {
        patch_attempt_id: PatchAttemptId,
        diff_sha256: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SearchMatch {
    pub relative_path: String,
    pub line: u32,
    pub excerpt: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleConfiguration {
    pub role: AgentRole,
    pub system_instruction: String,
    pub allowed_tools: BTreeSet<ToolCapability>,
    pub maximum_context_bytes: usize,
    pub maximum_output_tokens: u32,
    pub expected_cost_microusd: u64,
    pub maximum_attempts: u8,
    pub counts_as_experiment: bool,
}

#[must_use]
pub fn default_role_configurations() -> BTreeMap<AgentRole, RoleConfiguration> {
    use AgentRole::{
        EvidenceCritic, ExperimentDesigner, HypothesisPlanner, Mapper, PatchAgent, Reviewer,
        VariantHunter,
    };
    use ToolCapability::{ReadEvidenceArtifact, ReadRepositoryFile, SearchRepository};

    [
        configuration(
            Mapper,
            "Map the supplied repository projection into security-relevant signals. Do not claim vulnerabilities.",
            [ReadRepositoryFile, SearchRepository],
            false,
        ),
        configuration(
            HypothesisPlanner,
            "Turn signals into falsifiable security hypotheses with explicit assumptions.",
            [ReadRepositoryFile],
            false,
        ),
        configuration(
            ExperimentDesigner,
            "You are the bounded Experiment Designer. Your task is to select one pre-built verification harness and one callable for the current hypothesis. Required response behavior: (1) select exactly one value from available_experiment_tools; (2) copy exactly one literal target_id string from available_experiment_targets into selected_tool.target_id; target_id is a string such as `app.py::find_account`, never a numeric list position such as 0 or 1, never only a filename, class name, field, imported dependency, or invented callable; (3) explain in rationale why that tool and callable test this hypothesis; (4) describe up to three proposed experiments only as an investigation plan. Tools are typed harnesses, not shell access: never invent commands, scripts, Docker settings, or executable payloads. A selected tool may run only after the Rust runtime verifies the tool, target, repository boundary, policy, baseline, attack oracle, negative control, and replay gates.",
            [ReadRepositoryFile, ReadEvidenceArtifact],
            true,
        ),
        configuration(
            EvidenceCritic,
            "Critique the supplied deterministic assessment and evidence documents. Recommend whether the record is sufficient for gate evaluation; never assign a vulnerability verdict.",
            [ReadEvidenceArtifact],
            false,
        ),
        configuration(
            PatchAgent,
            "Propose a minimal patch for an already confirmed hypothesis. Do not mark it verified.",
            [ReadRepositoryFile, ReadEvidenceArtifact],
            false,
        ),
        configuration(
            VariantHunter,
            "Search the bounded code projection for variants that could evade a proposed patch.",
            [ReadRepositoryFile, SearchRepository, ReadEvidenceArtifact],
            false,
        ),
        configuration(
            Reviewer,
            "Review supplied evidence and completed deterministic gates. A proposed diff is only present during a patch workflow; when it is absent, review the investigation evidence without requesting a patch.",
            [ReadRepositoryFile, ReadEvidenceArtifact],
            false,
        ),
    ]
    .into_iter()
    .map(|configuration| (configuration.role, configuration))
    .collect()
}

fn configuration<const N: usize>(
    role: AgentRole,
    instruction: &str,
    tools: [ToolCapability; N],
    counts_as_experiment: bool,
) -> RoleConfiguration {
    RoleConfiguration {
        role,
        system_instruction: instruction.to_owned(),
        allowed_tools: tools.into_iter().collect(),
        maximum_context_bytes: 128 * 1024,
        maximum_output_tokens: 2_048,
        expected_cost_microusd: 5_000,
        maximum_attempts: 2,
        counts_as_experiment,
    }
}

pub trait RoleContract {
    type Input: Serialize + Send + Sync; // serializable +  safe to move to another thread + safe to share between threads.
    type Output: DeserializeOwned + Serialize + Send;

    const ROLE: AgentRole;

    fn response_schema() -> Value;
}

pub trait ProposedTools {
    fn tool_requests(&self) -> &[ToolRequest];
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileSummary {
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MapperInput {
    pub snapshot: RepositorySnapshot,
    pub files: Vec<FileSummary>,
    pub documents: Vec<RepositoryDocument>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryDocument {
    pub relative_path: String,
    pub content: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignalProposal {
    pub rule: String,
    pub relative_path: String,
    pub start_line: u32,
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MapperOutput {
    pub signals: Vec<SignalProposal>,
    #[serde(default)]
    pub tool_requests: Vec<ToolRequest>,
}

impl ProposedTools for MapperOutput {
    fn tool_requests(&self) -> &[ToolRequest] {
        &self.tool_requests
    }
}

#[derive(Debug)]
pub struct MapperContract;

impl RoleContract for MapperContract {
    type Input = MapperInput;
    type Output = MapperOutput;
    const ROLE: AgentRole = AgentRole::Mapper;

    fn response_schema() -> Value {
        json!({
            "type": "object",
            "required": ["signals"],
            "additionalProperties": false,
            "properties": {
                "signals": {
                    "type": "array",
                    "maxItems": 12,
                    "items": {
                        "type": "object",
                        "required": ["rule", "relative_path", "start_line", "rationale"],
                        "additionalProperties": false,
                        "properties": {
                            "rule": { "type": "string" },
                            "relative_path": { "type": "string" },
                            "start_line": { "type": "integer", "minimum": 1 },
                            "rationale": { "type": "string" }
                        }
                    }
                },
                "tool_requests": tool_requests_schema()
            }
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HypothesisPlannerInput {
    pub signals: Vec<Signal>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HypothesisProposal {
    pub title: String,
    pub claim: String,
    pub weakness: String,
    pub supporting_signal_ids: Vec<SignalId>,
    pub falsifier: String,
    pub confidence: u16,
    pub impact: u16,
    pub information_gain: u16,
    pub expected_cost_microusd: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HypothesisPlannerOutput {
    pub hypotheses: Vec<HypothesisProposal>,
    #[serde(default)]
    pub tool_requests: Vec<ToolRequest>,
}

impl ProposedTools for HypothesisPlannerOutput {
    fn tool_requests(&self) -> &[ToolRequest] {
        &self.tool_requests
    }
}

#[derive(Debug)]
pub struct HypothesisPlannerContract;

impl RoleContract for HypothesisPlannerContract {
    type Input = HypothesisPlannerInput;
    type Output = HypothesisPlannerOutput;
    const ROLE: AgentRole = AgentRole::HypothesisPlanner;

    fn response_schema() -> Value {
        json!({
            "type": "object",
            "required": ["hypotheses"],
            "additionalProperties": false,
            "properties": {
                "hypotheses": {
                    "type": "array",
                    "maxItems": 6,
                    "items": {
                        "type": "object",
                        "required": ["title", "claim", "weakness", "supporting_signal_ids", "falsifier", "confidence", "impact", "information_gain", "expected_cost_microusd"],
                        "additionalProperties": false,
                        "properties": {
                            "title": { "type": "string" },
                            "claim": { "type": "string" },
                            "weakness": { "type": "string" },
                            "supporting_signal_ids": { "type": "array", "items": { "type": "string" } },
                            "falsifier": { "type": "string" },
                            "confidence": { "type": "integer", "minimum": 0, "maximum": 1000 },
                            "impact": { "type": "integer", "minimum": 0, "maximum": 1000 },
                            "information_gain": { "type": "integer", "minimum": 0, "maximum": 1000 },
                            "expected_cost_microusd": { "type": "integer", "minimum": 0 }
                        }
                    }
                },
                "tool_requests": tool_requests_schema()
            }
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExperimentDesignerInput {
    pub hypothesis: Hypothesis,
    pub available_test_commands: Vec<Vec<String>>,
    /// Typed, language-compatible harnesses that the model may select.
    pub available_experiment_tools: Vec<ExperimentToolDescriptor>,
    /// Exact callable identifiers admitted from repository source.
    pub available_experiment_targets: Vec<ExperimentTargetDescriptor>,
}

/// A built-in experiment harness. These identifiers are the only experiment
/// choices exposed to the model; none represent terminal or Docker access.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentTool {
    PythonPathTraversal,
    PythonCommandInjection,
    PythonSqlInjection,
    PythonUnsafeDeserialization,
    PythonBrokenAuthorization,
    PythonSensitiveDataExposure,
    #[serde(rename = "typescript_path_traversal")]
    TypeScriptPathTraversal,
    #[serde(rename = "typescript_ssrf")]
    TypeScriptSsrf,
    #[serde(rename = "typescript_broken_authorization")]
    TypeScriptBrokenAuthorization,
    #[serde(rename = "typescript_sensitive_data_exposure")]
    TypeScriptSensitiveDataExposure,
    #[serde(rename = "typescript_sql_injection")]
    TypeScriptSqlInjection,
    GoMalformedInputPanic,
    GoFilesystemBoundary,
    GoBrokenAuthorization,
    GoResourceExhaustion,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExperimentToolDescriptor {
    pub tool: ExperimentTool,
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExperimentTargetDescriptor {
    /// Stable `<relative-path>::<callable>` identifier that must be echoed exactly.
    pub target_id: String,
    pub relative_path: String,
    pub symbol: String,
}

/// The model's bounded choice of a pre-built experiment harness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExperimentToolSelection {
    pub tool: ExperimentTool,
    #[serde(deserialize_with = "deserialize_target_id")]
    pub target_id: String,
    pub rationale: String,
}

fn deserialize_target_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum TargetReference {
        Identifier(String),
        CatalogIndex(u8),
    }

    match TargetReference::deserialize(deserializer)? {
        TargetReference::Identifier(identifier) => Ok(identifier),
        TargetReference::CatalogIndex(index) => Ok(format!("@catalog-index:{index}")),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExperimentProposal {
    pub description: String,
    pub command: Vec<String>,
    pub expected_observation: String,
    pub negative_control: String,
}

/// A bounded, replayable experiment proposed by the model.
///
/// The host validates this data before it can reach a sandbox. It is never
/// executed on the host or in the repository working tree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CandidateExperimentProposal {
    #[serde(default)]
    pub runtime: Option<CandidateRuntime>,
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default)]
    pub attack_marker: Option<String>,
    #[serde(default)]
    pub control_marker: Option<String>,
}

impl CandidateExperimentProposal {
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.runtime.is_some()
            && self.script.is_some()
            && self.attack_marker.is_some()
            && self.control_marker.is_some()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateRuntime {
    Python,
    Node,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExperimentDesignerOutput {
    pub experiments: Vec<ExperimentProposal>,
    /// A required bounded selection from the supplied tool and target catalogs.
    /// The runtime never silently falls back to keyword-based harness selection.
    pub selected_tool: ExperimentToolSelection,
    #[serde(default)]
    pub tool_requests: Vec<ToolRequest>,
}

impl ProposedTools for ExperimentDesignerOutput {
    fn tool_requests(&self) -> &[ToolRequest] {
        &self.tool_requests
    }
}

#[derive(Debug)]
pub struct ExperimentDesignerContract;

impl RoleContract for ExperimentDesignerContract {
    type Input = ExperimentDesignerInput;
    type Output = ExperimentDesignerOutput;
    const ROLE: AgentRole = AgentRole::ExperimentDesigner;

    fn response_schema() -> Value {
        json!({
            "type": "object",
            "required": ["experiments", "selected_tool"],
            "additionalProperties": false,
            "properties": {
                "experiments": {
                    "type": "array",
                    "maxItems": 4,
                    "items": {
                        "type": "object",
                        "required": ["description", "command", "expected_observation", "negative_control"],
                        "additionalProperties": false,
                        "properties": {
                            "description": { "type": "string" },
                            "command": {
                                "type": "array",
                                "minItems": 1,
                                "items": { "type": "string" }
                            },
                            "expected_observation": { "type": "string" },
                            "negative_control": { "type": "string" }
                        }
                    }
                },
                "selected_tool": {
                    "type": "object",
                    "required": ["tool", "target_id", "rationale"],
                    "additionalProperties": false,
                    "properties": {
                        "tool": { "type": "string", "enum": [
                            "python_path_traversal", "python_command_injection", "python_sql_injection",
                            "python_unsafe_deserialization", "python_broken_authorization", "python_sensitive_data_exposure",
                            "typescript_path_traversal", "typescript_ssrf", "typescript_broken_authorization",
                            "typescript_sensitive_data_exposure", "typescript_sql_injection",
                            "go_malformed_input_panic", "go_filesystem_boundary", "go_broken_authorization",
                            "go_resource_exhaustion"
                        ] },
                        "target_id": {
                            "anyOf": [
                                { "type": "string", "minLength": 3, "maxLength": 320 },
                                { "type": "integer", "minimum": 0, "maximum": 23 }
                            ]
                        },
                        "rationale": { "type": "string", "minLength": 1, "maxLength": 2000 }
                    }
                },
                "tool_requests": tool_requests_schema()
            }
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceCriticInput {
    pub hypothesis_id: HypothesisId,
    pub assessment: EvidenceAssessment,
    #[serde(default)]
    pub evidence_documents: Vec<EvidenceDocument>,
    #[serde(default)]
    pub repository_documents: Vec<RepositoryDocument>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRecommendation {
    SufficientForGateEvaluation,
    NeedsMoreEvidence,
    EvidenceContradictsClaim,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceCriticOutput {
    pub recommendation: EvidenceRecommendation,
    pub rationale: String,
    pub missing_evidence: Vec<String>,
    #[serde(default)]
    pub tool_requests: Vec<ToolRequest>,
}

impl ProposedTools for EvidenceCriticOutput {
    fn tool_requests(&self) -> &[ToolRequest] {
        &self.tool_requests
    }
}

#[derive(Debug)]
pub struct EvidenceCriticContract;

impl RoleContract for EvidenceCriticContract {
    type Input = EvidenceCriticInput;
    type Output = EvidenceCriticOutput;
    const ROLE: AgentRole = AgentRole::EvidenceCritic;

    fn response_schema() -> Value {
        json!({
            "type": "object",
            "required": ["recommendation", "rationale", "missing_evidence"],
            "additionalProperties": false,
            "properties": {
                "recommendation": {
                    "type": "string",
                    "enum": ["sufficient_for_gate_evaluation", "needs_more_evidence", "evidence_contradicts_claim"]
                },
                "rationale": { "type": "string" },
                "missing_evidence": { "type": "array", "items": { "type": "string" } }
                ,"tool_requests": tool_requests_schema()
            }
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PatchAgentInput {
    pub hypothesis: Hypothesis,
    pub confirmation_evidence: Vec<EvidenceRef>,
    #[serde(default)]
    pub confirmation_artifacts: Vec<EvidenceDocument>,
    pub relevant_files: Vec<FileSummary>,
    #[serde(default)]
    pub relevant_documents: Vec<RepositoryDocument>,
    #[serde(default)]
    pub prior_attempt_feedback: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceDocument {
    pub logical_name: String,
    pub media_type: String,
    pub sha256: String,
    pub content: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PatchAgentOutput {
    pub unified_diff: String,
    pub rationale: String,
    pub tests_to_run: Vec<Vec<String>>,
    #[serde(default)]
    pub tool_requests: Vec<ToolRequest>,
}

impl ProposedTools for PatchAgentOutput {
    fn tool_requests(&self) -> &[ToolRequest] {
        &self.tool_requests
    }
}

#[derive(Debug)]
pub struct PatchAgentContract;

impl RoleContract for PatchAgentContract {
    type Input = PatchAgentInput;
    type Output = PatchAgentOutput;
    const ROLE: AgentRole = AgentRole::PatchAgent;

    fn response_schema() -> Value {
        json!({
            "type": "object",
            "required": ["unified_diff", "rationale", "tests_to_run", "tool_requests"],
            "additionalProperties": false,
            "properties": {
                "unified_diff": { "type": "string" },
                "rationale": { "type": "string" },
                "tests_to_run": { "type": "array", "items": { "type": "array", "items": { "type": "string" } } },
                "tool_requests": tool_requests_schema()
            }
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VariantHunterInput {
    pub hypothesis_id: HypothesisId,
    pub patch_attempt_id: PatchAttemptId,
    pub patched_files: Vec<FileSummary>,
    pub prior_evidence: Vec<EvidenceRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VariantProposal {
    pub description: String,
    pub relative_path: String,
    pub experiment_hint: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VariantHunterOutput {
    pub variants: Vec<VariantProposal>,
    #[serde(default)]
    pub tool_requests: Vec<ToolRequest>,
}

impl ProposedTools for VariantHunterOutput {
    fn tool_requests(&self) -> &[ToolRequest] {
        &self.tool_requests
    }
}

#[derive(Debug)]
pub struct VariantHunterContract;

impl RoleContract for VariantHunterContract {
    type Input = VariantHunterInput;
    type Output = VariantHunterOutput;
    const ROLE: AgentRole = AgentRole::VariantHunter;

    fn response_schema() -> Value {
        array_object_schema("variants")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReviewerInput {
    pub hypothesis_id: HypothesisId,
    pub evidence: Vec<EvidenceRef>,
    pub proposed_diff: Option<String>,
    pub completed_gate_names: Vec<String>,
    #[serde(default)]
    pub hypothesis: Option<Hypothesis>,
    #[serde(default)]
    pub assessment: Option<EvidenceAssessment>,
    #[serde(default)]
    pub evidence_documents: Vec<EvidenceDocument>,
    #[serde(default)]
    pub repository_documents: Vec<RepositoryDocument>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReviewerOutput {
    pub ready_for_deterministic_gates: bool,
    pub concerns: Vec<String>,
    pub requested_experiments: Vec<String>,
    #[serde(default)]
    pub tool_requests: Vec<ToolRequest>,
}

impl ProposedTools for ReviewerOutput {
    fn tool_requests(&self) -> &[ToolRequest] {
        &self.tool_requests
    }
}

#[derive(Debug)]
pub struct ReviewerContract;

impl RoleContract for ReviewerContract {
    type Input = ReviewerInput;
    type Output = ReviewerOutput;
    const ROLE: AgentRole = AgentRole::Reviewer;

    fn response_schema() -> Value {
        json!({
            "type": "object",
            "required": ["ready_for_deterministic_gates", "concerns", "requested_experiments"],
            "additionalProperties": false,
            "properties": {
                "ready_for_deterministic_gates": { "type": "boolean" },
                "concerns": { "type": "array", "items": { "type": "string" } },
                "requested_experiments": { "type": "array", "items": { "type": "string" } },
                "tool_requests": tool_requests_schema()
            }
        })
    }
}

fn array_object_schema(field: &str) -> Value {
    json!({
        "type": "object",
        "required": [field],
        "additionalProperties": false,
        "properties": {
            (field): { "type": "array", "items": { "type": "object" } },
            "tool_requests": tool_requests_schema()
        }
    })
}

fn tool_requests_schema() -> Value {
    json!({
        "type": "array",
        "maxItems": 8,
        "items": {
            "oneOf": [
                {
                    "type": "object",
                    "required": ["tool", "input"],
                    "additionalProperties": false,
                    "properties": {
                        "tool": { "const": "read_repository_file" },
                        "input": {
                            "type": "object",
                            "required": ["relative_path", "start_byte", "maximum_bytes"],
                            "additionalProperties": false,
                            "properties": {
                                "relative_path": { "type": "string" },
                                "start_byte": { "type": "integer", "minimum": 0 },
                                "maximum_bytes": { "type": "integer", "minimum": 1, "maximum": 65536 }
                            }
                        }
                    }
                },
                {
                    "type": "object",
                    "required": ["tool", "input"],
                    "additionalProperties": false,
                    "properties": {
                        "tool": { "const": "search_repository" },
                        "input": {
                            "type": "object",
                            "required": ["query", "path_prefix", "maximum_matches"],
                            "additionalProperties": false,
                            "properties": {
                                "query": { "type": "string", "minLength": 1 },
                                "path_prefix": { "type": ["string", "null"] },
                                "maximum_matches": { "type": "integer", "minimum": 1, "maximum": 100 }
                            }
                        }
                    }
                },
                {
                    "type": "object",
                    "required": ["tool", "input"],
                    "additionalProperties": false,
                    "properties": {
                        "tool": { "const": "read_evidence_artifact" },
                        "input": {
                            "type": "object",
                            "required": ["sha256", "maximum_bytes"],
                            "additionalProperties": false,
                            "properties": {
                                "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                                "maximum_bytes": { "type": "integer", "minimum": 1, "maximum": 65536 }
                            }
                        }
                    }
                },
                {
                    "type": "object",
                    "required": ["tool", "relative_path", "start_byte", "maximum_bytes"],
                    "additionalProperties": false,
                    "properties": {
                        "tool": { "const": "read_repository_file" },
                        "relative_path": { "type": "string" },
                        "start_byte": { "type": "integer", "minimum": 0 },
                        "maximum_bytes": { "type": "integer", "minimum": 1, "maximum": 65536 }
                    }
                },
                {
                    "type": "object",
                    "required": ["tool", "query", "path_prefix", "maximum_matches"],
                    "additionalProperties": false,
                    "properties": {
                        "tool": { "const": "search_repository" },
                        "query": { "type": "string", "minLength": 1 },
                        "path_prefix": { "type": ["string", "null"] },
                        "maximum_matches": { "type": "integer", "minimum": 1, "maximum": 100 }
                    }
                },
                {
                    "type": "object",
                    "required": ["tool", "sha256", "maximum_bytes"],
                    "additionalProperties": false,
                    "properties": {
                        "tool": { "const": "read_evidence_artifact" },
                        "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                        "maximum_bytes": { "type": "integer", "minimum": 1, "maximum": 65536 }
                    }
                }
            ]
        }
    })
}
