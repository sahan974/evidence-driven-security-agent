use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::SCHEMA_VERSION;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Python,
    TypeScript,
    JavaScript,
    Go,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestKind {
    PythonProject,
    PythonRequirements,
    PythonSetup,
    PythonPipfile,
    NodePackage,
    TypeScriptConfig,
    GoModule,
    GoWorkspace,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DetectedManifest {
    pub schema_version: u16,
    pub relative_path: String,
    pub kind: ManifestKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LanguageDetection {
    pub schema_version: u16,
    pub languages: BTreeSet<Language>,
    pub manifests: Vec<DetectedManifest>,
}

pub(crate) fn detect(paths: &[String]) -> LanguageDetection {
    let mut languages = BTreeSet::new();
    let mut manifests = Vec::new();
    for relative_path in paths {
        let path = Path::new(relative_path);
        if let Some(language) = source_language(path) {
            languages.insert(language);
        }
        if let Some(kind) = manifest_kind(path) {
            manifests.push(DetectedManifest {
                schema_version: SCHEMA_VERSION,
                relative_path: relative_path.clone(),
                kind,
            });
            match kind {
                ManifestKind::PythonProject
                | ManifestKind::PythonRequirements
                | ManifestKind::PythonSetup
                | ManifestKind::PythonPipfile => {
                    languages.insert(Language::Python);
                }
                ManifestKind::TypeScriptConfig => {
                    languages.insert(Language::TypeScript);
                }
                ManifestKind::NodePackage => {
                    languages.insert(Language::JavaScript);
                }
                ManifestKind::GoModule | ManifestKind::GoWorkspace => {
                    languages.insert(Language::Go);
                }
            }
        }
    }
    manifests.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    LanguageDetection {
        schema_version: SCHEMA_VERSION,
        languages,
        manifests,
    }
}

fn source_language(path: &Path) -> Option<Language> {
    match path.extension().and_then(|extension| extension.to_str())? {
        "py" | "pyi" => Some(Language::Python),
        "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
        "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
        "go" => Some(Language::Go),
        _ => None,
    }
}

fn manifest_kind(path: &Path) -> Option<ManifestKind> {
    let name = path.file_name()?.to_str()?;
    match name {
        "pyproject.toml" => Some(ManifestKind::PythonProject),
        "setup.py" | "setup.cfg" => Some(ManifestKind::PythonSetup),
        "Pipfile" => Some(ManifestKind::PythonPipfile),
        "package.json" => Some(ManifestKind::NodePackage),
        "tsconfig.json" => Some(ManifestKind::TypeScriptConfig),
        "go.mod" => Some(ManifestKind::GoModule),
        "go.work" => Some(ManifestKind::GoWorkspace),
        name if name.starts_with("requirements")
            && path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("txt")) =>
        {
            Some(ManifestKind::PythonRequirements)
        }
        _ => None,
    }
}
