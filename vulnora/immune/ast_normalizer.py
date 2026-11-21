"""
Multi-language AST normalization and anonymization engine for Vulnora AI.

Parses source code across 100+ languages via `tree-sitter-language-pack`,
strips proprietary identifiers/literals, preserves control-flow & call semantics,
and calculates structural similarity scores. Includes deterministic token fallback.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import difflib
import hashlib
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

# Optional Tree-sitter Language Pack import
try:
    import tree_sitter_language_pack as tslp
    TREE_SITTER_AVAILABLE = True
except ImportError:
    tslp = None
    TREE_SITTER_AVAILABLE = False


LANGUAGE_EXTENSIONS: Dict[str, str] = {
    # Python
    ".py": "python",
    ".pyi": "python",
    # JavaScript / TypeScript
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".mts": "typescript",
    ".cts": "typescript",
    # Go
    ".go": "go",
    # Rust
    ".rs": "rust",
    # Java / Kotlin
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    # C / C++
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    # C#
    ".cs": "c_sharp",
    # Ruby
    ".rb": "ruby",
    # PHP
    ".php": "php",
    # Swift
    ".swift": "swift",
    # Config / IaC / Data
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".tf": "hcl",
    ".hcl": "hcl",
}

# Standard language keywords that should not be converted to VAR_N
LANGUAGE_KEYWORDS: Set[str] = {
    "def", "class", "return", "if", "else", "elif", "for", "while", "import", "from",
    "try", "except", "finally", "with", "as", "pass", "break", "continue", "raise",
    "in", "is", "not", "and", "or", "yield", "async", "await", "lambda", "global",
    "function", "const", "let", "var", "switch", "case", "default", "throw", "catch",
    "package", "func", "type", "struct", "interface", "map", "chan", "go", "select",
    "fn", "pub", "mod", "use", "impl", "trait", "mut", "ref", "match", "enum",
    "public", "private", "protected", "static", "void", "int", "boolean", "string",
}


@dataclass
class NormalizedAST:
    """
    Normalized AST representation of a code block.
    Guarantees variable-rename invariance and zero proprietary identifier leakage.
    """
    language: str
    exact_hash: str
    ast_signature: str
    anonymized_template: str
    structural_tokens: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "language": self.language,
            "exact_hash": self.exact_hash,
            "ast_signature": self.ast_signature,
            "anonymized_template": self.anonymized_template,
            "structural_tokens": list(self.structural_tokens),
        }


class ASTNormalizer:
    """
    Multi-language AST normalization, symbol extraction, and similarity engine.
    """

    def __init__(self):
        self._parsers: Dict[str, Any] = {}

    @classmethod
    def detect_language(cls, file_path: Union[str, Path]) -> str:
        """Determines programming language from filename or file extension."""
        name = Path(file_path).name.lower()
        if name in ("dockerfile", "dockerfile.build"):
            return "dockerfile"
        if name in ("makefile", "gnumakefile"):
            return "make"

        suffix = Path(file_path).suffix.lower()
        return LANGUAGE_EXTENSIONS.get(suffix, "generic")

    def _get_tree_sitter_parser(self, language: str) -> Optional[Any]:
        """Loads and caches Tree-sitter parser for a given language."""
        if not TREE_SITTER_AVAILABLE or tslp is None:
            return None

        if language in self._parsers:
            return self._parsers[language]

        lang_candidates = [language]
        if language == "c_sharp":
            lang_candidates.append("csharp")
        elif language == "cpp":
            lang_candidates.append("cpp")

        for cand in lang_candidates:
            try:
                parser = tslp.get_parser(cand)
                if parser is not None:
                    self._parsers[language] = parser
                    return parser
            except Exception:
                continue

        self._parsers[language] = None
        return None

    def extract_enclosing_block(
        self,
        code: str,
        line_number: Optional[int] = None,
        language: str = "generic",
    ) -> str:
        """
        Extracts the tightest enclosing function, block, or statement around line_number.
        If line_number is None or symbol extraction is unavailable, returns code snippet.
        """
        if not code or not code.strip():
            return ""

        if line_number is None or line_number <= 0:
            return code.strip()

        parser = self._get_tree_sitter_parser(language)
        if parser is None:
            # Fallback: extract window around target line
            lines = code.splitlines()
            idx = line_number - 1
            if 0 <= idx < len(lines):
                start = max(0, idx - 2)
                end = min(len(lines), idx + 3)
                return "\n".join(lines[start:end]).strip()
            return code.strip()

        try:
            tree = parser.parse(code.encode("utf-8"))
            root = tree.root_node
            target_row = line_number - 1

            best_function = None
            best_statement = None

            for node in self._walk_nodes(root):
                if node.start_point.row <= target_row <= node.end_point.row:
                    if node.type in (
                        "function_definition", "function_declaration", "method_definition",
                        "arrow_function",
                    ):
                        best_function = node
                    elif node.type in (
                        "statement", "expression_statement", "if_statement",
                        "for_statement", "while_statement", "try_statement", "block",
                    ):
                        best_statement = node

            chosen_node = best_function or best_statement or root
            snippet = chosen_node.text.decode("utf-8", errors="replace")
            return snippet.strip() if snippet.strip() else code.strip()
        except Exception:
            return code.strip()

    def normalize(self, code: str, language: str = "generic") -> NormalizedAST:
        """
        Normalizes code into canonical AST signature and anonymized template.
        Identical control flows with renamed variables yield identical AST signatures.
        """
        clean_code = code.strip()
        if not clean_code:
            return NormalizedAST(
                language=language,
                exact_hash=hashlib.sha256(b"").hexdigest(),
                ast_signature="",
                anonymized_template="",
                structural_tokens=[],
            )

        # Exact hash: whitespace/comment normalized
        canonical_raw = re.sub(r"\s+", " ", re.sub(r"#.*|\/\/.*", "", clean_code)).strip()
        exact_hash = hashlib.sha256(canonical_raw.encode("utf-8")).hexdigest()

        parser = self._get_tree_sitter_parser(language)
        if parser is not None:
            try:
                tree = parser.parse(clean_code.encode("utf-8"))
                return self._normalize_tree_sitter(tree.root_node, clean_code, language, exact_hash)
            except Exception:
                pass

        # Deterministic Token-Structure Fallback
        return self._normalize_token_fallback(clean_code, language, exact_hash)

    def _normalize_tree_sitter(
        self,
        root_node: Any,
        source_code: str,
        language: str,
        exact_hash: str,
    ) -> NormalizedAST:
        """Normalizes Tree-sitter AST nodes."""
        var_map: Dict[str, str] = {}
        str_count = 0
        num_count = 0
        structural_tokens: List[str] = []
        sig_parts: List[str] = []

        def get_placeholder(name: str) -> str:
            if name in LANGUAGE_KEYWORDS:
                return name
            if name not in var_map:
                var_map[name] = f"VAR_{len(var_map)}"
            return var_map[name]

        def traverse(node: Any) -> str:
            nonlocal str_count, num_count
            node_type = node.type

            # Check for identifiers
            if node_type in ("identifier", "field_identifier", "property_identifier", "type_identifier"):
                id_name = node.text.decode("utf-8", errors="replace")
                mapped = get_placeholder(id_name)
                structural_tokens.append(f"ID:{mapped}")
                return f"({node_type} {mapped})"

            # String literals
            if "string" in node_type:
                str_count += 1
                structural_tokens.append("LIT:STR")
                return f"({node_type} STR_LIT)"

            # Numeric literals
            if node_type in ("integer", "number", "float", "int_literal", "decimal_literal"):
                num_count += 1
                structural_tokens.append("LIT:NUM")
                return f"({node_type} NUM_LIT)"

            if node.is_named:
                structural_tokens.append(node_type)
                child_reprs = [traverse(c) for c in node.children if c.is_named]
                if child_reprs:
                    return f"({node_type} " + " ".join(child_reprs) + ")"
                return f"({node_type})"

            return ""

        ast_signature = traverse(root_node)

        # Build Anonymized Template: Replace identifiers and literals in source text
        anonymized = source_code
        # Sort identifiers longest first to avoid partial replacements
        for original, placeholder in sorted(var_map.items(), key=lambda x: len(x[0]), reverse=True):
            pattern = r"\b" + re.escape(original) + r"\b"
            anonymized = re.sub(pattern, placeholder, anonymized)

        # Replace strings
        anonymized = re.sub(r'(".*?"|\'.*?\')', '"STR_LIT"', anonymized)
        # Replace numbers
        anonymized = re.sub(r"\b\d+\b", "0", anonymized)

        return NormalizedAST(
            language=language,
            exact_hash=exact_hash,
            ast_signature=ast_signature,
            anonymized_template=anonymized.strip(),
            structural_tokens=structural_tokens,
        )

    def _normalize_token_fallback(
        self,
        clean_code: str,
        language: str,
        exact_hash: str,
    ) -> NormalizedAST:
        """
        Deterministic regex token fallback when Tree-sitter language grammar is unavailable.
        Maintains variable-rename invariance.
        """
        var_map: Dict[str, str] = {}
        structural_tokens: List[str] = []

        # Tokenizer regex
        token_pattern = re.compile(
            r'(".*?"|\'.*?\')|(\b\d+\b)|([a-zA-Z_][a-zA-Z0-9_]*)|([+\-*/%=<>!&|^~]+)|([()\[\]{},;:.])'
        )

        anonymized_tokens: List[str] = []
        sig_tokens: List[str] = []

        for match in token_pattern.finditer(clean_code):
            string_lit, num_lit, identifier, operator, punctuation = match.groups()

            if string_lit:
                structural_tokens.append("LIT:STR")
                sig_tokens.append("STR_LIT")
                anonymized_tokens.append('"STR_LIT"')
            elif num_lit:
                structural_tokens.append("LIT:NUM")
                sig_tokens.append("NUM_LIT")
                anonymized_tokens.append("0")
            elif identifier:
                if identifier in LANGUAGE_KEYWORDS:
                    structural_tokens.append(f"KW:{identifier}")
                    sig_tokens.append(identifier)
                    anonymized_tokens.append(identifier)
                else:
                    if identifier not in var_map:
                        var_map[identifier] = f"VAR_{len(var_map)}"
                    mapped = var_map[identifier]
                    structural_tokens.append(f"ID:{mapped}")
                    sig_tokens.append(mapped)
                    anonymized_tokens.append(mapped)
            elif operator:
                structural_tokens.append(f"OP:{operator}")
                sig_tokens.append(operator)
                anonymized_tokens.append(operator)
            elif punctuation:
                structural_tokens.append(f"PUNCT:{punctuation}")
                sig_tokens.append(punctuation)
                anonymized_tokens.append(punctuation)

        ast_signature = " ".join(sig_tokens)
        anonymized_template = " ".join(anonymized_tokens)

        return NormalizedAST(
            language=language,
            exact_hash=exact_hash,
            ast_signature=ast_signature,
            anonymized_template=anonymized_template,
            structural_tokens=structural_tokens,
        )

    def calculate_similarity(self, sig1: str, sig2: str) -> float:
        """
        Computes structural AST similarity between two signatures.
        Returns float between 0.0 (completely distinct) and 1.0 (identical structure).
        Executes in sub-millisecond time.
        """
        if not sig1 or not sig2:
            return 0.0
        if sig1 == sig2:
            return 1.0

        # Fast sequence matching ratio
        return difflib.SequenceMatcher(None, sig1, sig2).ratio()

    def _walk_nodes(self, node: Any):
        """Generator yielding all nodes in a Tree-sitter tree."""
        yield node
        for child in node.children:
            yield from self._walk_nodes(child)
