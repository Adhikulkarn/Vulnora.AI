"""
AST Immune Memory and Antibody Pack System for Vulnora AI.

Turns any Git repository into a self-vaccinating codebase:
- Multi-language Tree-sitter AST normalization and variable-rename invariance.
- Sub-10ms 3-Tier local immune lookups against `.vulnora/memory.json`.
- Zero-leakage portable Antibody Packs (JSON & YAML).
"""

from vulnora.immune.antibody_pack import AntibodyPackError, AntibodyPackManager
from vulnora.immune.ast_normalizer import ASTNormalizer, NormalizedAST
from vulnora.immune.memory_store import ImmuneMemoryStore

__all__ = [
    "ASTNormalizer",
    "NormalizedAST",
    "ImmuneMemoryStore",
    "AntibodyPackManager",
    "AntibodyPackError",
]
