"""AI provider configuration."""

import os
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


class AIProvider(Enum):
    """Supported AI providers."""
    BEDROCK = "bedrock"
    OPENAI = "openai"
    OLLAMA = "ollama"
    NONE = "none"  # AI disabled — pure static scanning


DEFAULT_MODELS = {
    AIProvider.BEDROCK: "us.anthropic.claude-sonnet-4-20250514-v1:0",
    AIProvider.OPENAI: "gpt-4o",
    AIProvider.OLLAMA: "llama3.1",
}


@dataclass
class AIConfig:
    """AI enhancement configuration."""

    provider: AIProvider = AIProvider.NONE
    model_id: Optional[str] = None
    aws_region: str = field(default_factory=lambda: os.environ.get("AWS_REGION", "us-east-1"))
    openai_api_key: Optional[str] = field(default_factory=lambda: os.environ.get("OPENAI_API_KEY"))
    ollama_base_url: str = field(default_factory=lambda: os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"))
    temperature: float = 0.0

    def __post_init__(self):
        if self.provider == AIProvider.OPENAI and not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY environment variable required for OpenAI provider")

    @property
    def enabled(self) -> bool:
        return self.provider != AIProvider.NONE

    def get_model_id(self) -> str:
        return self.model_id or DEFAULT_MODELS.get(self.provider, "")
