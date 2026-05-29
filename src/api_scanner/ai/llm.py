"""LLM provider abstraction for AI-enhanced scanning."""

from api_scanner.ai.config import AIConfig, AIProvider


def create_llm(config: AIConfig):
    """Create LLM client based on provider config."""
    if config.provider == AIProvider.BEDROCK:
        from langchain_aws import ChatBedrockConverse
        return ChatBedrockConverse(
            model=config.get_model_id(),
            region_name=config.aws_region,
            temperature=config.temperature,
            max_tokens=4096,
        )
    elif config.provider == AIProvider.OPENAI:
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=config.get_model_id(),
            api_key=config.openai_api_key,
            temperature=config.temperature,
            max_tokens=4096,
        )
    elif config.provider == AIProvider.OLLAMA:
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=config.get_model_id(),
            base_url=config.ollama_base_url,
            temperature=config.temperature,
            num_predict=4096,
        )
    else:
        raise ValueError(f"Cannot create LLM for provider: {config.provider}")
