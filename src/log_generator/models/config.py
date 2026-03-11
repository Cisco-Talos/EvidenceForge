"""Configuration models for EvidenceForge.

This module defines Pydantic models for the application configuration file (config.yaml).
All configuration models are frozen (immutable) to prevent accidental modification.

Note: Environment variable interpolation (${VAR_NAME}) is handled by utils/config.py
loader, not by these Pydantic models.
"""

from pydantic import BaseModel, ConfigDict, Field


class AWSConfig(BaseModel):
    """AWS configuration for Bedrock access.

    Attributes:
        profile: AWS profile name (from ~/.aws/credentials)
        region: AWS region where Bedrock is available
    """

    profile: str = Field(default="default", description="AWS profile name")
    region: str = Field(default="us-east-1", description="AWS region")

    model_config = ConfigDict(frozen=True, extra="forbid")


class BedrockConfig(BaseModel):
    """AWS Bedrock model configuration.

    Attributes:
        model_primary: Primary model for conversation and semantic validation
        model_research: Model for MITRE ATT&CK TTP research
        model_generation: Model for bulk generation tasks (cost optimization)
    """

    model_primary: str = Field(
        default="anthropic.claude-sonnet-4-6-v1:0",
        description="Primary model for conversation/validation",
    )
    model_research: str = Field(
        default="anthropic.claude-sonnet-4-6-v1:0",
        description="Model for MITRE ATT&CK research",
    )
    model_generation: str = Field(
        default="anthropic.claude-haiku-4-5-v1:0",
        description="Model for bulk generation tasks",
    )

    model_config = ConfigDict(frozen=True, extra="forbid")


class OutputConfig(BaseModel):
    """Output configuration.

    Attributes:
        base_directory: Base directory for generated datasets.
                       Each generation run creates a timestamped subdirectory.
    """

    base_directory: str = Field(
        default="./output", description="Base directory for generated datasets"
    )

    model_config = ConfigDict(frozen=True, extra="forbid")


class LoggingConfig(BaseModel):
    """Logging configuration.

    Attributes:
        level: Overall logging level (debug|info|warning|error)
        console_level: Console output level (typically less verbose than file)
        file: Optional log file path. If None, logs only to console.
    """

    level: str = Field(
        default="info",
        pattern="^(debug|info|warning|error)$",
        description="Overall logging level",
    )
    console_level: str = Field(
        default="warning",
        pattern="^(debug|info|warning|error)$",
        description="Console logging level",
    )
    file: str | None = Field(default=None, description="Optional log file path")

    model_config = ConfigDict(frozen=True, extra="forbid")


class AppConfig(BaseModel):
    """Main application configuration.

    This is the root configuration model that encompasses all configuration sections.
    Typically loaded from config.yaml with environment variable interpolation.

    Attributes:
        aws: AWS and Bedrock configuration
        bedrock: Bedrock model selection
        output: Output directory configuration
        logging: Logging configuration
    """

    aws: AWSConfig = Field(default_factory=AWSConfig)
    bedrock: BedrockConfig = Field(default_factory=BedrockConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    model_config = ConfigDict(frozen=True, extra="forbid")
