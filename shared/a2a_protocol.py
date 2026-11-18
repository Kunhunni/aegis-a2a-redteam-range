from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class AgentProvider(BaseModel):
    organization: str = "A2A System"
    url: str = ""


class AgentCapabilities(BaseModel):
    streaming: bool = True
    pushNotifications: bool = False
    stateTransitionHistory: bool = False


class AgentSkill(BaseModel):
    id: str
    name: str
    description: str
    inputModes: List[str] = ["text"]
    outputModes: List[str] = ["text"]
    tags: Optional[List[str]] = None


class AgentCard(BaseModel):
    name: str
    description: str
    url: str
    serviceEndpoint: str
    protocolVersion: str = "0.2"
    provider: AgentProvider = Field(default_factory=AgentProvider)
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)
    skills: List[AgentSkill]
    defaultInputModes: List[str] = ["text"]
    defaultOutputModes: List[str] = ["text"]
    securitySchemes: Dict[str, Any] = Field(default_factory=dict)
    security: List[Any] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class A2AWorkflowRequest(BaseModel):
    prompt: str = Field(..., description="Natural language workflow request")
    history: Optional[List[str]] = Field(
        default_factory=list,
        description="Prior conversation history for stateful multi-turn context"
    )
    workflow_id: Optional[str] = None


class A2ATaskSendRequest(BaseModel):
    task_id: Optional[str] = None
    skill_id: Optional[str] = None
    prompt: str = ""
    data: Optional[Dict[str, Any]] = Field(default_factory=dict)
    history: Optional[List[str]] = Field(default_factory=list)


class AgentRegistrationRequest(BaseModel):
    agent_id: str
    name: str
    description: str
    url: str
    serviceEndpoint: str
    skills: List[AgentSkill]
    tls_fingerprint: Optional[str] = "sha256:trusted-a2a-default-fingerprint-01"