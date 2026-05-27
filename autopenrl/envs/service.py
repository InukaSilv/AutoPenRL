"""Service data model for network hosts."""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class Protocol(str, Enum):
    """Network protocol enumeration."""
    TCP = "tcp"
    UDP = "udp"


class Service(BaseModel):
    """Service data model representing a service running on a host.
    
    Attributes:
        port: Port number the service listens on
        protocol: Network protocol (TCP/UDP)
        name: Service name (e.g., 'apache', 'ssh')
        version: Service version string
        is_running: Whether the service is currently running
        vulnerabilities: List of known vulnerabilities affecting this service
    """
    
    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: Protocol = Field(default=Protocol.TCP, description="Network protocol")
    name: str = Field(..., description="Service name")
    version: str = Field(..., description="Service version")
    is_running: bool = Field(default=True, description="Whether service is running")
    vulnerabilities: List['Vulnerability'] = Field(default_factory=list, description="Known vulnerabilities")
    
    def __str__(self) -> str:
        """Return string representation of service."""
        return f"{self.name}@{self.version} ({self.protocol.value}:{self.port})"


from .vulnerability import Vulnerability
Service.model_rebuild()
