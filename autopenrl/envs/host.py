"""Host data model for network penetration testing environment."""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field, field_validator


class OSType(str, Enum):
    """Operating system type enumeration."""
    LINUX = "linux"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class CompromiseLevel(str, Enum):
    """Host compromise level enumeration."""
    NONE = "none"
    USER = "user"
    ROOT = "root"
    DOMAIN_ADMIN = "domain_admin"


class Host(BaseModel):
    """Host data model representing a network host.
    
    Attributes:
        id: Unique identifier for the host
        ip: IP address of the host
        hostname: Hostname of the host
        os: Operating system type
        segment_id: Network segment identifier
        services: List of services running on the host
        is_compromised: Whether the host has been compromised
        compromise_level: Current compromise level on the host
        is_discovered: Whether the host has been discovered by the attacker
        is_target: Whether this is the target host for the attack
        detection_sensitivity: Detection sensitivity on a scale of 0.0-1.0
    """
    
    id: int = Field(..., description="Unique host identifier")
    ip: str = Field(..., description="IPv4 address of the host")
    hostname: str = Field(..., description="Hostname of the host")
    os: OSType = Field(default=OSType.UNKNOWN, description="Operating system type")
    segment_id: int = Field(default=0, description="Network segment identifier")
    is_compromised: bool = Field(default=False, description="Whether host is compromised")
    compromise_level: CompromiseLevel = Field(default=CompromiseLevel.NONE, description="Current compromise level")
    is_discovered: bool = Field(default=False, description="Whether host has been discovered")
    is_target: bool = Field(default=False, description="Whether this is the target host")
    detection_sensitivity: float = Field(default=0.5, ge=0.0, le=1.0, description="Detection sensitivity (0.0-1.0)")
    services: List['Service'] = Field(default_factory=list, description="Services running on the host")
    
    @field_validator('ip')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IPv4 address format."""
        parts = v.split('.')
        if len(parts) != 4:
            raise ValueError('Invalid IPv4 address')
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    raise ValueError('IPv4 octet out of range')
            except ValueError:
                raise ValueError('IPv4 octet must be numeric')
        return v
    
    def mark_discovered(self) -> None:
        """Mark the host as discovered."""
        self.is_discovered = True
    
    def compromise(self, level: CompromiseLevel) -> None:
        """Update host compromise status.
        
        Args:
            level: New compromise level to set
            
        Raises:
            ValueError: If attempting to downgrade compromise level
        """
        level_order = {CompromiseLevel.NONE: 0, CompromiseLevel.USER: 1, 
                      CompromiseLevel.ROOT: 2, CompromiseLevel.DOMAIN_ADMIN: 3}
        
        if level_order[level] < level_order[self.compromise_level]:
            raise ValueError("Cannot downgrade compromise level")
        
        self.is_compromised = True
        self.compromise_level = level
    
    def reset(self) -> None:
        """Reset host to initial state."""
        self.is_compromised = False
        self.compromise_level = CompromiseLevel.NONE
        self.is_discovered = False


from .service import Service
Host.model_rebuild()
