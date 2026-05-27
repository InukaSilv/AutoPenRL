"""Hierarchical action space for network penetration testing."""

from enum import IntEnum
from typing import Dict, List, Tuple, Optional
import numpy as np
from pydantic import BaseModel, Field


class TacticType(IntEnum):
    """Hierarchical tactic types from MITRE ATT&CK."""
    RECONNAISSANCE = 0
    INITIAL_ACCESS = 1
    EXECUTION = 2
    PERSISTENCE = 3
    PRIVILEGE_ESCALATION = 4
    LATERAL_MOVEMENT = 5
    EXFILTRATION = 6


TACTIC_TECHNIQUES = {
    TacticType.RECONNAISSANCE: [
        "port_scan",
        "service_enumeration",
        "os_detection",
    ],
    TacticType.INITIAL_ACCESS: [
        "exploit_public_app",
        "phishing_simulation",
        "valid_accounts",
    ],
    TacticType.EXECUTION: [
        "command_execution",
        "script_execution",
        "inter_process_communication",
    ],
    TacticType.PERSISTENCE: [
        "scheduled_task",
        "service_installation",
        "registry_modification",
    ],
    TacticType.PRIVILEGE_ESCALATION: [
        "sudo_exploit",
        "token_impersonation",
        "kernel_exploit",
    ],
    TacticType.LATERAL_MOVEMENT: [
        "pass_the_hash",
        "rdp_exploitation",
        "smb_exploitation",
        "ssh_pivot",
    ],
    TacticType.EXFILTRATION: [
        "data_collection",
        "data_compression",
        "exfiltration_channel",
    ],
}


class ActionMasker(BaseModel):
    """Mask invalid actions based on current environment state.
    
    Attributes:
        max_hosts: Maximum number of hosts in the environment
        tactic_types: Number of tactic types
        techniques_per_tactic: Number of techniques per tactic type
    """
    
    max_hosts: int = Field(default=32, description="Maximum number of hosts")
    tactic_types: int = Field(default=7, description="Number of tactic types")
    techniques_per_tactic: int = Field(default=5, description="Max techniques per tactic")
    
    def get_valid_actions(
        self,
        compromised_hosts: List[int],
        discovered_hosts: List[int],
        attacker_access_levels: Dict[int, str],
        target_host_id: int,
    ) -> np.ndarray:
        """Get binary mask of valid actions.
        
        Args:
            compromised_hosts: List of compromised host IDs
            discovered_hosts: List of discovered host IDs
            attacker_access_levels: Dict mapping host ID to access level
            target_host_id: ID of target host
            
        Returns:
            Binary mask array where 1 = valid action, 0 = invalid
        """
        # Total action space: tactic * technique * host
        action_space_size = self.tactic_types * self.techniques_per_tactic * self.max_hosts
        mask = np.ones(action_space_size, dtype=np.uint8)
        
        for tactic_id in range(self.tactic_types):
            for tech_id in range(self.techniques_per_tactic):
                for host_id in range(self.max_hosts):
                    action_idx = tactic_id * self.techniques_per_tactic * self.max_hosts + \
                                tech_id * self.max_hosts + host_id
                    
                    # Cannot attack non-discovered hosts
                    if host_id not in discovered_hosts:
                        mask[action_idx] = 0
                        continue
                    
                    # Privilege escalation only on compromised hosts
                    if tactic_id == TacticType.PRIVILEGE_ESCALATION:
                        if host_id not in compromised_hosts:
                            mask[action_idx] = 0
                            continue
                    
                    # Lateral movement only from compromised hosts
                    if tactic_id == TacticType.LATERAL_MOVEMENT:
                        if not compromised_hosts:  # No foothold yet
                            mask[action_idx] = 0
                            continue
        
        return mask
    
    def get_action_size(self) -> int:
        """Get total number of possible actions.
        
        Returns:
            Total action space size
        """
        return self.tactic_types * self.techniques_per_tactic * self.max_hosts
