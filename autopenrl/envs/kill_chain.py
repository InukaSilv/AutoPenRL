"""Kill chain stage tracking for MITRE ATT&CK framework."""

from enum import IntEnum
from typing import List
from pydantic import BaseModel, Field


class KillChainStage(IntEnum):
    """MITRE ATT&CK kill chain stages."""
    STAGE_0_RECONNAISSANCE = 0
    STAGE_1_INITIAL_ACCESS = 1
    STAGE_2_EXECUTION = 2
    STAGE_3_PERSISTENCE = 3
    STAGE_4_PRIVILEGE_ESCALATION = 4
    STAGE_5_LATERAL_MOVEMENT = 5
    STAGE_6_EXFILTRATION = 6


class KillChainTracker(BaseModel):
    """Tracks attacker progress through MITRE ATT&CK kill chain.
    
    Attributes:
        current_stage: Current kill chain stage
        stage_history: History of stages reached
    """
    
    current_stage: KillChainStage = Field(default=KillChainStage.STAGE_0_RECONNAISSANCE)
    stage_history: List[KillChainStage] = Field(default_factory=list)
    
    model_config = {"use_enum_values": False}
    
    def __init__(self, **data):
        """Initialize kill chain tracker."""
        super().__init__(**data)
        if len(self.stage_history) == 0:
            self.stage_history.append(self.current_stage)
    
    def advance(self, new_stage: KillChainStage) -> bool:
        """Attempt to advance to the next stage.
        
        Args:
            new_stage: Target stage to advance to
            
        Returns:
            True if stage was advanced, False otherwise
        """
        if new_stage > self.current_stage:
            self.current_stage = new_stage
            if new_stage not in self.stage_history:
                self.stage_history.append(new_stage)
            return True
        return False
    
    def get_progress_score(self) -> float:
        """Get normalized progress through kill chain (0.0 to 1.0).
        
        Returns:
            Progress score from 0.0 (stage 0) to 1.0 (stage 6)
        """
        return float(self.current_stage) / 6.0
    
    def get_available_tactics(self) -> List[KillChainStage]:
        """Get list of tactics available for current or next stage.
        
        Returns:
            List of available KillChainStage values
        """
        if self.current_stage < KillChainStage.STAGE_6_EXFILTRATION:
            return [self.current_stage, self.current_stage + 1]
        return [KillChainStage.STAGE_6_EXFILTRATION]
    
    def reset(self) -> None:
        """Reset kill chain to initial state."""
        self.current_stage = KillChainStage.STAGE_0_RECONNAISSANCE
        self.stage_history = [KillChainStage.STAGE_0_RECONNAISSANCE]
