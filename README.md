# AutoPenRL

A research system for autonomous multi-stage network penetration testing using Deep Reinforcement Learning.

This is an academic Final Year Project. All testing occurs in simulation only — no real networks involved.

## Features

- Graph Neural Network policy encoder that reads network topology directly
- State space encoding MITRE ATT&CK kill chain stage as explicit progress signal
- Hierarchical action space (tactical → technical) mirroring real attacker decision-making
- Multi-objective reward combining attack success, stealth, and efficiency
- Curriculum learning from small to large networks

## Tech Stack

- Python 3.11+
- PyTorch
- Stable-Baselines3
- Gymnasium
- NetworkX
- Plotly + Dash
- PyYAML
- Pydantic

## Quick Start

```bash
pip install -r requirements.txt
python -m autopenrl.cli train
```
