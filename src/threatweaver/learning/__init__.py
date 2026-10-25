"""ThreatWeaver continual learning package."""

from threatweaver.learning.adaptation_service import (
    AdaptationQueue,
    AdaptationQueueItem,
    AdaptationService,
)
from threatweaver.learning.replay_buffer import ReplayBuffer, ReplaySample
from threatweaver.learning.selection import (
    ReplaySelector,
    NoReplaySelector,
    RandomReplaySelector,
    UncertaintyReplaySelector,
    UncertaintyDiversityReplaySelector,
    get_replay_selector,
)
from threatweaver.learning.trainer import ContinualTrainer, compute_predictive_entropy

__all__ = [
    "AdaptationQueue",
    "AdaptationQueueItem",
    "AdaptationService",
    "ReplayBuffer",
    "ReplaySample",
    "ReplaySelector",
    "NoReplaySelector",
    "RandomReplaySelector",
    "UncertaintyReplaySelector",
    "UncertaintyDiversityReplaySelector",
    "get_replay_selector",
    "ContinualTrainer",
    "compute_predictive_entropy",
]
