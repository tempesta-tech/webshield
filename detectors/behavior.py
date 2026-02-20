from detectors.base import SQLBasedDetector

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"


class BehaviorDetector(SQLBasedDetector):

    @staticmethod
    def name() -> str:
        return "behavior"


