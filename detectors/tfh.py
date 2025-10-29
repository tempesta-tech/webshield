from detectors.ip import IPRPSDetector

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TFhRPSDetector(IPRPSDetector):
    @staticmethod
    def name() -> str:
        return "tfh_rps"

    @property
    def validation_key(self) -> str:
        return 'tfh'

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            SELECT 
                groupUniqArray(tft) tft, 
                array(tfh) tfh,
                groupUniqArray(address) address,
                count(1) value
            FROM prepared_users
            GROUP by tfh
            HAVING  
                value >= {self.threshold}
            LIMIT {self.block_limit_per_check}
            """,
            start_at=start_at,
            finish_at=finish_at,
        )


class TFhErrorRequestDetector(TFhRPSDetector):
    def __init__(self, *args, allowed_statues: list[int] = (), **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed_statues = allowed_statues

    @staticmethod
    def name() -> str:
        return "tfh_errors"

    def get_request(self, start_at, finish_at):
        statuses = ", ".join(list(map(str, self.allowed_statues)))
        return self.shared_filter(
            f"""
            SELECT 
                groupUniqArray(tft) tft, 
                array(tfh) tfh,
                groupUniqArray(address) address,
                countIf(status not in ({statuses})) value
            FROM prepared_users
            GROUP by tfh
            HAVING  
                value >= {self.threshold}
            LIMIT {self.block_limit_per_check}
            """,
            start_at=start_at,
            finish_at=finish_at,
        )


class TFhAccumulativeTimeDetector(TFhRPSDetector):

    @staticmethod
    def name() -> str:
        return "tfh_time"

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            SELECT 
                groupUniqArray(tft) tft, 
                array(tfh) tfh,
                groupUniqArray(address) address,
                sum(response_time) value
            FROM prepared_users
            GROUP by tfh
            HAVING  
                value >= {self.threshold}
            LIMIT {self.block_limit_per_check}
            """,
            start_at=start_at,
            finish_at=finish_at,
        )
