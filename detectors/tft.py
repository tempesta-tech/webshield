from detectors.ip import IPRPSDetector

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TFtRPSDetector(IPRPSDetector):
    @staticmethod
    def name() -> str:
        return "tft_rps"

    @property
    def validation_key(self) -> str:
        return 'tft'

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            SELECT 
                array(tft) tft, 
                groupUniqArray(tfh) tfh,
                groupUniqArray(address) address,
                count(1) value
            FROM prepared_users
            GROUP by tft
            HAVING  
                value >= {self.threshold}
            LIMIT {self.block_limit_per_check}
            """,
            start_at=start_at,
            finish_at=finish_at,
        )


class TFtErrorRequestDetector(TFtRPSDetector):
    def __init__(self, *args, allowed_statues: list[int] = (), **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed_statues = allowed_statues

    @staticmethod
    def name() -> str:
        return "tft_errors"

    def get_request(self, start_at, finish_at):
        statuses = ", ".join(list(map(str, self.allowed_statues)))
        return self.shared_filter(
            f"""
            SELECT 
                array(tft) tft, 
                groupUniqArray(tfh) tfh,
                groupUniqArray(address) address,
                countIf(status not in ({statuses})) value
            FROM prepared_users
            GROUP by tft
            HAVING  
                value >= {self.threshold}
            LIMIT {self.block_limit_per_check}
            """,
            start_at=start_at,
            finish_at=finish_at,
        )


class TFtAccumulativeTimeDetector(TFtRPSDetector):

    @staticmethod
    def name() -> str:
        return "tft_time"

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            SELECT 
                array(tft) tft, 
                groupUniqArray(tfh) tfh,
                groupUniqArray(address) address,
                sum(response_time) value
            FROM prepared_users
            GROUP by tft
            HAVING  
                value >= {self.threshold}
            LIMIT {self.block_limit_per_check}
            """,
            start_at=start_at,
            finish_at=finish_at,
        )
