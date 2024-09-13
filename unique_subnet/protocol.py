from typing import List, Optional
import bittensor as bt

class UniqueSynapse(bt.Synapse):

    time_elapsed: int = 0

    nums1: int
    nums2: int

    response: Optional[int] = None

    def deserialize(self) -> Optional[int]:
        """
        Deserialize the miner response.

        Returns:
        - List[dict]: The deserialized response, which is a list of dictionaries containing the extracted data.
        """
        return self.response