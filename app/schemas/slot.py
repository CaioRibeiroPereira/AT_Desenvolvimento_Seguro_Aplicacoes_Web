from datetime import datetime

from pydantic import BaseModel


class SlotRead(BaseModel):
    profissional_id: int
    data_hora: datetime
