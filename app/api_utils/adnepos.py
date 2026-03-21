import logging
from pydantic import BaseModel
from google.genai import types
from typing import Optional
import os 

logger = logging.getLogger(__name__)

class Metadata(BaseModel):
    date: Optional[str] = None
    location: Optional[str] = None
    entities: Optional[str] = None

class TranscribeResult(BaseModel):
    filename: str 
    transcription: str
    metadata: Optional[Metadata] = None



class Transcriber:

    def __init__(self, client): 

        self.client = client 
        
    async def _transcribe(self, image_bytes:bytes, temperature:float = 0.0): 


        response = self.client.models.generate_content(
            model="gemini-3-flash-preview",
            contents=[
                types.Part.from_bytes(data=image_bytes, mime_type="image/jpeg"),
                "Please transcribe the text in the image with high accuracy. "
                "Then, provide metadata containing any facts or insights you inferred."
            ],
            config=types.GenerateContentConfig(
                response_schema=TranscribeResult,
                temperature=temperature  # lower randomness for accuracy
            )
        )

        result = response.parsed

        return result 



    async def process_image(self, image_bytes: bytes, image_filename: str) -> TranscribeResult:

        result = await self._transcribe(image_bytes)
        result.filename = image_filename
       
        return result  #dict with transcrpiton and metadata 




      
