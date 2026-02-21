from fastapi import UploadFile, HTTPException
import pandas as pd 
import pyarrow as pa
import duckdb 
import logging
import os 
import aiofiles

logger = logging.getLogger(__name__)

class HandleFiles:

    @staticmethod
    async def write_file(file: UploadFile , file_path:str):
        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)

        return len(content)

    @staticmethod 
    async def read_file(file_path:str,mode: str): 
    
        try:
            async with aiofiles.open(file_path,mode) as f:
                file = await f.read()
        except FileNotFoundError:
            raise HTTPException(
                status_code=404,
                detail="File Not found"
            )

        return file

    @staticmethod
    async def read_csv(file_path: str) -> pa.Table:
        """
        For reading csv files and return a arrow table
        """
        logger.info(f"Reading Mobilbanken CSV file: {os.path.basename(file_path)}")
        
        try: 
            df = pd.read_csv(file_path, delimiter=';',encoding='unicode_escape')
        except (TypeError, FileNotFoundError, UnicodeDecodeError, MemoryError) as e: 
            raise  HTTPException(
                status_code=500,
                detail=f"Failed reading Mobilbanken CSV file from path: {file_path}, Exception: {e}")



        logger.info(f"Converting to arrow table")

        arrow = pa.Table.from_pandas(df=df)
        
        return arrow


