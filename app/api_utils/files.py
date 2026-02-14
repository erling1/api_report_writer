from fastapi import UploadFile, HTTPException
import pandas as pd 
import pyarrow as pa
import duckdb 
import logging
import os 

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
            with open(file=file_path,mode=mode) as f:
                file = f.read()
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

        df = pd.read_csv(file_path, delimiter=';',encoding='unicode_escape')

        logger.info(f"Converting to arrow table")

        arrow = pa.Table.from_pandas(df=df)
        
        return arrow


