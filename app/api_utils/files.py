from fastapi import UploadFile
import pandas as pd 
import pyarrow as pd 
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
    async def read_mb_csv(file_path: str):
        """
        For reading mobilbanken csv files
        """
        
        logger.info(f"Reading Mobilbanken CSV file: {os.path.basename(file_path)}")


        df = pd.read_csv(transactions_path, delimiter=';',encoding='unicode_escape')
        arrow = pa.Table.from_pandas(df=df)

        
        row = duckdb.sql("""
            SELECT
                count(*) as number_of_transactions,
                MIN(amount) AS min_amount,
                MAX(amount) AS max_amount,
                AVG(amount) AS avg_amount
            FROM arrow
        """).fetchone()

        number_of_transactions,min_amount, max_amount, avg_amount = row 

        metadata = {"number_of_transactions": number_of_transactions,
                    "min_amount": min_amount ,
                    "max_amount": max_amount,
                    "avg_amount": avg_amount,}


        return arrow_cleaned, metadata


