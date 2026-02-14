#YNAB 
from ynab import ApiClient, Configuration
from ynab.api.transactions_api import TransactionsApi
from ynab.models.new_transaction import NewTransaction
from ynab.models.post_transactions_wrapper import PostTransactionsWrapper
import asyncio
import duckdb 
import pyarrow as pa 
import ynab 
import os 



from fastapi import HTTPException, status

from api_utils.logger import logger 

async def filter_mobilebanken_transactions(arrow: pa.lib.Table, from_account:str, to_account:str):

    YNAB_ACCOUNT_ID: str = 'cb961646-4066-4349-9981-c56da6c0f444'
    #YNAB_ACCOUNT_ID: str = 'eab793df-a728-41d0-908f-a0a747c6a348'

    logger.info(f"Before filtering:{arrow.num_rows}")
    query= f"""select 
        '{YNAB_ACCOUNT_ID}' as account_id,
        STRPTIME("Utført dato", '%d.%m.%Y')::DATE as var_date, 
        --Beskrivelse as memo,
        Beskrivelse as payee_name,
        CASE
            WHEN "Beløp inn" IS NOT NULL THEN "Beløp inn"::INT32 * 1000
            ELSE "Beløp ut"::INT32 * 1000
        END AS amount,
        --'Sparekonto 18-33' as payee_id, 
        'cleared' as cleared,
        CAST("Utført dato" AS VARCHAR) || '_' || CAST(amount AS VARCHAR) || '_v5' AS import_id,
        --Mottakernavn as payee_name

        from arrow
        WHERE TRY_STRPTIME("Utført dato", '%d.%m.%Y') IS NOT NULL
        AND (
        "Fra konto" = '{from_account}'
        OR "Til konto" = '{to_account}'
    )

        """
    
    logger.info(f"SQL QUERRY: {query}")
    

    arrow = duckdb.sql(query=query).to_arrow_table()


    logger.info(f"Number of rows: {arrow.num_rows}")


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




    return arrow, metadata

   

class YNABAPI:

    def __init__(self, YNAB_PAC: str, budget_id: str ="690d3321-6bdc-4eef-b662-bd1346084552" ):
    
        self.budget_id = budget_id

        self.configuration = ynab.Configuration(access_token = YNAB_PAC)
        self._client: ynab.ApiClient = None

    async def _create_client(self)-> ynab.ApiClient: 
        """
        creating a new client each time this function is called, unsure if its best to resuse or keep an old client
        """

        #if self._client is None: 
        self._client = ynab.ApiClient(self.configuration)
        return self._client 
       # else: 
       #     return self._client

    async def create_transactions(self, arrow) -> list[NewTransaction]:
        transactions = [
            NewTransaction(**row)
            for row in arrow.to_pandas().to_dict(orient="records")
        ]

        return transactions

    async def import_transactions(self, transactions): 
        

        ### unsure if it is the most optimal to create a new client, or reuse a create client 
        ### right now the with stat
        with await self._create_client() as client:
            api_instance = TransactionsApi(client)

            logger.info(f"{transactions=}")

            data = PostTransactionsWrapper(transactions=transactions)

            try:
                api_response = api_instance.create_transaction(self.budget_id, data)
                
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error importing transactions to YNAB: {e}",
                )            
            






    






