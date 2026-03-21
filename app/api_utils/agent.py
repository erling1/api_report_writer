import asyncio

from pyarrow import Message
from pathlib import Path
import anthropic
from pydantic import BaseModel
from api_utils.logger import logger
####### All relevant Agents:
# Summary Agent
# Assessment Agent
# Intervention Evaluation Agent
# Family and Network Agent
# Child Perspective Agent
# Synthesis Agent
# Recommendation Agent
# Incident Agent
# Risk Agent
# Development Agent


###### One big Orchestrator agent to monitor coherent output from sub agents


class CompletionResult(BaseModel):
    content: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    stop_reason: str


class OrchestratorAgent:
    _client: anthropic.AsyncAnthropic
    agents: list = [
        "sammendragsagent",
        "kartleggingsagent",
        "tiltaksevalueringsagent",
        "familie_og_nettverksagent",
        "barnets_perspektiv_agent",
        "synteseagent",
        "anbefalingsagent",
        "hendelsesagent",
        "risikoagent",
        "utviklingsagent"
    ]
    async def _create_client(self) -> anthropic.AsyncAnthropic:
        if not self._client:
            logger.info(f"Creating Anthropic API Client")
            self._client = anthropic.AsyncAnthropic()

        return self._client

    async def validate_output():
        return None

    async def create_agent(self, name: str, prompt_path: str) -> Agent:
        logger.info(f"Creating Agent: {name}")
        self._client = self._create_client()
        self.system_prompt = Path(prompt_path).read_text()self.system_prompt = Path(prompt_path).read_text()
        agent = Agent(name=name, system_prompt=system_prompt, _client=client)
        logger.info(f"Agents Created for API Report Writer")
        return agent


class Agent:
    name: str
    system_prompt: str
    message: str
    _client: anthropic.AsyncAnthropic

    _model: str
    _max_tokens: int = 1024

    async def generate_completion(self, messages=None) -> CompletionResult:
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=[
                {
                    "type": "text",
                    "text": self.system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=messages,
        )

        return CompletionResult(
            content=response.content[0].text,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            cache_read_tokens=response.usage.cache_read_input_tokens or 0,
            stop_reason=response.stop_reason,
        )

    async def generate_section(self) -> CompletionResult:
        return await self.generate_completion()

    async def feedback(self, input: str) -> CompletionResult:
        messages = [{"role": "user", "content": input}]
        return await self.generate_completion(messages=messages)
