import asyncio

from pyarrow import Message
from pathlib import Path
import anthropic
from pydantic import BaseModel
from api_utils.logger import logger
from tools import delegering_plan
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
    orchestrator_prompt: str = "prompts/orchestrator.md"
    available_tools: list = [delegering_plan]
    agents: list = [
        ("sammendragsagent", "prompts/sammendragsagent.md"),
        ("kartleggingsagent", "prompts/kartleggingsagent.md"),
        ("tiltaksevalueringsagent", "prompts/tiltaksevalueringsagent.md"),
        ("familie_og_nettverksagent", "prompts/familie_og_nettverksagent.md"),
        ("barnets_perspektiv_agent", "prompts/barnets_perspektiv_agent.md"),
        ("synteseagent", "prompts/synteseagent.md"),
        ("anbefalingsagent", "prompts/anbefalingsagent.md"),
        ("hendelsesagent", "prompts/hendelsesagent.md"),
        ("risikoagent", "prompts/risikoagent.md"),
        ("utviklingsagent", "prompts/utviklingsagent.md"),
    ]
    _model: str = "claude-sonnet-4-20250514"
    _max_tokens: int = 4096

    def __init__(self, client: anthropic.AsyncAnthropic):
        self._client = client
        self.system_prompt = Path(self.orchestrator_prompt).read_text()

    async def generate_completion(self, messages, tool: str = None):
        kwargs = dict(
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
        if tool:
            kwargs["tools"] = self.available_tools
            kwargs["tool_choice"] = {"type": "tool", "name": tool}

        response = await self._client.messages.create(**kwargs)

        if tool:
            return response.content[0].input

        return CompletionResult(
            content=response.content[0].text,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            cache_read_tokens=response.usage.cache_read_input_tokens or 0,
            stop_reason=response.stop_reason,
        )

    async def create_agent_plan(
        self, draft: str
    ):  # usnure if i should send in string or file here
        """ "

              Delegates relevant parts of a draft to each agent returns

              {
            "delegering": [
                {
                    "agent": "kartleggingsagent",
                    "input_tekst": ["Relevant text from the draft..."],
                    "run_last": False,
                    "depends_on": [],
                    "merknad": ""
                },
                {
                    "agent": "barnets_perspektiv_agent",
                    "input_tekst": [],
                    "run_last": False,
                    "depends_on": [],
                    "merknad": "Ingen informasjon om barnets perspektiv funnet i utkastet."
                },
                # ... one entry per agent
            ],
            "usikker": [
                "Avsnittet om samarbeid med skolen kan tilhøre flere agenter."
            ]
        }

        """
        messages = [{"role": "user", "content": draft}]
        plan = await self.generate_completion(messages=messages, tool=delegering_plan)

        return plan

    async def validate_output():
        return None

    async def create_agent(self, agent: str, input_tekst: str) -> Agent:
        logger.info(f"Creating Agent: {agent}")
        prompt_path = f"prompts/{agent}.md"
        self.system_prompt = Path(prompt_path).read_text()
        agent = Agent(
            name=name,
            system_prompt=system_prompt,
            message=input_tekst,
            _client=self.client,
        )
        logger.info(f"Agents Created for API Report Writer")
        return agent

    async def create_agents(self, plan: dict) -> dict[str, Agent]:
        agents = {}
        for task in plan:
            agent = await self.create_agent(
                **task,
            )
            agents[agent["name"]] = agent

        return agents


class Agent:
    name: str
    system_prompt: str
    message: str
    _client: anthropic.AsyncAnthropic

    _model: str
    _max_tokens: int = 1024

    async def generate_completion(self, input=None) -> CompletionResult:
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
            messages=[{"role": "user", "content": input}],
        )

        return CompletionResult(
            content=response.content[0].text,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            cache_read_tokens=response.usage.cache_read_input_tokens or 0,
            stop_reason=response.stop_reason,
        )

    async def generate_section(self) -> CompletionResult:
        return await self.generate_completion(input=self.message)

    async def feedback(self, input: str) -> CompletionResult:
        return await self.generate_completion(input=self.message)
