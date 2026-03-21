delegering_plan = {
    "name": "delegering_plan",
    "description": "Delegeringsplan som fordeler brukerens input til riktige agenter",
    "input_schema": {
        "type": "object",
        "properties": {
            "delegering": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "agent": {
                            "type": "string",
                            "description": "Navnet på agenten som skal motta denne delen av inputen",
                        },
                        "input_tekst": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Relevante utdrag fra brukerens input for denne agenten",
                        },
                        "run_last": {
                            "type": "boolean",
                            "description": "Om agenten skal kjøres etter at andre agenter er ferdige",
                        },
                        "depends_on": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Liste over agentnavn denne agenten er avhengig av",
                        },
                        "merknad": {
                            "type": "string",
                            "description": "Eventuell merknad om manglende data eller usikkerhet",
                        },
                    },
                    "required": ["agent", "input_tekst", "run_last", "depends_on"],
                },
            },
            "usikker": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Tekstblokker der agenten er usikker på hvilken agent som bør motta dem",
            },
        },
        "required": ["delegering", "usikker"],
    },
}
